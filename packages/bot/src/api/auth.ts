// GRVT Authentication Module - Fase 3
// Auth via edge.grvt.io con cookie-based auth + IPv4 forzado
// Implementado según specs verificadas por Marta

import dns from 'dns';
import http from 'http';
import https from 'https';
import dotenv from 'dotenv';
import { Agent, fetch as undiciFetch, request as undiciRequest } from 'undici';

dotenv.config();

// 🚨 CRÍTICO: Forzar IPv4 globalmente 
dns.setDefaultResultOrder('ipv4first');

// Agente HTTP con IPv4 forzado (para undici)
const ipv4Agent = new Agent({ connect: { family: 4 } });

// Override global fetch with undici (supports agent option properly)
const fetchIPv4 = (url: string, init?: any): Promise<Response> => {
  return undiciFetch(url, { ...init, dispatcher: ipv4Agent }) as unknown as Promise<Response>;
};

// Legacy agents (keep for compatibility)
const httpAgent = new http.Agent({ family: 4 });
const httpsAgent = new https.Agent({ family: 4 });

export interface AuthState {
  gravityCookie: string;
  accountId: string;
  isAuthenticated: boolean;
  expiresAt: number;
  loginTime: number;
}

export function createEmptyAuthState(): AuthState {
  return {
    gravityCookie: '',
    accountId: '',
    isAuthenticated: false,
    expiresAt: 0,
    loginTime: 0,
  };
}

function headerValue(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value[0] ?? '';
  return value ?? '';
}

function headerJoin(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value.join('; ');
  return value ?? '';
}

// Fetch hides Set-Cookie (forbidden header). undici.request() returns
// the raw hop-by-hop headers, which is what GRVT login depends on.
async function loginWithApiKey(apiKey: string): Promise<{ gravityCookie: string; accountId: string } | null> {
  const { statusCode, headers, body } = await undiciRequest(
    'https://edge.grvt.io/auth/api_key/login',
    {
      method: 'POST',
      dispatcher: ipv4Agent,
      headers: {
        'content-type': 'application/json',
        'user-agent': 'GRVT-Grid-Bot/1.0',
      },
      body: JSON.stringify({ api_key: apiKey }),
    }
  );
  const responseText = await body.text();
  if (statusCode < 200 || statusCode >= 300) {
    console.error(`❌ GRVT login HTTP ${statusCode}: ${responseText.slice(0, 300)}`);
    return null;
  }
  const setCookie = headerJoin(headers['set-cookie']);
  const accountId = headerValue(headers['x-grvt-account-id']);
  const gravityMatch = setCookie.match(/gravity=([^;]+)/);
  if (!gravityMatch?.[1] || !accountId) {
    console.error('❌ GRVT login missing gravity cookie or x-grvt-account-id', {
      statusCode,
      hasSetCookie: Boolean(setCookie),
      accountId: accountId || null,
    });
    return null;
  }
  return { gravityCookie: gravityMatch[1], accountId };
}

// Legacy global auth state — used by the singleton GRVTClient path
// (env-based creds). Multi-tenant clients have their own AuthState.
let authState: AuthState = createEmptyAuthState();

/**
 * Login a GRVT usando API key - flow verificado por Marta
 * POST https://edge.grvt.io/auth/api_key/login
 * Response: Set-Cookie: gravity=XXX + X-Grvt-Account-Id: XXX
 */
export async function authenticateGRVT(): Promise<boolean> {
  try {
    console.log('🔐 Autenticando con GRVT Edge API...');
    
    const apiKey = process.env.GRVT_API_KEY;
    if (!apiKey) {
      throw new Error('GRVT_API_KEY no encontrada en .env');
    }

    const loggedIn = await loginWithApiKey(apiKey);
    if (!loggedIn) return false;

    const now = Date.now();
    authState = {
      gravityCookie: loggedIn.gravityCookie,
      accountId: loggedIn.accountId,
      isAuthenticated: true,
      expiresAt: now + (23 * 60 * 60 * 1000), // Expira en 23h (safety margin)
      loginTime: now
    };

    console.log('✅ Auth exitoso!');
    console.log(`🆔 Account ID: ${accountId}`);
    console.log(`🍪 Cookie expires in: ${Math.floor((authState.expiresAt - now) / 1000 / 3600)}h`);
    
    return true;

  } catch (error) {
    console.error('❌ Auth error:', error instanceof Error ? error.message : error);
    authState.isAuthenticated = false;
    return false;
  }
}

/**
 * Verificar si necesitamos re-autenticar
 */
function needsReauth(): boolean {
  if (!authState.isAuthenticated) return true;
  
  const now = Date.now();
  const timeLeft = authState.expiresAt - now;
  
  // Re-auth si quedan menos de 1 hora
  if (timeLeft < 60 * 60 * 1000) {
    console.log('⏰ Cookie expirando pronto, re-autenticando...');
    return true;
  }
  
  return false;
}

/**
 * Asegurar que estamos autenticados
 */
async function ensureAuthenticated(): Promise<void> {
  if (needsReauth()) {
    const success = await authenticateGRVT();
    if (!success) {
      throw new Error('Falló re-autenticación con GRVT');
    }
  }
}

/**
 * Realizar request autenticado a GRVT APIs
 */
export async function authenticatedRequest(
  url: string, 
  body: object = {}, 
  options: {
    method?: string;
    timeout?: number;
  } = {}
): Promise<any> {
  await ensureAuthenticated();
  
  const { method = 'POST', timeout = 30000 } = options;
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Cookie': `gravity=${authState.gravityCookie}`,
    'X-Grvt-Account-Id': authState.accountId,
    'User-Agent': 'GRVT-Grid-Bot/1.0'
  };
  
  try {
    // Debug: log request details
    if (url.includes('open_orders')) {
      console.log(`🔍 DEBUG open_orders - Cookie: ${authState.gravityCookie.substring(0, 20)}... AccountId: ${authState.accountId} Body: ${JSON.stringify(body)}`);
    }
    const response = await fetchIPv4(url, {
      method,
      headers,
      body: method !== 'GET' ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeout)
    });

    console.log(`📡 ${method} ${url} → ${response.status}`);

    if (response.status === 401) {
      // Token expirado, invalidar y reintentar
      console.log('🔒 Token expirado, reautenticando...');
      authState.isAuthenticated = false;
      await ensureAuthenticated();
      
      // Retry con nuevo token
      return await authenticatedRequest(url, body, options);
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    const data = (await response.json()) as { result?: unknown; [k: string]: unknown };
    return data.result ?? data;

  } catch (error) {
    if (error instanceof Error && error.name === 'TimeoutError') {
      throw new Error(`Request timeout after ${timeout}ms`);
    }
    throw error;
  }
}

/**
 * Request público a Market Data API (sin auth)
 */
export async function publicRequest(
  url: string,
  body: object = {},
  options: { timeout?: number } = {}
): Promise<any> {
  const { timeout = 15000 } = options;
  
  try {
    const response = await fetchIPv4(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'GRVT-Grid-Bot/1.0'
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeout)
    });

    console.log(`📡 POST ${url} → ${response.status}`);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText}`);
    }

    const data = (await response.json()) as { result?: unknown; [k: string]: unknown };
    return data.result ?? data;

  } catch (error) {
    if (error instanceof Error && error.name === 'TimeoutError') {
      throw new Error(`Public request timeout after ${timeout}ms`);
    }
    throw error;
  }
}

/**
 * Obtener estado de autenticación
 */
export function getAuthStatus() {
  const now = Date.now();
  const timeLeft = authState.expiresAt - now;
  
  return {
    isAuthenticated: authState.isAuthenticated,
    accountId: authState.accountId,
    hasValidCookie: !!authState.gravityCookie && timeLeft > 0,
    timeLeftHours: Math.max(0, timeLeft / 1000 / 3600),
    loginTime: authState.loginTime ? new Date(authState.loginTime).toISOString() : null,
    expiresAt: authState.expiresAt ? new Date(authState.expiresAt).toISOString() : null
  };
}

/**
 * Logout / invalidar sesión
 */
export function logout() {
  authState = {
    gravityCookie: '',
    accountId: '',
    isAuthenticated: false,
    expiresAt: 0,
    loginTime: 0
  };
  console.log('🚪 Logged out from GRVT');
}

// ─── Per-instance auth (multi-tenant) ────────────────────────────────
// These variants accept an explicit AuthState + apiKey so each
// GRVTClient instance can have its own cookie session. The global
// functions above are kept for backward compat with the singleton.

export async function authenticateWithKey(
  apiKey: string,
  state: AuthState
): Promise<boolean> {
  try {
    const loggedIn = await loginWithApiKey(apiKey);
    if (!loggedIn) {
      state.isAuthenticated = false;
      return false;
    }
    const now = Date.now();
    state.gravityCookie = loggedIn.gravityCookie;
    state.accountId = loggedIn.accountId;
    state.isAuthenticated = true;
    state.expiresAt = now + 23 * 60 * 60 * 1000;
    state.loginTime = now;
    return true;
  } catch (err) {
    console.error('❌ authenticateWithKey error:', err instanceof Error ? err.message : err);
    state.isAuthenticated = false;
    return false;
  }
}

export async function authenticatedRequestWithState(
  state: AuthState,
  apiKey: string,
  url: string,
  body: object = {},
  options: { method?: string; timeout?: number } = {}
): Promise<any> {
  // Re-auth if needed
  if (!state.isAuthenticated || (state.expiresAt - Date.now()) < 60 * 60 * 1000) {
    const ok = await authenticateWithKey(apiKey, state);
    if (!ok) throw new Error('GRVT re-authentication failed');
  }

  const { method = 'POST', timeout = 30000 } = options;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Cookie': `gravity=${state.gravityCookie}`,
    'X-Grvt-Account-Id': state.accountId,
    'User-Agent': 'GRVT-Grid-Bot/1.0',
  };

  const response = await fetchIPv4(url, {
    method,
    headers,
    body: method !== 'GET' ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeout),
  });

  if (response.status === 401) {
    state.isAuthenticated = false;
    const ok = await authenticateWithKey(apiKey, state);
    if (!ok) throw new Error('GRVT re-authentication failed after 401');
    return authenticatedRequestWithState(state, apiKey, url, body, options);
  }

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`HTTP ${response.status}: ${errorText}`);
  }

  const data = (await response.json()) as { result?: unknown; [k: string]: unknown };
  return data.result ?? data;
}

export default {
  authenticateGRVT,
  authenticatedRequest,
  publicRequest,
  getAuthStatus,
  logout,
  authenticateWithKey,
  authenticatedRequestWithState,
  createEmptyAuthState,
};