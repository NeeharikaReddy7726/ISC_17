import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import {
  fetchCurrentUser,
  loginUser,
  registerUnauthorizedHandler,
  registerUser
} from "../api/client";

/**
 * Token storage keys scoped to the browser session (`sessionStorage`).
 *
 * Security Rationale:
 * Given the current stateless Bearer-JWT FastAPI architecture (without HttpOnly auth cookies),
 * `sessionStorage` is preferred over `localStorage` because tokens remain isolated to the
 * active browser tab and are automatically discarded when the tab/browser closes.
 * All cryptographic token verification is still performed strictly on the backend.
 */
const TOKEN_STORAGE_KEY = "qr_shield_token";
export const LAST_SCAN_STORAGE_KEY = "qr_shield_last_scan";

const AuthContext = createContext(null);

function parseJwtExpirationMs(jwtToken) {
  try {
    const parts = jwtToken.split(".");
    if (parts.length !== 3) return null;
    const base64Payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(base64Payload));
    return typeof payload.exp === "number" ? payload.exp * 1000 : null;
  } catch {
    return -1; // Malformed JWT
  }
}

function isTokenVisiblyExpired(jwtToken) {
  const expMs = parseJwtExpirationMs(jwtToken);
  if (expMs === -1) return true;
  if (expMs === null) return false;
  return Date.now() >= expMs;
}

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => {
    const saved = sessionStorage.getItem(TOKEN_STORAGE_KEY);
    if (saved && isTokenVisiblyExpired(saved)) {
      sessionStorage.removeItem(TOKEN_STORAGE_KEY);
      sessionStorage.removeItem(LAST_SCAN_STORAGE_KEY);
      return null;
    }
    return saved;
  });

  const [user, setUser] = useState(null);
  const [isLoadingAuth, setIsLoadingAuth] = useState(Boolean(token));
  const [sessionMessage, setSessionMessage] = useState(null);

  // Prevents a redundant GET /api/auth/me call immediately after login() already fetched the user
  const verifiedTokenRef = useRef(null);

  const clearAuth = useCallback((notice = null) => {
    sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    sessionStorage.removeItem(LAST_SCAN_STORAGE_KEY);
    verifiedTokenRef.current = null;
    setToken(null);
    setUser(null);
    if (notice) {
      setSessionMessage(notice);
    }
  }, []);

  // Register global 401 handler so expired/invalid tokens return the user to Login
  useEffect(() => {
    registerUnauthorizedHandler((serverMsg) => {
      clearAuth(serverMsg || "Your session has expired or is invalid. Please log in again.");
    });
  }, [clearAuth]);

  // Verify stored token against GET /api/auth/me on initial mount or page reload
  useEffect(() => {
    let active = true;

    async function verifySession() {
      if (!token) {
        if (active) {
          setUser(null);
          setIsLoadingAuth(false);
        }
        return;
      }

      if (verifiedTokenRef.current === token) {
        if (active) setIsLoadingAuth(false);
        return;
      }

      setIsLoadingAuth(true);
      try {
        const profile = await fetchCurrentUser(token);
        if (active) {
          verifiedTokenRef.current = token;
          setUser(profile);
        }
      } catch (err) {
        if (active && err?.status !== 401) {
          // 401 is already handled by registerUnauthorizedHandler with the exact backend reason
          clearAuth(err?.message || "Unable to verify your session. Please log in again.");
        }
      } finally {
        if (active) {
          setIsLoadingAuth(false);
        }
      }
    }

    verifySession();
    return () => {
      active = false;
    };
  }, [token, clearAuth]);

  // Schedule client-side cleanup when JWT `exp` timestamp arrives
  useEffect(() => {
    if (!token) return;
    const expMs = parseJwtExpirationMs(token);
    if (!expMs || expMs <= 0) return;

    const remainingMs = expMs - Date.now();
    if (remainingMs <= 0) {
      clearAuth("Authentication token has expired. Please log in again.");
      return;
    }

    const timerId = setTimeout(() => {
      clearAuth("Your session has expired. Please log in again.");
    }, remainingMs);

    return () => clearTimeout(timerId);
  }, [token, clearAuth]);

  const login = useCallback(async (email, password) => {
    setSessionMessage(null);
    const data = await loginUser({ email, password });
    const profile = await fetchCurrentUser(data.access_token);
    sessionStorage.setItem(TOKEN_STORAGE_KEY, data.access_token);
    verifiedTokenRef.current = data.access_token;
    setToken(data.access_token);
    setUser(profile);
    setIsLoadingAuth(false);
    return profile;
  }, []);

  const register = useCallback(async (email, password) => {
    setSessionMessage(null);
    return registerUser({ email, password });
  }, []);

  const logout = useCallback(() => {
    clearAuth(null);
  }, [clearAuth]);

  const clearSessionMessage = useCallback(() => {
    setSessionMessage(null);
  }, []);

  const value = {
    token,
    user,
    isAuthenticated: Boolean(token && user),
    isLoadingAuth,
    sessionMessage,
    clearSessionMessage,
    login,
    register,
    logout
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside an AuthProvider.");
  }
  return ctx;
}
