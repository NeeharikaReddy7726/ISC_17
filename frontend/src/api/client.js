/**
 * Centralized API Client for QR Shield FastAPI Backend.
 * Matches exact endpoints and response schemas exposed by the backend.
 */

export const API_BASE_URL =
  import.meta.env?.VITE_API_BASE_URL?.replace(/\/+$/, "") || "http://127.0.0.1:8000";

let unauthorizedCallback = null;

/**
 * Allows AuthContext to subscribe to HTTP 401 events from protected API calls
 * so expired or invalid JWT tokens automatically return the user to Login.
 */
export function registerUnauthorizedHandler(callback) {
  unauthorizedCallback = callback;
}

export class ApiError extends Error {
  constructor(message, status, detail = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Extracts a human-readable error message from FastAPI HTTPException strings
 * or Pydantic 422 validation error arrays.
 */
function parseErrorDetail(data, fallbackStatus) {
  if (!data) {
    return `Request failed with status ${fallbackStatus}.`;
  }

  if (typeof data.detail === "string") {
    return data.detail;
  }

  if (Array.isArray(data.detail) && data.detail.length > 0) {
    return data.detail
      .map((err) => {
        const field = Array.isArray(err.loc) ? err.loc[err.loc.length - 1] : null;
        return field && field !== "body" ? `${field}: ${err.msg}` : err.msg;
      })
      .join(" | ");
  }

  return `Unexpected server response (HTTP ${fallbackStatus}).`;
}

/**
 * Core HTTP request helper that attaches Bearer JWT tokens cleanly
 * and handles network errors, JSON parsing, and 401 unauthorized redirects.
 */
async function request(path, { method = "GET", body = null, token = null, isFormData = false, triggerAuthReset = true } = {}) {
  const headers = {};

  if (!isFormData) {
    headers["Content-Type"] = "application/json";
  }

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method,
      headers,
      body: isFormData ? body : body ? JSON.stringify(body) : null
    });
  } catch {
    throw new ApiError(
      "Cannot reach the QR Shield backend server. Ensure FastAPI is running on http://127.0.0.1:8000.",
      0
    );
  }

  let data = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    data = await response.json().catch(() => null);
  }

  if (!response.ok) {
    const message = parseErrorDetail(data, response.status);

    if (response.status === 401 && triggerAuthReset && unauthorizedCallback) {
      unauthorizedCallback(message);
    }

    throw new ApiError(message, response.status, data?.detail ?? null);
  }

  return data;
}

/**
 * POST /api/auth/register
 * Request: { email, password }
 * Response (201): { id, email, created_at }
 */
export function registerUser({ email, password }) {
  return request("/api/auth/register", {
    method: "POST",
    body: { email, password },
    triggerAuthReset: false
  });
}

/**
 * POST /api/auth/login
 * Request: { email, password }
 * Response (200): { access_token, token_type, expires_in_minutes }
 */
export function loginUser({ email, password }) {
  return request("/api/auth/login", {
    method: "POST",
    body: { email, password },
    triggerAuthReset: false
  });
}

/**
 * GET /api/auth/me
 * Response (200): { id, email, created_at }
 */
export function fetchCurrentUser(token) {
  return request("/api/auth/me", {
    method: "GET",
    token,
    triggerAuthReset: true
  });
}

/**
 * POST /api/scan
 * Request: multipart/form-data with field "file"
 * Response (201): {
 *   scan_id, url, url_fingerprint, previously_scanned, previous_scan_count,
 *   prediction, risk_level, confidence_percentage, warnings, scanned_at
 * }
 */
export function scanQrImage(file, token) {
  const formData = new FormData();
  formData.append("file", file);

  return request("/api/scan", {
    method: "POST",
    body: formData,
    token,
    isFormData: true,
    triggerAuthReset: true
  });
}

/**
 * GET /api/history
 * Response (200): Array<{
 *   scan_id, url, url_fingerprint, prediction, risk_level, scanned_at
 * }>
 */
export function fetchScanHistory(token) {
  return request("/api/history", {
    method: "GET",
    token,
    triggerAuthReset: true
  });
}

/**
 * GET /api/history/{scan_id}
 * Response (200): {
 *   scan_id, url, url_fingerprint, prediction, risk_level, scanned_at
 * }
 */
export function fetchSingleScan(scanId, token) {
  return request(`/api/history/${encodeURIComponent(scanId)}`, {
    method: "GET",
    token,
    triggerAuthReset: true
  });
}
