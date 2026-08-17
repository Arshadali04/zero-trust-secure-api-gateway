/**
 * api.js — Global window.API and window._extractError
 *
 * Plain JS (no import/export). Loaded before auth.js and all page scripts.
 * Defines window.API for all backend communication and window._extractError
 * for consistent error message extraction.
 */

// ---------------------------------------------------------------------------
// _extractError — shared error helper used by both api.js consumers and auth.js
// ---------------------------------------------------------------------------

window._extractError = function _extractError(error, fallback) {
  fallback = fallback || "Request failed";

  var detail = error && error.data && error.data.detail;

  // FastAPI/Pydantic validation array: [{loc, msg, type}, ...]
  if (Array.isArray(detail)) {
    return detail
      .map(function (e) {
        var loc = Array.isArray(e.loc) ? e.loc.slice(1).join(".") : "";
        var msg = e.msg || "Invalid value";
        return loc ? loc + ": " + msg : msg;
      })
      .join(", ");
  }

  if (typeof detail === "string") return detail;
  if (error && typeof error.message === "string") return error.message;

  return fallback;
};

// ---------------------------------------------------------------------------
// window.API
// ---------------------------------------------------------------------------

window.API = {
  _base: window.location.origin,

  // ── Core request ─────────────────────────────────────────────────────────

  async request(method, endpoint, body) {
    if (body === undefined) body = null;

    var options = {
      method: method,
      headers: {
        "Content-Type": "application/json",
      },
    };

    var token = localStorage.getItem("token");
    if (token) {
      options.headers["Authorization"] = "Bearer " + token;
    }

    if (body !== null) {
      options.body = JSON.stringify(body);
    }

    var response;
    try {
      response = await fetch(this._base + endpoint, options);
    } catch (networkErr) {
      throw {
        status: 0,
        message:
          "Network error while contacting the API. Check that the backend is running and that this page origin is allowed by CORS.",
        cause: networkErr,
      };
    }

    // Safely parse JSON — some endpoints return empty bodies (204 etc.)
    var data = null;
    try {
      data = await response.json();
    } catch (_) {
      data = null;
    }

    if (!response.ok) {
      // 401 — try refreshing the token once before forcing re-login
      if (response.status === 401) {
        var refreshed = await this._tryRefresh();
        if (refreshed) {
          return this.request(method, endpoint, body);
        }
        // Only redirect to login when there was an active session (token was
        // present). If there was no token this is a credential-check failure
        // (e.g. wrong password on /auth/login) — throw so the caller can show
        // the error instead of silently swallowing it.
        if (token) {
          localStorage.removeItem("token");
          localStorage.removeItem("user");
          localStorage.removeItem("refresh_token");
          window.location.replace("login.html");
          return;
        }
        throw { status: response.status, data: data };
      }

      // 403 stepup_required — redirect to step-up verification page
      if (
        response.status === 403 &&
        data &&
        data.detail === "stepup_required"
      ) {
        sessionStorage.setItem(
          "stepup_return_full",
          window.location.pathname + window.location.search
        );
        window.location.replace("stepup.html");
        return;
      }

      throw { status: response.status, data: data };
    }

    return data;
  },

  // ── Token refresh ─────────────────────────────────────────────────────────

  async _tryRefresh() {
    var refreshToken = localStorage.getItem("refresh_token");
    if (!refreshToken) return false;
    try {
      var resp = await fetch(this._base + "/auth/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (!resp.ok) return false;
      var data = await resp.json();
      if (data && data.access_token) {
        localStorage.setItem("token", data.access_token);
        if (data.refresh_token) {
          localStorage.setItem("refresh_token", data.refresh_token);
        }
        return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  },

  // ── Auth ──────────────────────────────────────────────────────────────────

  login: (email, password) =>
    API.request("POST", "/auth/login", { email, password }),

  register: (email, username, password, fullName) =>
    API.request("POST", "/auth/register", {
      email,
      username,
      full_name: fullName,
      password,
    }),

  getMe: () => API.request("GET", "/auth/me"),

  updateMe: (data) => API.request("PATCH", "/auth/me", data),

  updatePassword: (currentPassword, newPassword) =>
    API.request("PATCH", "/auth/me/password", {
      current_password: currentPassword,
      new_password: newPassword,
    }),

  forgotPassword: (email) =>
    API.request("POST", "/auth/forgot-password", { email }),

  resetPassword: (token, newPassword) =>
    API.request("POST", "/auth/reset-password", {
      token,
      new_password: newPassword,
    }),

  // ── MFA ───────────────────────────────────────────────────────────────────

  getMfaStatus: () => API.request("GET", "/auth/mfa/status"),

  setupMfa: () => API.request("POST", "/auth/mfa/setup"),

  verifyMfaSetup: (code) =>
    API.request("POST", "/auth/mfa/verify-setup", { code }),

  verifyMfa: (code) => API.request("POST", "/auth/mfa/verify", { code }),

  disableMfa: (code) => API.request("POST", "/auth/mfa/disable", { code }),

  // ── API Keys ──────────────────────────────────────────────────────────────

  getApiKeys: () => API.request("GET", "/api-keys"),

  createApiKey: (name, scopes, expiresInDays) =>
    API.request("POST", "/api-keys", {
      name,
      scopes,
      ...(expiresInDays ? { expires_in_days: expiresInDays } : {}),
    }),

  updateApiKey: (id, data) => API.request("PATCH", "/api-keys/" + id, data),

  revokeApiKey: (id) => API.request("POST", "/api-keys/" + id + "/revoke"),

  rotateApiKey: (id) => API.request("POST", "/api-keys/" + id + "/rotate"),

  // ── Services ──────────────────────────────────────────────────────────────

  getServices: () => API.request("GET", "/services"),

  createService: (data) => API.request("POST", "/services", data),

  updateService: (id, data) =>
    API.request("PATCH", "/services/" + id, data),

  revokeService: (id) =>
    API.request("POST", "/services/" + id + "/revoke"),

  reactivateService: (id) =>
    API.request("POST", "/services/" + id + "/reactivate"),

  deleteService: (id) => API.request("DELETE", "/services/" + id),

  // ── Proxy demo ────────────────────────────────────────────────────────────

  proxyRequest: (path) => API.request("GET", "/api/v1/" + path),

  // ── Attack Lab ────────────────────────────────────────────────────────────

  runAttack: (attackType, duration, intensity) =>
    API.request("POST", "/attack-lab/run", {
      attack_type: attackType,
      duration,
      intensity,
    }),

  stopAttack: () => API.request("POST", "/attack-lab/stop"),

  getAttackState: () => API.request("GET", "/attack-lab/state"),

  // ── Admin ─────────────────────────────────────────────────────────────────

  getAdminUsers: () => API.request("GET", "/admin/users"),

  updateUserRole: (id, role) =>
    API.request(
      "PATCH",
      "/admin/users/" + id + "/role?role=" + encodeURIComponent(role)
    ),

  unfreezeUser: (id) =>
    API.request("POST", "/admin/users/" + id + "/unfreeze"),

  deleteUser: (id) => API.request("DELETE", "/admin/users/" + id),

  getAuditLogs: () => API.request("GET", "/admin/audit-logs"),

  getSecurityEvents: (threatType) =>
    API.request(
      "GET",
      "/admin/security-events" +
        (threatType ? "?threat_type=" + encodeURIComponent(threatType) : "")
    ),

  // ── Health ────────────────────────────────────────────────────────────────

  getHealth: () => API.request("GET", "/health"),

  getReady: () => API.request("GET", "/ready"),
};
