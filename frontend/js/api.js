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
  _base: (function () {
    var configured = window.APP_CONFIG && window.APP_CONFIG.API_BASE_URL;
    if (configured) return configured.replace(/\/+$/, "");

    var isLocalhost =
      window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1";
    if (isLocalhost && window.location.port && window.location.port !== "8000") {
      return (
        window.location.protocol +
        "//" +
        window.location.hostname +
        ":8000"
      );
    }
    return window.location.origin;
  })(),

  // ── Core request ─────────────────────────────────────────────────────────

  /**
   * Make an HTTP request.
   *
   * Overloaded:
   *   API.request('GET', '/path')         — explicit method
   *   API.request('/path')                — shorthand GET (single string arg)
   */
  async request(methodOrUrl, endpoint, body, _isRetry) {
    var method, actualEndpoint;
    if (endpoint === undefined || typeof endpoint !== 'string') {
      // Single-argument shorthand: request('/path') → GET /path
      method = 'GET';
      actualEndpoint = methodOrUrl;
      body = null;
    } else {
      method = methodOrUrl;
      actualEndpoint = endpoint;
      if (body === undefined) body = null;
    }

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
      response = await fetch(this._base + actualEndpoint, options);
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

    // Extract Zero Trust Gateway security headers on every response
    var secHeaders = {
      riskScore: response.headers ? response.headers.get("x-risk-score") : null,
      riskAction: response.headers ? response.headers.get("x-risk-action") : null,
      wafBlocked: response.headers ? response.headers.get("x-waf-blocked") : null,
      wafRiskScore: response.headers ? response.headers.get("x-waf-risk-score") : null,
      rateLimitRemaining: response.headers ? response.headers.get("x-ratelimit-remaining") : null,
      requestId: response.headers ? response.headers.get("x-request-id") : null,
      statusCode: response.status,
    };
    this.lastSecurityHeaders = secHeaders;

    if (!response.ok) {
      // 401 — refresh the access token and retry, but only ONCE.
      //
      // This block used to recurse without any guard, even though its own
      // comment claimed "once". Whenever the 401 was not actually about the
      // access token — a wrong TOTP code on /auth/mfa/verify was the real
      // case — the refresh succeeded (the session was fine), the identical
      // request was re-issued, and it 401'd again, forever. Every iteration
      // rotated the refresh-token family. It could not even fail closed: the
      // logout branch below is unreachable while refresh keeps succeeding, so
      // the page just hung with its button stuck on "Verifying…" and the
      // caller's catch block never ran.
      //
      // _isRetry is internal — no caller passes it.
      if (response.status === 401 && !_isRetry) {
        var refreshed = await this._tryRefresh(token);
        if (refreshed) {
          return this.request(method, actualEndpoint, body, true);
        }
      }

      if (response.status === 401) {
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
        throw { status: response.status, data: data, headers: secHeaders };
      }

      // 403 stepup_required or stepup_required_no_mfa — redirect to step-up verification page
      if (
        response.status === 403 &&
        data &&
        (data.detail === "stepup_required" || data.detail === "stepup_required_no_mfa")
      ) {
        sessionStorage.setItem(
          "stepup_return_full",
          window.location.pathname + window.location.search
        );
        window.location.replace("stepup.html");
        return;
      }

      throw { status: response.status, data: data, headers: secHeaders };
    }

    return data;
  },

  // ── Token refresh ─────────────────────────────────────────────────────────

  // Shared promise for an in-flight /auth/refresh call. Refresh tokens are
  // single-use with family reuse-detection on the server, so two concurrent
  // refreshes are not merely wasteful — the second one presents an already
  // consumed token, rotate_refresh_token() reads that as theft, deletes the
  // whole family and bumps token_version. The user is hard-logged-out of every
  // session and a false "REFRESH TOKEN REUSE DETECTED" incident lands in the
  // security log. All it took was two requests 401'ing at the same moment.
  _refreshInFlight: null,

  /**
   * Refresh the access token. Returns true if a usable token is now in
   * localStorage.
   *
   * @param tokenAtRequestTime the access token the caller actually sent. If it
   *   no longer matches what is in localStorage, somebody else has already
   *   refreshed and there is nothing to do — report success so the caller
   *   retries with the new token instead of consuming a second refresh token.
   *
   * Limitation, stated plainly: this closes the race within one page only.
   * Two browser tabs have separate _refreshInFlight but share localStorage, so
   * the tokenAtRequestTime check helps there but does not eliminate the window
   * where both tabs read the refresh token before either writes. Closing that
   * properly needs a cross-context lock (navigator.locks). Left as a known gap
   * rather than papered over.
   */
  async _tryRefresh(tokenAtRequestTime) {
    if (
      tokenAtRequestTime &&
      localStorage.getItem("token") !== tokenAtRequestTime
    ) {
      return true;
    }

    if (this._refreshInFlight) return this._refreshInFlight;

    var self = this;
    this._refreshInFlight = (async function () {
      var refreshToken = localStorage.getItem("refresh_token");
      if (!refreshToken) return false;
      try {
        var resp = await fetch(self._base + "/auth/refresh", {
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
    })();

    try {
      return await this._refreshInFlight;
    } finally {
      // Safe to clear: any caller that arrived while this was pending already
      // holds a reference to the same promise via the early return above.
      this._refreshInFlight = null;
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

  revokeApiKey: (id) => API.request("POST", "/api-keys/" + id + "/revoke"),

  rotateApiKey: (id) => API.request("POST", "/api-keys/" + id + "/rotate"),

  // ── Services ──────────────────────────────────────────────────────────────
 
  getServices: (all) =>
    API.request("GET", all ? "/services?all=true" : "/services"),

  createService: (data) => API.request("POST", "/services", data),

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

  getAdminUsers: (skip, limit) => {
    var qs = [];
    if (skip !== undefined) qs.push("skip=" + encodeURIComponent(skip));
    qs.push("limit=" + encodeURIComponent(limit !== undefined ? limit : 200));
    var query = "?" + qs.join("&");
    return API.request("GET", "/admin/users" + query);
  },

  updateUserRole: (id, role) =>
    API.request(
      "PATCH",
      "/admin/users/" + id + "/role?role=" + encodeURIComponent(role)
    ),

  unfreezeUser: (id) =>
    API.request("POST", "/admin/users/" + id + "/unfreeze"),

  freezeUser: (id) =>
    API.request("POST", "/admin/users/" + id + "/freeze"),


  deleteUser: (id) => API.request("DELETE", "/admin/users/" + id),

  getAuditLogs: () => API.request("GET", "/admin/audit-logs"),

  getSecurityEvents: (threatType) =>
    API.request(
      "GET",
      "/admin/security-events" +
        (threatType ? "?threat_type=" + encodeURIComponent(threatType) : "")
    ),

  // ── Health ────────────────────────────────────────────────────────────────

  getHealth: () => API.request('GET', '/health'),

  // ── Analytics (admin) ─────────────────────────────────────────────────────

  getAnalyticsSummary: () =>
    API.request('GET', '/admin/analytics/summary'),

  getThreatTimeline: (hours) =>
    API.request('GET', '/admin/analytics/threat-timeline?hours=' + (hours || 24)),

  getThreatBreakdown: (hours) =>
    API.request('GET', '/admin/analytics/threat-breakdown?hours=' + (hours || 24)),

  getUserRiskDist: () =>
    API.request('GET', '/admin/analytics/user-risk-dist'),

  getTopIPs: (limit, hours) =>
    API.request('GET', '/admin/analytics/top-ips?limit=' + (limit || 15) + '&hours=' + (hours || 24)),

  // Audit 2026-08-22 — five helpers removed here as dead code:
  //   updateMe      → PATCH  /auth/me
  //   getMfaStatus  → GET    /auth/mfa/status
  //   updateApiKey  → PATCH  /api-keys/{id}
  //   updateService → PATCH  /services/{id}
  //   getReady      → GET    /ready
  // All five backend routes exist and still work; nothing in the UI ever
  // called these wrappers, so they were surface area that looked supported
  // and wasn't. Five *other* unused wrappers (getMe, updatePassword, setupMfa,
  // verifyMfaSetup, disableMfa) were kept instead and their inline
  // `API.request(...)` callers repointed at them — those endpoints are live in
  // the UI, so the wrapper was the right layer and the duplication was the bug.
};


// When the frontend is hosted separately (for example on Vercel), OAuth
// links must target the FastAPI backend rather than the static-site origin.
if (typeof document !== "undefined" && window.API && window.API._base) {
  document.querySelectorAll('a[href^="/auth/oauth/"]').forEach(function (link) {
    link.href = window.API._base + link.getAttribute("href");
  });
}
