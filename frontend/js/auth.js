/**
 * auth.js — Global window.Auth
 *
 * Plain JS (no import/export). Requires window.API (api.js) to be loaded first.
 * Provides authentication state management, login/register flows, OAuth callback
 * handling, and route guards for protected pages.
 *
 * Rules:
 *  - Never wipe the token except in logout() and the expiry check in isAuthenticated().
 *  - Every public method that can fail catches internally and returns a result object.
 *  - Navigation only happens in finishLogin(), logout(), requireAuth(), requireAdmin().
 */

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

function _storeSession(token, user) {
  localStorage.setItem("token", token);
  if (user && typeof user === "object") {
    localStorage.setItem("user", JSON.stringify(user));
  }
}

function _clearSession() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  localStorage.removeItem("refresh_token");
}

function _decodeJwtPayload(token) {
  try {
    var parts = token.split(".");
    if (parts.length !== 3) return null;
    var base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    var padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    return JSON.parse(atob(padded));
  } catch (_) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// window.Auth
// ---------------------------------------------------------------------------

window.Auth = {

  // ── Token / session helpers ───────────────────────────────────────────────

  getToken() {
    return localStorage.getItem("token");
  },

  isAuthenticated() {
    var token = this.getToken();
    if (!token) return false;

    var payload = _decodeJwtPayload(token);
    if (!payload) return false;

    if (payload.exp && Date.now() >= payload.exp * 1000) {
      _clearSession();
      return false;
    }

    return true;
  },

  getCurrentUser() {
    try {
      return JSON.parse(localStorage.getItem("user") || "null");
    } catch (_) {
      return null;
    }
  },

  decodeToken() {
    var token = this.getToken();
    if (!token) return null;
    return _decodeJwtPayload(token);
  },

  // ── Core finish step ──────────────────────────────────────────────────────

  finishLogin(token, user, refreshToken) {
    _storeSession(token, user || null);
    if (refreshToken) {
      localStorage.setItem("refresh_token", refreshToken);
    }
    window.location.replace("dashboard.html?t=" + Date.now());
  },

  // ── Email / password login ────────────────────────────────────────────────

  async login(email, password) {
    try {
      var response = await API.login(email, password);
      var token = response && response.access_token;

      if (response && response.mfa_required) {
        return { mfa_required: true, temp_token: token };
      }

      this.finishLogin(token, response && response.user, response && response.refresh_token);
      return { success: true };

    } catch (e) {
      return { error: _extractError(e, "Login failed") };
    }
  },

  // ── OAuth callback ────────────────────────────────────────────────────────

  async handleOAuthCallback() {
    try {
      var raw = window.location.hash.replace(/^#/, "");
      var params = new URLSearchParams(raw);
      var token = params.get("token");
      var refreshToken = params.get("refresh_token");
      var email = params.get("user");
      var error = params.get("error");
      var msg   = params.get("msg");
      var mfaRequired = params.get("mfa_required") === "true";

      // Nothing in the fragment — normal login page load
      if (!token && !error) return false;

      // Always clean the fragment so a page refresh does not re-trigger
      window.history.replaceState({}, document.title, window.location.pathname);

      if (error) {
        var errMsg =
          error === "account_frozen"
            ? msg || "Account frozen due to suspicious behaviour. Please try again after 1 hour."
            : error === "no_email"
            ? msg || "OAuth account has no usable verified email."
            : msg || "OAuth login failed. Please try again.";
        // Return an error object so the login page can display it via showAlert.
        return { error: errMsg };
      }

      if (mfaRequired) {
        return { mfa_required: true, temp_token: token, email: email };
      }

      // The OAuth callbacks now return a refresh token alongside the access
      // token. Without storing it, an OAuth user was hard-logged-out after the
      // 30-minute access-token lifetime with no silent-refresh path.

      // Build a minimal user from the email query param as a fast fallback
      var user = null;
      if (email) {
        var username = email.split("@")[0] || "user";
        user = { email: email, username: username, full_name: username };
      }

      // Try to get the full user object from /auth/me
      // Temporarily store the token so API.request picks it up
      localStorage.setItem("token", token);
      try {
        var fresh = await API.getMe();
        if (fresh && typeof fresh === "object") user = fresh;
      } catch (fetchErr) {
        // /auth/me failed — use the email-derived fallback; not fatal
        console.warn("[Auth] /auth/me failed during OAuth callback:", fetchErr);
        localStorage.removeItem("token");
      }

      this.finishLogin(token, user, refreshToken);
      return true;

    } catch (e) {
      console.error("[Auth] handleOAuthCallback unexpected error:", e);
      if (window.UI && typeof window.UI.showError === "function") {
        window.UI.showError("Unexpected error during OAuth login.");
      }
      return false;
    }
  },

  // ── Registration ──────────────────────────────────────────────────────────

  async register(email, username, password, fullName) {
    try {
      await API.register(email, username, password, fullName);
      return { success: true };
    } catch (e) {
      return { error: _extractError(e, "Registration failed") };
    }
  },

  // ── Logout ────────────────────────────────────────────────────────────────

  logout() {
    _clearSession();
    window.location.replace("login.html");
  },

  // ── Route guard: any authenticated user ───────────────────────────────────

  async requireAuth() {
    if (!this.isAuthenticated()) {
      window.location.replace("login.html");
      return null;
    }

    // Try to get fresh user data from the backend
    try {
      var fresh = await API.getMe();
      if (fresh && typeof fresh === "object") {
        localStorage.setItem("user", JSON.stringify(fresh));
        return fresh;
      }
    } catch (e) {
      // Hard auth failures — token is no longer valid
      if (
        e.status === 401 ||
        (e.status === 403 && e.data && e.data.detail === "mfa_required")
      ) {
        console.warn("[Auth] Token rejected by server, redirecting to login.");
        _clearSession();
        window.location.replace("login.html");
        return null;
      }
      // Soft failures (rate-limit, network) — fall back to cached data
      console.warn("[Auth] /auth/me failed, falling back to cache:", e.status || e);
    }

    // Return cached user if available
    var cached = this.getCurrentUser();
    if (cached) return cached;

    // Last resort: synthesise a minimal user object from the token payload
    var payload = this.decodeToken();
    if (payload && payload.sub) {
      var minimal = {
        email: payload.sub,
        username: payload.sub.split("@")[0],
        role: payload.role || "user",
      };
      localStorage.setItem("user", JSON.stringify(minimal));
      return minimal;
    }

    // Valid token but zero user data — return a safe placeholder
    return { email: "unknown", username: "User", role: "user" };
  },

  // ── Route guard: admin only ───────────────────────────────────────────────

  async requireAdmin() {
    var user = await this.requireAuth();
    if (!user) return null; // requireAuth already redirected

    if (user.role !== "admin") {
      window.location.replace("dashboard.html");
      return null;
    }

    return user;
  },
};
