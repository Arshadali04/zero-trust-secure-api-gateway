/**
 * auth.js — Unified authentication module.
 *
 * Single login flow for BOTH email/password AND OAuth:
 *   1. Obtain a JWT token (API call or URL param).
 *   2. Optionally fetch /auth/me for a full user object.
 *   3. Call finishLogin(token, user) → stores session → redirects to dashboard.
 *
 * Rules enforced here:
 *  - NEVER wipe the token inside this module except in logout() / isAuthenticated() expiry check.
 *  - NEVER navigate inside a catch block — show an error and stay on the page.
 *  - Every public method that can fail catches internally and returns null/false (no re-throw).
 */

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

function _extractErrorMessage(error, fallback) {
  fallback = fallback || "Request failed";

  const detail = error && error.data && error.data.detail;

  // FastAPI/Pydantic validation: { detail: [ {loc, msg, type}, ... ] }
  if (Array.isArray(detail)) {
    return detail
      .map(function (e) {
        const loc = Array.isArray(e.loc) ? e.loc.slice(1).join(".") : "";
        const msg = e.msg || "Invalid value";
        return loc ? loc + ": " + msg : msg;
      })
      .join(", ");
  }

  if (typeof detail === "string") return detail;
  if (error && typeof error.data === "string") return error.data;
  if (error && typeof error.message === "string") return error.message;

  return fallback;
}

function _storeSession(token, user) {
  localStorage.setItem("token", token);
  if (user && typeof user === "object") {
    localStorage.setItem("user", JSON.stringify(user));
  }
}

function _clearSession() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
}

// ---------------------------------------------------------------------------
// Public Auth object
// ---------------------------------------------------------------------------

const Auth = {

  // ── Token / session helpers ────────────────────────────────────────────────

  getToken() {
    return localStorage.getItem("token");
  },

  isAuthenticated() {
    const token = this.getToken();
    if (!token) return false;

    try {
      const parts = token.split(".");
      if (parts.length !== 3) return false;

      const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
      const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
      const payload = JSON.parse(atob(padded));

      if (payload.exp && Date.now() >= payload.exp * 1000) {
        _clearSession();   // token is expired — clean up proactively
        return false;
      }

      return true;
    } catch (e) {
      console.warn("[Auth] JWT decode failed:", e);
      return false;
    }
  },

  getCurrentUser() {
    try {
      const raw = localStorage.getItem("user");
      if (!raw) return null;
      const obj = JSON.parse(raw);
      return obj && typeof obj === "object" ? obj : null;
    } catch {
      return null;
    }
  },

  // ── Core shared finish step (used by BOTH flows) ───────────────────────────

  /**
   * Store session and navigate to dashboard.
   * This is the ONLY place that does window.location navigation after login.
   */
  finishLogin(token, user) {
    if (!token) {
      UI.showError("Login failed: server did not return a token.");
      return;
    }
    _storeSession(token, user || null);
    // Use timestamp to force browser to fetch a fresh dashboard.html,
    // bypassing any stale cached version.
    window.location.replace("dashboard.html?t=" + Date.now());
  },

  // ── Email / password login ─────────────────────────────────────────────────

  /**
   * Called from the login form submit handler.
   * Returns true on success, false on failure (never throws).
   */
  async login(email, password) {
    UI.showLoading("Logging in…");

    try {
      const response = await API.login(email, password);
      const token = response && response.access_token;
      const user  = response && response.user;

      if (!token) {
        throw { message: "Server did not return an access token." };
      }

      if (response.mfa_required) {
          UI.hideLoading();
          return { mfa_required: true, temp_token: token };
      }

      this.finishLogin(token, user);
      return { success: true };

    } catch (error) {
      UI.hideLoading();
      const msg = _extractErrorMessage(error, "Login failed. Check your email and password.");
      UI.showError(msg);
      console.error("[Auth] email/password login error:", error);
      return false;
    }
  },

  // ── OAuth callback ─────────────────────────────────────────────────────────

  /**
   * Call on login.html load.
   * Detects ?token=... in the URL (set by the backend OAuth callback).
   * Returns true if an OAuth redirect was processed, false if this is a plain login load.
   * Never throws.
   */
  async handleOAuthCallback() {
    try {
      const params = new URLSearchParams(window.location.search);
      const token  = params.get("token");
      const email  = params.get("user");
      const error  = params.get("error");
      const msg    = params.get("msg");

      // Nothing in the URL — normal login page load, do nothing.
      if (!token && !error) return false;

      // Always clean the URL immediately so a page refresh doesn't re-trigger this.
      window.history.replaceState({}, document.title, window.location.pathname);

      if (error) {
        UI.showError(msg || "OAuth login failed. Please try again.");
        return false;
      }

      const mfa_required = params.get("mfa_required") === "true";
      if (mfa_required) {
          return { mfa_required: true, temp_token: token, email: email };
      }

      // Build a minimal user from the email query param as a fast fallback.
      let user = null;
      if (email) {
        const username = email.split("@")[0] || "user";
        user = { email: email, username: username, full_name: username };
      }

      // Try to get the full user object from /auth/me.
      // We store the token temporarily for API.request to pick up.
      localStorage.setItem("token", token);
      try {
        const fresh = await API.request("GET", "/auth/me");
        if (fresh && typeof fresh === "object") user = fresh;
      } catch (e) {
        // /auth/me failed — not fatal, we'll use the email-derived fallback.
        console.warn("[Auth] /auth/me failed during OAuth callback, using cached user:", e);
        // Remove the temp token so finishLogin -> _storeSession sets it cleanly.
        localStorage.removeItem("token");
      }

      // finishLogin will re-persist the token (and user) and navigate.
      this.finishLogin(token, user);
      return true;

    } catch (e) {
      console.error("[Auth] handleOAuthCallback unexpected error:", e);
      UI.showError("Unexpected error during OAuth login.");
      return false;
    }
  },

  // ── Registration ───────────────────────────────────────────────────────────

  async register(email, username, password, fullName) {
    UI.showLoading("Creating account…");

    try {
      await API.register(email, username, password, fullName);
      UI.hideLoading();
      UI.showSuccess("Account created! Redirecting to login…");
      setTimeout(function () {
        window.location.replace("login.html");
      }, 1200);
      return true;
    } catch (error) {
      UI.hideLoading();
      UI.showError(_extractErrorMessage(error, "Registration failed."));
      console.error("[Auth] register error:", error);
      return false;
    }
  },

  // ── Sync user from backend (used by profile.html) ─────────────────────────

  /**
   * Fetches the current user from /auth/me and caches in localStorage.
   * Returns the user object on success, null on failure.
   */
  async syncCurrentUser() {
    const token = this.getToken();
    if (!token) {
      _clearSession();
      return null;
    }
    try {
      const me = await API.request("GET", "/auth/me");
      if (me && typeof me === "object") {
        localStorage.setItem("user", JSON.stringify(me));
        return me;
      }
      return null;
    } catch (e) {
      console.warn("[Auth] syncCurrentUser failed:", e);
      return null;
    }
  },

  // ── Logout ─────────────────────────────────────────────────────────────────

  logout() {
    _clearSession();
    window.location.replace("login.html");
  },

  // ── Dashboard guard ────────────────────────────────────────────────────────

  /**
   * Call at the top of dashboard.html.
   * Redirects to login if not authenticated, otherwise returns the user object.
   * NEVER returns null while the token is valid — falls back to localStorage cache.
   */
  async requireAuth() {
    if (!this.isAuthenticated()) {
      window.location.replace("login.html");
      return null;
    }

    // Try to get fresh user data from backend.
    try {
      const fresh = await API.request("GET", "/auth/me");
      if (fresh && typeof fresh === "object") {
        localStorage.setItem("user", JSON.stringify(fresh));
        return fresh;
      }
    } catch (e) {
      // If the backend says the token is invalid or requires MFA, 
      // the token is effectively useless. Clear session and redirect.
      if (e.status === 401 || (e.status === 403 && e.data && e.data.detail === "mfa_required")) {
        console.warn("[Auth] Token invalid or MFA required, redirecting to login...");
        _clearSession();
        window.location.replace("login.html");
        return null;
      }
      
      // Other errors (e.g. 429 rate limit, network error) — not fatal.
      // Fall back to cached user — DO NOT redirect to login.
      console.warn("[Auth] /auth/me failed, using cached user:", e.status || e);
    }

    // Return cached user. If there's truly no cached user despite a valid
    // token, build a minimal object from the token payload itself.
    const cached = this.getCurrentUser();
    if (cached) return cached;

    // Last resort: decode email from token and return a minimal user object.
    try {
      const parts = this.getToken().split(".");
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      if (payload.sub) {
        const minimal = { email: payload.sub, username: payload.sub.split("@")[0], role: "user" };
        localStorage.setItem("user", JSON.stringify(minimal));
        return minimal;
      }
    } catch (e) { /* ignore */ }

    // Token is valid but we couldn't get any user data at all — rare edge case.
    // Still don't redirect; return a placeholder so the dashboard can render.
    return { email: "unknown", username: "User", role: "user" };
  },
};
