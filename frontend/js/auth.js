function extractErrorMessage(error, fallback = "Request failed") {
  const detail = error?.data?.detail;

  // FastAPI/Pydantic validation errors: { detail: [ {loc,msg,type}, ... ] }
  if (Array.isArray(detail)) {
    return detail
      .map((e) => {
        const loc = Array.isArray(e.loc) ? e.loc.slice(1).join(".") : "";
        const msg = e.msg || "Invalid value";
        return loc ? `${loc}: ${msg}` : msg;
      })
      .join(", ");
  }

  // Normal FastAPI errors: { detail: "..." }
  if (typeof detail === "string") return detail;

  if (typeof error?.data === "string") return error.data;
  if (typeof error?.message === "string") return error.message;

  return fallback;
}

const Auth = {
  async register(email, username, password, fullName) {
    UI.showLoading("Creating account...");

    try {
      await API.register(email, username, password, fullName);
      UI.hideLoading();
      UI.showSuccess("Account created! Redirecting to login...");
      setTimeout(() => (window.location.href = "login.html"), 1200);
    } catch (error) {
      UI.hideLoading();
      UI.showError(extractErrorMessage(error, "Registration failed"));
      // IMPORTANT: do not re-throw (prevents page “blink”)
      return null;
    }
  },

  async login(email, password) {
    UI.showLoading("Logging in...");

    try {
      const response = await API.login(email, password);

      // Store the token first so protected pages can proceed immediately.
      localStorage.setItem("token", response.access_token);

      // Try to warm the user cache, but do not treat a temporary /auth/me miss
      // as a failed login. That was causing the redirect loop back to login.
      await this.syncCurrentUser();

      UI.hideLoading();
      UI.showSuccess("Login successful!");

      setTimeout(() => {
        window.location.href = "dashboard.html";
      }, 500);

      return response;

    } catch (error) {
      UI.hideLoading();
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      UI.showError(extractErrorMessage(error, "Login failed or session invalid"));
      return null;
    }
  },

  logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    window.location.href = "login.html";
  },

  isAuthenticated() {
    const token = localStorage.getItem("token");

    if (!token) return false;

    try {
      const payloadPart = token.split(".")[1];
      if (!payloadPart) return false;

      const base64 = payloadPart
        .replace(/-/g, "+")
        .replace(/_/g, "/");
      const paddedBase64 = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");

      const payload = JSON.parse(atob(paddedBase64));

      if (payload.exp && Date.now() >= payload.exp * 1000) {
        return false;
      }

      return true;
    } catch (e) {
      console.error("JWT decode failed:", e);
      return false;
    }
  },

  getCurrentUser() {
    const raw = localStorage.getItem("user");
    if (!raw) return null;
    try {
      const obj = JSON.parse(raw);
      return obj && typeof obj === "object" ? obj : null;
    } catch {
      return null;
    }
  },

  setCurrentUser(userObj) {
    localStorage.setItem("user", JSON.stringify(userObj));
  },

  getToken() {
    return localStorage.getItem("token");
  },

  async syncCurrentUser() {
    const token = this.getToken();
    if (!token) {
      localStorage.removeItem("user");
      return null;
    }

    try {
      const me = await API.request("GET", "/auth/me");
      this.setCurrentUser(me);
      return me;
    } catch (e) {
      console.error("syncCurrentUser failed:", e);
      return null;
    }
  },

  async handleOAuthCallback() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    const user = params.get("user");
    const error = params.get("error");
    const message = params.get("msg");

    if (error) {
      UI.showError(message || "OAuth login failed");
      window.history.replaceState({}, document.title, window.location.pathname);
      return false;
    }

    if (!token) {
      return false;
    }

    localStorage.setItem("token", token);

    if (user) {
      const username = user.split("@")[0] || "user";
      this.setCurrentUser({
        email: user,
        username,
        full_name: username,
      });
    }

    await this.syncCurrentUser();
    UI.showSuccess("Login successful!");
    window.history.replaceState({}, document.title, window.location.pathname);

    setTimeout(() => {
      window.location.href = "dashboard.html";
    }, 500);

    return true;
  },
};
