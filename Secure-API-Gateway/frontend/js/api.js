/**
 * Zero Trust API Gateway - API Client
 * Handles all communication with the FastAPI backend.
 */
const API_BASE = "http://localhost:8000";

class ApiClient {
    constructor() {
        this.token = localStorage.getItem("zt_token");
        this.role = localStorage.getItem("zt_role");
        this.username = localStorage.getItem("zt_username");
    }

    /** Store auth data after successful login */
    setAuth(token, role, username) {
        this.token = token;
        this.role = role;
        this.username = username;
        localStorage.setItem("zt_token", token);
        localStorage.setItem("zt_role", role);
        localStorage.setItem("zt_username", username);
    }

    /** Clear auth data on logout */
    clearAuth() {
        this.token = null;
        this.role = null;
        this.username = null;
        localStorage.removeItem("zt_token");
        localStorage.removeItem("zt_role");
        localStorage.removeItem("zt_username");
    }

    isAuthenticated() {
        return !!this.token;
    }

    /** Make an authenticated API request */
    async request(method, path, body = null) {
        const headers = { "Content-Type": "application/json" };
        if (this.token) {
            headers["Authorization"] = `Bearer ${this.token}`;
        }

        const options = { method, headers };
        if (body) options.body = JSON.stringify(body);

        const startTime = performance.now();
        try {
            const response = await fetch(`${API_BASE}${path}`, options);
            const elapsed = Math.round(performance.now() - startTime);
            const data = await response.json();
            return {
                status: response.status,
                ok: response.ok,
                data,
                elapsed,
            };
        } catch (error) {
            return {
                status: 0,
                ok: false,
                data: { error: "Network error. Is the backend running?" },
                elapsed: 0,
            };
        }
    }

    // ── Auth Endpoints ──────────────────────────────
    async login(username, password) {
        const result = await this.request("POST", "/api/login", { username, password });
        if (result.ok) {
            this.setAuth(result.data.access_token, result.data.role, username);
        }
        return result;
    }

    async register(username, password, role = "user") {
        return this.request("POST", "/api/register", { username, password, role });
    }

    async verifyToken() {
        return this.request("GET", "/api/verify");
    }

    // ── Protected Endpoints ─────────────────────────
    async getData() {
        return this.request("GET", "/api/data");
    }

    async getUsers() {
        return this.request("GET", "/api/admin/users");
    }

    async deleteUser(username) {
        return this.request("DELETE", `/api/admin/users/${username}`);
    }

    // ── Monitoring ──────────────────────────────────
    async getLogs() {
        return this.request("GET", "/api/gateway/logs");
    }

    async getStats() {
        return this.request("GET", "/api/gateway/stats");
    }
}

// Singleton
const api = new ApiClient();
