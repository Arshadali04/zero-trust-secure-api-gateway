/**
 * Zero Trust API Gateway - Frontend Application
 * Handles UI state, login/logout, API testing, and dashboard rendering.
 */

document.addEventListener("DOMContentLoaded", () => {
    // ── DOM References ──────────────────────────────
    const loginContainer = document.getElementById("login-container");
    const appContainer = document.getElementById("app-container");
    const loginForm = document.getElementById("login-form");
    const registerForm = document.getElementById("register-form");
    const loginAlert = document.getElementById("login-alert");
    const registerAlert = document.getElementById("register-alert");
    const loginToggle = document.getElementById("login-toggle");
    const registerToggle = document.getElementById("register-toggle");
    const loginView = document.getElementById("login-view");
    const registerView = document.getElementById("register-view");
    const logoutBtn = document.getElementById("logout-btn");
    const userInfo = document.getElementById("user-info");
    const userRole = document.getElementById("user-role");
    const responseBody = document.getElementById("response-body");
    const responseStatus = document.getElementById("response-status");
    const responseTime = document.getElementById("response-time");

    // ── Init: check existing auth ───────────────────
    if (api.isAuthenticated()) {
        api.verifyToken().then((result) => {
            if (result.ok) {
                showDashboard();
            } else {
                api.clearAuth();
            }
        });
    }

    // ── Login / Register Toggle ─────────────────────
    loginToggle?.addEventListener("click", (e) => {
        e.preventDefault();
        loginView.style.display = "none";
        registerView.style.display = "block";
    });

    registerToggle?.addEventListener("click", (e) => {
        e.preventDefault();
        registerView.style.display = "none";
        loginView.style.display = "block";
    });

    // ── Login ───────────────────────────────────────
    loginForm?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = document.getElementById("login-username").value.trim();
        const password = document.getElementById("login-password").value;

        if (!username || !password) {
            showAlert(loginAlert, "Please fill in all fields", "error");
            return;
        }

        const btn = loginForm.querySelector("button[type=submit]");
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Authenticating...';

        const result = await api.login(username, password);

        btn.disabled = false;
        btn.textContent = "Sign In";

        if (result.ok) {
            showAlert(loginAlert, "Login successful! Redirecting...", "success");
            setTimeout(showDashboard, 500);
        } else {
            showAlert(loginAlert, result.data.detail || "Login failed", "error");
        }
    });

    // ── Register ────────────────────────────────────
    registerForm?.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = document.getElementById("reg-username").value.trim();
        const password = document.getElementById("reg-password").value;
        const role = document.getElementById("reg-role").value;

        if (!username || !password) {
            showAlert(registerAlert, "Please fill in all fields", "error");
            return;
        }
        if (username.length < 3) {
            showAlert(registerAlert, "Username must be at least 3 characters", "error");
            return;
        }
        if (password.length < 6) {
            showAlert(registerAlert, "Password must be at least 6 characters", "error");
            return;
        }

        const result = await api.register(username, password, role);

        if (result.ok) {
            showAlert(registerAlert, "Registration successful! Please log in.", "success");
            setTimeout(() => {
                registerView.style.display = "none";
                loginView.style.display = "block";
            }, 1000);
        } else {
            showAlert(registerAlert, result.data.detail || "Registration failed", "error");
        }
    });

    // ── Logout ──────────────────────────────────────
    logoutBtn?.addEventListener("click", () => {
        api.clearAuth();
        showLogin();
    });

    // ── View Switching ──────────────────────────────
    function showDashboard() {
        loginContainer.classList.add("hidden");
        appContainer.classList.add("active");
        userInfo.textContent = api.username;
        userRole.textContent = api.role;
        userRole.className = `role-tag ${api.role}`;

        // NEW: Display the token in the header
        document.getElementById("user-token").textContent = api.token;

        loadStats();
    }
    function showLogin() {
        appContainer.classList.remove("active");
        loginContainer.classList.remove("hidden");
        loginAlert.classList.remove("show");
    }

    // ── Alert Helper ────────────────────────────────
    function showAlert(el, message, type) {
        el.textContent = message;
        el.className = `alert ${type} show`;
        setTimeout(() => el.classList.remove("show"), 5000);
    }

    // ── API Tester ──────────────────────────────────
    const endpoints = document.querySelectorAll(".endpoint-item");
    endpoints.forEach((ep) => {
        ep.addEventListener("click", async () => {
            const method = ep.dataset.method;
            const path = ep.dataset.path;

            // 1. Ask for Token Validation
            const userInputToken = prompt(`Security Check: \nTo access ${path}, please paste your active JWT token to validate your session:`);

            // If user cancels or enters wrong token, deny access
            if (userInputToken !== api.token) {
                alert("❌ Validation Failed: The token provided is invalid or empty.");
                return;
            }

            // 2. Check Role before giving access (Client-side RBAC)
            // Define which routes require elevated privileges
            const isAdminRoute = path.includes('/admin/') || path.includes('/gateway/');

            if (isAdminRoute && api.role !== 'admin' && api.role !== 'moderator') {
                alert(`🚫 Access Denied: Your role '${api.role}' is not authorized to access restricted data at ${path}.`);
                return;
            }

            // 3. Proceed with request if validations pass
            endpoints.forEach((e) => e.classList.remove("active"));
            ep.classList.add("active");

            responseBody.textContent = "Loading...";
            responseStatus.textContent = "...";
            responseStatus.className = "status-badge";
            responseTime.textContent = "";

            const result = await api.request(method, path);

            responseBody.textContent = JSON.stringify(result.data, null, 2);
            responseStatus.textContent = result.status;
            responseStatus.className = `status-badge ${result.ok ? "success" : "error"}`;
            responseTime.textContent = `${result.elapsed}ms`;
        });
    });

    // ── Tabs ────────────────────────────────────────
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach((btn) => {
        btn.addEventListener("click", () => {
            const target = btn.dataset.tab;
            tabBtns.forEach((b) => b.classList.remove("active"));
            btn.classList.add("active");
            document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
            document.getElementById(`tab-${target}`).classList.add("active");

            if (target === "logs") loadLogs();
            if (target === "overview") loadStats();
        });
    });

    // ── Load Stats ──────────────────────────────────
    async function loadStats() {
        const result = await api.getStats();
        if (result.ok) {
            document.getElementById("stat-total").textContent = result.data.total_requests;
            document.getElementById("stat-blocked").textContent = result.data.blocked_requests;
            document.getElementById("stat-users").textContent = result.data.active_users;
            const mins = Math.floor(result.data.uptime_seconds / 60);
            document.getElementById("stat-uptime").textContent = `${mins}m`;
        }
    }

    // ── Load Logs ───────────────────────────────────
    async function loadLogs() {
        const tbody = document.getElementById("logs-body");
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">Loading...</td></tr>';

        const result = await api.getLogs();
        if (result.ok && result.data.logs) {
            if (result.data.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">No logs yet</td></tr>';
                return;
            }
            tbody.innerHTML = result.data.logs
                .map(
                    (log) => `
                <tr>
                    <td style="color:var(--text-muted)">${new Date(log.timestamp).toLocaleTimeString()}</td>
                    <td><span class="method-badge ${log.method}">${log.method}</span></td>
                    <td>${log.path}</td>
                    <td>${log.user || "—"}</td>
                    <td><span class="status-badge ${log.status_code < 400 ? "success" : "error"}">${log.status_code}</span></td>
                    <td>${log.response_time_ms}ms</td>
                </tr>
            `
                )
                .join("");
        } else {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--accent-red)">Access denied or error</td></tr>';
        }
    }
});
