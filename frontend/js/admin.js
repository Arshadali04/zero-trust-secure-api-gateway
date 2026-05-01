// ── Admin Dashboard Logic ──────────────────────────────────────────────────

// Switch between Users and Logs tabs
function switchTab(tabName) {
    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    // Update content
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    document.getElementById(`${tabName}Tab`).classList.add('active');

    // Load data if switching
    if (tabName === 'users') loadUsers();
    if (tabName === 'logs') loadLogs();
}

// Format Dates safely
function formatDate(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    return d.toLocaleString();
}

// Load Users from Backend
async function loadUsers() {
    const tbody = document.getElementById('usersTableBody');
    try {
        const users = await API.request("GET", "/admin/users");
        
        if (!users || users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;">No users found.</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(u => `
            <tr>
                <td>${u.id}</td>
                <td><strong>${u.username}</strong></td>
                <td>${u.email}</td>
                <td>
                    <span class="badge ${u.role === 'admin' ? 'badge-admin' : 'badge-user'}">
                        ${u.role.toUpperCase()}
                    </span>
                </td>
                <td>
                    <span class="badge ${u.is_active ? 'badge-success' : 'badge-error'}">
                        ${u.is_active ? 'Active' : 'Disabled'}
                    </span>
                </td>
                <td>${new Date(u.created_at).toLocaleDateString()}</td>
                <td class="admin-actions">
                    ${u.role === 'user' 
                        ? `<button class="btn btn-secondary btn-small" onclick="promoteUser(${u.id})">Make Admin</button>`
                        : `<button class="btn btn-secondary btn-small" onclick="demoteUser(${u.id})">Remove Admin</button>`
                    }
                    <button class="btn btn-danger btn-small" onclick="deleteUser(${u.id})">Delete</button>
                </td>
            </tr>
        `).join('');

    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: red;">Failed to load users.</td></tr>';
    }
}

// Load Audit Logs from Backend
async function loadLogs() {
    const tbody = document.getElementById('logsTableBody');
    try {
        const logs = await API.request("GET", "/admin/audit-logs");
        
        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No audit logs found.</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map(l => {
            let details = {};
            try { details = JSON.parse(l.details || '{}'); } catch(e) {}
            
            // Format status color
            const statusColor = l.status_code >= 400 ? 'red' : 'green';

            return `
            <tr>
                <td style="white-space: nowrap; font-size: 0.9em;">${formatDate(l.timestamp)}</td>
                <td><strong>${l.action}</strong></td>
                <td><span class="badge" style="background: #e5e7eb; color: #374151;">${l.method}</span></td>
                <td><span style="color: ${statusColor}; font-weight: bold;">${l.status_code || '—'}</span></td>
                <td style="font-family: monospace;">${l.ip_address}</td>
                <td style="font-size: 0.9em;">
                    User: ${details.user || 'anonymous'}<br>
                    Time: ${details.elapsed_ms || 0}ms
                </td>
            </tr>
            `;
        }).join('');

    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: red;">Failed to load logs.</td></tr>';
    }
}

// Change user role helper
async function setRole(userId, role) {
    if (!confirm(`Are you sure you want to make user #${userId} an ${role}?`)) return;
    
    try {
        await API.request("PATCH", `/admin/users/${userId}/role?role=${role}`);
        UI.showSuccess(`User #${userId} is now an ${role}.`);
        loadUsers(); // refresh table
    } catch (e) {
        // UI.showError is handled by API.request internally, but we catch so it doesn't crash
    }
}

function promoteUser(id) { setRole(id, 'admin'); }
function demoteUser(id) { setRole(id, 'user'); }

// Delete user
async function deleteUser(userId) {
    if (!confirm(`Are you sure you want to PERMANENTLY DELETE user #${userId}? This action cannot be undone.`)) return;
    
    try {
        await API.request("DELETE", `/admin/users/${userId}`);
        UI.showSuccess(`User #${userId} deleted successfully.`);
        loadUsers(); // refresh table
    } catch (e) {
        // UI.showError is handled by API.request internally
    }
}

// ── On Page Load ────────────────────────────────────────────────────────────
window.addEventListener("load", async function () {
    // 1. Require Auth
    const user = await Auth.requireAuth();
    if (!user) return;

    // 2. Require Admin Role
    if (user.role !== 'admin') {
        UI.showError("Access Denied: You do not have admin privileges.");
        setTimeout(() => window.location.replace("dashboard.html"), 1500);
        return;
    }

    // 3. Initialize UI
    document.getElementById("userName").textContent = user.username || "Admin";
    
    // Load initial tab
    loadUsers();
});
