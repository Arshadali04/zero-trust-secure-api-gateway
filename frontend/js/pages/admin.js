/**
 * admin.js — Administration page module
 *
 * Loaded as <script type="module"> after api.js, ui.js, and auth.js.
 * Requires: window.Auth, window.API, window.UI, window._extractError
 */

// Scene + animation loaded dynamically so a CDN failure never breaks page logic.
let initAdminScene = () => {};
let revealPanels = () => {};
let revealTableRows = () => {};

// ── State ────────────────────────────────────────────────────────────────────

/** @type {Array<object>} */
let allUsers  = [];

/** @type {Array<object>} */
let allLogs   = [];

/** @type {Array<object>} */
let allEvents = [];

let logsLoaded   = false;
let eventsLoaded = false;

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * HTML-escape a value so it is safe to insert via innerHTML.
 * @param {*} s
 * @returns {string}
 */
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Format a timestamp — handles ISO strings, Unix seconds (< 1e12), and ms.
 * @param {string|number|null} ts
 * @returns {string}
 */
function fmt(ts) {
  if (ts == null || ts === '') return '—';
  try {
    const n = Number(ts);
    const d = !isNaN(n) && n > 0
      ? (n < 1e12 ? new Date(n * 1000) : new Date(n))
      : new Date(ts);
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleString();
  } catch (_) {
    return String(ts);
  }
}

/**
 * CSS color variable string for a 0–1 risk score.
 * @param {number} score
 * @returns {string}
 */
function riskColor(score) {
  if (score < 0.3) return 'var(--success)';
  if (score < 0.7) return 'var(--warning)';
  return 'var(--alert)';
}

/**
 * Badge class for a threat type string.
 * @param {string|null|undefined} type
 * @returns {string}
 */
function threatBadgeClass(type) {
  if (!type) return 'badge-dim';
  const t = type.toLowerCase();
  if (
    t.includes('sql') || t.includes('sqli') ||
    t.includes('xss') || t.includes('injection') ||
    t.includes('command') || t.includes('cmdi')
  ) return 'badge-alert';

  if (
    t.includes('bruteforce') || t.includes('brute') ||
    t.includes('traversal')  || t.includes('flood') ||
    t.includes('rate')       || t.includes('dos')
  ) return 'badge-warn';

  if (
    t.includes('anomaly')  || t.includes('behavior') ||
    t.includes('unusual')  || t.includes('travel')   ||
    t.includes('ml')
  ) return 'badge-info';

  return 'badge-dim';
}

/**
 * Single-row HTML for "loading" state in a table.
 * @param {number} cols
 * @returns {string}
 */
function loadingRow(cols) {
  return `<tr><td colspan="${cols}"><div class="empty-state">Loading…</div></td></tr>`;
}

/**
 * Single-row HTML for an error state in a table.
 * @param {number} cols
 * @param {string} msg
 * @returns {string}
 */
function errorRow(cols, msg) {
  return `<tr><td colspan="${cols}"><div class="empty-state text-alert">${esc(msg)}</div></td></tr>`;
}

/**
 * Single-row HTML for an empty state in a table.
 * @param {number} cols
 * @param {string} msg
 * @returns {string}
 */
function emptyRow(cols, msg) {
  return `<tr><td colspan="${cols}"><div class="empty-state">${esc(msg)}</div></td></tr>`;
}

// ── Render: Users ─────────────────────────────────────────────────────────────

/**
 * Render (or re-render) the users table with the given user array.
 * @param {Array<object>} users
 */
function renderUsersTable(users) {
  const tbody = document.getElementById('usersBody');
  if (!tbody) return;

  if (!users || users.length === 0) {
    tbody.innerHTML = emptyRow(6, 'No users found.');
    return;
  }

  tbody.innerHTML = users.map(u => {
    // ── Status badge
    const isFrozen  = !!(u.account_frozen_until && new Date(u.account_frozen_until) > new Date());
    const isActive  = !!u.is_active;
    const statusBadge = !isActive
      ? '<span class="badge badge-dim">Inactive</span>'
      : isFrozen
        ? '<span class="badge badge-alert">Frozen</span>'
        : '<span class="badge badge-ok">Active</span>';

    // ── Risk score
    const rs = typeof u.risk_score === 'number' ? u.risk_score : null;
    const rsHtml = rs !== null
      ? `<span class="mono" style="color:${riskColor(rs)}">${rs.toFixed(3)}</span>`
      : '<span class="text-dim" style="font-family:var(--mono)">—</span>';

    // ── Inline role select
    const roleSelect = `
      <select class="form-select"
              data-action="role-change"
              data-uid="${esc(u.id)}"
              style="min-width:80px;"
              aria-label="Role for ${esc(u.email)}">
        <option value="user"${u.role === 'user'  ? ' selected' : ''}>user</option>
        <option value="admin"${u.role === 'admin' ? ' selected' : ''}>admin</option>
      </select>`.trim();

    // ── Action buttons
    const unfreezeBtn = isFrozen
      ? `<button class="btn btn-ghost btn-sm"
                 data-action="unfreeze"
                 data-uid="${esc(u.id)}"
                 type="button">Unfreeze</button>`
      : '';
    const deleteBtn = `<button class="btn btn-danger btn-sm"
               data-action="delete"
               data-uid="${esc(u.id)}"
               data-email="${esc(u.email)}"
               type="button">Delete</button>`;
    const actionsHtml = `<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
      ${unfreezeBtn}${deleteBtn}
    </div>`.trim();

    return `<tr>
      <td>
        <span style="font-family:var(--mono);font-size:0.8rem;color:var(--text);">${esc(u.email || '—')}</span>
      </td>
      <td style="font-weight:500;">${esc(u.username || '—')}</td>
      <td>${roleSelect}</td>
      <td>${statusBadge}</td>
      <td>${rsHtml}</td>
      <td>${actionsHtml}</td>
    </tr>`;
  }).join('');

  revealTableRows(tbody); // Motion: stagger rows in
}

// ── Render: Audit Logs ───────────────────────────────────────────────────────

/**
 * Render the audit logs table (up to 50 most recent rows).
 * @param {Array<object>} logs
 */
function renderAuditTable(logs) {
  const tbody = document.getElementById('logsBody');
  if (!tbody) return;

  if (!logs || logs.length === 0) {
    tbody.innerHTML = emptyRow(5, 'No audit log entries found.');
    return;
  }

  tbody.innerHTML = logs.slice(0, 50).map(l => `
    <tr>
      <td class="mono" style="white-space:nowrap;">${fmt(l.timestamp)}</td>
      <td class="mono">${esc(l.user_id || '—')}</td>
      <td class="mono">${esc(l.action  || '—')}</td>
      <td class="mono"
          style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
          title="${esc(l.resource || '')}">${esc(l.resource || '—')}</td>
      <td class="mono">${esc(l.ip_address || '—')}</td>
    </tr>`).join('');
}

// ── Render: Security Events ──────────────────────────────────────────────────

/**
 * Render the security events table.
 * @param {Array<object>} events
 */
function renderEventsTable(events) {
  const tbody = document.getElementById('eventsBody');
  if (!tbody) return;

  if (!events || events.length === 0) {
    tbody.innerHTML = emptyRow(5, 'No security events detected.');
    return;
  }

  tbody.innerHTML = events.map(e => {
    const rs    = typeof e.risk_score === 'number' ? e.risk_score : 0;
    const pct   = Math.min(100, Math.round(rs * 100));
    const color = riskColor(rs);

    const riskBarHtml = `
      <div class="risk-bar-wrap">
        <div class="risk-bar-track">
          <div class="risk-bar-fill" style="width:${pct}%;background:${color};"></div>
        </div>
        <span class="mono" style="color:${color};min-width:38px;text-align:right;">${rs.toFixed(2)}</span>
      </div>`.trim();

    return `<tr>
      <td class="mono" style="white-space:nowrap;">${fmt(e.timestamp)}</td>
      <td><span class="badge ${threatBadgeClass(e.threat_type)}">${esc(e.threat_type || '—')}</span></td>
      <td style="font-size:0.8rem;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
          title="${esc(e.detail || e.description || '')}">${esc(e.detail || e.description || '—')}</td>
      <td>${riskBarHtml}</td>
      <td class="mono">${esc(e.ip_address || '—')}</td>
    </tr>`;
  }).join('');
}

// ── Data loaders ─────────────────────────────────────────────────────────────

/**
 * Fetch all admin users, update metric cards, and re-render the table.
 */
async function loadUsers() {
  const tbody = document.getElementById('usersBody');
  if (tbody) tbody.innerHTML = loadingRow(6);

  try {
    allUsers = await API.getAdminUsers() || [];

    // Update metric cards
    const setMetric = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };
    setMetric('metricTotal',  allUsers.length);
    setMetric('metricAdmins', allUsers.filter(u => u.role === 'admin').length);
    const now = new Date();
    setMetric('metricActive', allUsers.filter(u => u.is_active && !(u.account_frozen_until && new Date(u.account_frozen_until) > now)).length);
    setMetric('metricFrozen', allUsers.filter(u => u.account_frozen_until && new Date(u.account_frozen_until) > now).length);

    renderUsersTable(allUsers);
  } catch (err) {
    if (tbody) tbody.innerHTML = errorRow(6, 'Failed to load users. Check admin permissions.');
  }
}

/**
 * Fetch audit logs and render the table.
 * @param {boolean} [force=false] — skip the "already loaded" guard if true
 */
async function loadAuditLogs(force) {
  if (logsLoaded && !force) return;
  const tbody = document.getElementById('logsBody');
  if (tbody) tbody.innerHTML = loadingRow(5);

  try {
    allLogs = await API.getAuditLogs() || [];
    logsLoaded = true;
    renderAuditTable(allLogs);
  } catch (err) {
    if (tbody) tbody.innerHTML = errorRow(5, 'Failed to load audit logs.');
  }
}

/**
 * Fetch security events (optionally filtered by threat type) and render.
 * On the first call, also populate the threat type filter <select>.
 * @param {string} [threatType='']
 */
async function loadSecurityEvents(threatType) {
  const tbody = document.getElementById('eventsBody');
  if (tbody) tbody.innerHTML = loadingRow(5);

  try {
    allEvents = await API.getSecurityEvents(threatType || '') || [];

    // On first load, populate the <select> with unique threat types
    if (!eventsLoaded) {
      const sel = document.getElementById('threatFilter');
      if (sel) {
        const types = [...new Set(
          allEvents.map(e => e.threat_type).filter(Boolean)
        )].sort();

        // Remove all options except the first "All threat types" placeholder
        while (sel.options.length > 1) sel.remove(1);

        types.forEach(t => {
          const opt = document.createElement('option');
          opt.value = t;
          opt.textContent = t.replace(/_/g, ' ');
          sel.appendChild(opt);
        });
      }
      eventsLoaded = true;
    }

    renderEventsTable(allEvents);
  } catch (err) {
    if (tbody) tbody.innerHTML = errorRow(5, 'Failed to load security events.');
  }
}

// ── Tab switching ─────────────────────────────────────────────────────────────

/**
 * Activate a tab by its name ("users" | "logs" | "events").
 * Lazily loads data for logs and events on first reveal.
 * @param {string} tabName
 */
function switchTab(tabName) {
  // Update tab button states
  document.querySelectorAll('.tab-btn').forEach(b => {
    const isActive = b.dataset.tab === tabName;
    b.classList.toggle('active', isActive);
    b.setAttribute('aria-selected', String(isActive));
  });

  // Show/hide tab panels
  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.toggle('active', p.id === `panel-${tabName}`);
  });

  // Lazy-load data
  if (tabName === 'logs')   loadAuditLogs(false);
  if (tabName === 'events' && !eventsLoaded) loadSecurityEvents('');
}

// ── Action handlers ───────────────────────────────────────────────────────────

/**
 * Update a user's role via the API, then reload the table.
 * @param {string|number} id
 * @param {string} newRole  "admin" | "user"
 */
async function handleRoleChange(id, newRole) {
  try {
    await API.updateUserRole(id, newRole);
    if (window.UI) UI.showSuccess(`Role updated to "${newRole}".`);
    await loadUsers();
  } catch (err) {
    const msg = (window._extractError && _extractError(err)) || 'Failed to update role.';
    if (window.UI) UI.showError(msg);
    // Re-render to reset the select to the actual value
    await loadUsers();
  }
}

/**
 * Unfreeze a user account after confirmation.
 * @param {string|number} id
 */
async function handleUnfreeze(id) {
  if (!confirm(`Unfreeze account #${id}? This will restore login access.`)) return;
  try {
    await API.unfreezeUser(id);
    if (window.UI) UI.showSuccess(`Account #${id} has been unfrozen.`);
    await loadUsers();
  } catch (err) {
    const msg = (window._extractError && _extractError(err)) || 'Failed to unfreeze account.';
    if (window.UI) UI.showError(msg);
  }
}

/**
 * Permanently delete a user after confirmation.
 * @param {string|number} id
 * @param {string} email
 */
async function handleDelete(id, email) {
  if (!confirm(`Delete user "${email}"?\n\nThis cannot be undone.`)) return;
  try {
    await API.deleteUser(id);
    if (window.UI) UI.showSuccess('User deleted.');
    await loadUsers();
  } catch (err) {
    const msg = (window._extractError && _extractError(err)) || 'Failed to delete user.';
    if (window.UI) UI.showError(msg);
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {

  // 1. Admin guard — redirects non-admins to dashboard.html, unauthed to login.html
  const user = await Auth.requireAdmin();
  if (!user) return;

  // 2. Init WebGL admin scene + animations (lazy, CDN-resilient)
  Promise.all([
    import('../scene-admin.js').catch(() => null),
    import('../motion-utils.js').catch(() => null),
  ]).then(([sceneM, motionM]) => {
    if (sceneM) { const c = document.getElementById('bg-canvas'); if (c) sceneM.initAdminScene(c); }
    if (motionM) { revealPanels = motionM.revealPanels; revealTableRows = motionM.revealTableRows; motionM.revealPanels('.panel', 0.1); }
  });

  // 3. Populate topbar username
  const topbarUser = document.getElementById('topbarUser');
  if (topbarUser) topbarUser.textContent = user.username || user.email || 'admin';

  // 4. Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // 5. User search — filter visible rows on input
  const searchInput = document.getElementById('userSearch');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const q = searchInput.value.toLowerCase().trim();
      if (!q) {
        renderUsersTable(allUsers);
        return;
      }
      renderUsersTable(allUsers.filter(u =>
        (u.email    || '').toLowerCase().includes(q) ||
        (u.username || '').toLowerCase().includes(q)
      ));
    });
  }

  // 6. Users table — event delegation for role select, unfreeze, delete
  const usersBody = document.getElementById('usersBody');
  if (usersBody) {
    // Role change: select "change" event
    usersBody.addEventListener('change', async e => {
      if (e.target.dataset.action === 'role-change') {
        await handleRoleChange(e.target.dataset.uid, e.target.value);
      }
    });

    // Unfreeze / Delete: button "click" event
    usersBody.addEventListener('click', async e => {
      const target = e.target.closest('[data-action]');
      if (!target || target.tagName === 'SELECT') return;

      const action = target.dataset.action;
      if (action === 'unfreeze') {
        await handleUnfreeze(target.dataset.uid);
      } else if (action === 'delete') {
        await handleDelete(target.dataset.uid, target.dataset.email);
      }
    });
  }

  // 7. Refresh audit logs button
  const refreshLogsBtn = document.getElementById('refreshLogsBtn');
  if (refreshLogsBtn) {
    refreshLogsBtn.addEventListener('click', () => loadAuditLogs(true));
  }

  // 8. Security events filter button
  const filterBtn = document.getElementById('filterEventsBtn');
  if (filterBtn) {
    filterBtn.addEventListener('click', () => {
      const sel = document.getElementById('threatFilter');
      loadSecurityEvents(sel ? sel.value : '');
    });
  }

  // 9. Logout
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) logoutBtn.addEventListener('click', () => Auth.logout());

  // 10. Initial data load (users tab is active by default)
  await loadUsers();
});
