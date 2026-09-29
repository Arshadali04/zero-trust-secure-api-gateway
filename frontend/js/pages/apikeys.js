/**
 * apikeys.js — Page module for api-keys.html
 *
 * Handles:
 *  - Auth guard
 *  - Tab switching (API Keys / Upstream Services)
 *  - API Keys table: list, rotate, revoke
 *  - Services table: list, revoke, reactivate, delete
 *  - "New API Key" modal with dynamic scope checkboxes
 *  - One-time key reveal modal (key destroyed from memory on close)
 *  - "Register Service" modal
 */

// Scene + animation loaded dynamically so a CDN failure never breaks page logic.
let initProfileScene = () => {};
let revealPanels = () => {};
let revealTableRows = () => {};
let modalOpen = () => {};

// ─────────────────────────────────────────────
// DOM helper
// ─────────────────────────────────────────────
function $(id) { return document.getElementById(id); }

// ─────────────────────────────────────────────
// HTML escaping
// ─────────────────────────────────────────────
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ─────────────────────────────────────────────
// Date formatting
// ─────────────────────────────────────────────
function parseUtcDate(ts) {
  if (ts == null || ts === '') return null;
  if (ts instanceof Date) return isNaN(ts.getTime()) ? null : ts;
  const n = Number(ts);
  if (!isNaN(n) && n > 0) return n < 1e12 ? new Date(n * 1000) : new Date(n);
  let str = String(ts).trim();
  if (!str) return null;
  if (!str.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(str)) str += 'Z';
  const d = new Date(str);
  return isNaN(d.getTime()) ? new Date(ts) : d;
}

function fmt(s) {
  if (!s) return '<span style="color:var(--dim);">—</span>';
  const d = parseUtcDate(s);
  return esc(d && !isNaN(d.getTime()) ? d.toLocaleString() : String(s));
}

// ─────────────────────────────────────────────
// Empty row helper
// ─────────────────────────────────────────────
function emptyRow(cols, msg) {
  return `<tr><td colspan="${cols}"><div class="empty-state">${esc(msg)}</div></td></tr>`;
}

// ─────────────────────────────────────────────
// Module-level state
// ─────────────────────────────────────────────
let _services = [];   // cached for scope checkboxes
let _revealKey = null; // one-time key — cleared on modal close

// ─────────────────────────────────────────────
// Key Reveal Modal
// ─────────────────────────────────────────────
function showKeyReveal(key) {
  _revealKey = key;
  $('revealKeyText').textContent = key;

  const copyBtn = $('copyKeyBtn');
  copyBtn.textContent = 'Copy to clipboard';
  copyBtn.style.minWidth = '';

  $('keyRevealModal').style.display = 'flex';
  modalOpen($('keyRevealModal').querySelector('.modal-box')); // Motion: spring open
}

function closeKeyReveal() {
  // Destroy the key from memory and DOM before hiding
  _revealKey = null;
  $('revealKeyText').textContent = '';
  $('keyRevealModal').style.display = 'none';
}

// ─────────────────────────────────────────────
// Services scope checkboxes (inside new-key modal)
// ─────────────────────────────────────────────
function rebuildScopeCheckboxes(services, preselectedScope) {
  const group = $('scopesGroup');
  if (!group) return;

  // Remove any previously injected proxy scope rows (keep the first "all" row)
  group.querySelectorAll('.proxy-scope-item').forEach((el) => el.remove());

  const activeServices = (services || []).filter((s) => s.is_active);
  activeServices.forEach((svc) => {
    const scopeVal = `proxy:${svc.name}`;
    const isPreselected = preselectedScope === scopeVal;
    const label = document.createElement('label');
    label.className = 'checkbox-item proxy-scope-item';
    label.style.cursor = 'pointer';
    label.innerHTML =
      `<input type="checkbox" class="proxy-scope-cb" value="${esc(scopeVal)}"${isPreselected ? ' checked' : ''}>`
      + `<span>Proxy: <strong>${esc(svc.name)}</strong>`
      + ` <span class="badge badge-dim" style="margin-left:4px;">${esc(scopeVal)}</span></span>`;
    group.appendChild(label);
  });

  const scopeAll = $('scopeAll');
  if (scopeAll) {
    if (preselectedScope) {
      scopeAll.checked = false;
    }
  }

  syncScopeCheckboxes();
}

function syncScopeCheckboxes() {
  const group = $('scopesGroup');
  if (!group) return;
  const scopeAll = $('scopeAll');
  if (!scopeAll) return;

  const proxyBoxes = group.querySelectorAll('.proxy-scope-cb');
  if (scopeAll.checked) {
    proxyBoxes.forEach((cb) => {
      cb.checked = false;
      cb.closest('.checkbox-item').style.opacity = '0.6';
    });
  } else {
    proxyBoxes.forEach((cb) => {
      cb.closest('.checkbox-item').style.opacity = '1';
    });
  }
}

// ─────────────────────────────────────────────
// Build scopes array from form checkboxes
// ─────────────────────────────────────────────
function collectScopes() {
  const group = $('scopesGroup');
  if (!group) return ['all'];
  const allCb = $('scopeAll');

  if (allCb && allCb.checked) return ['all'];

  const checked = [...group.querySelectorAll('.proxy-scope-cb:checked')]
    .map((cb) => cb.value);

  return checked.length > 0 ? checked : ['all'];
}

// ─────────────────────────────────────────────
// API Keys table
// ─────────────────────────────────────────────
async function loadApiKeys() {
  const tbody = $('keysTableBody');
  tbody.innerHTML = emptyRow(7, 'Loading API keys…');

  try {
    const keys = await API.getApiKeys() || [];
    renderApiKeys(keys);
  } catch (err) {
    tbody.innerHTML = emptyRow(7, 'Failed to load API keys.');
  }
}

function renderApiKeys(keys) {
  const tbody = $('keysTableBody');

  if (!keys.length) {
    tbody.innerHTML = emptyRow(7, 'No API keys yet — create one with the button above.');
    return;
  }

  tbody.innerHTML = keys.map((k) => {
    const expDate   = k.expires_at ? parseUtcDate(k.expires_at) : null;
    const isExpired = !!(expDate && expDate < new Date());
    const isRevoked = !!k.revoked_at || (k.is_active === false);
    const isActive  = !isRevoked && !isExpired;
    const scopes    = (k.scopes || [])
      .map((s) => `<span class="badge badge-info">${esc(s)}</span>`)
      .join(' ');
    const statusBadge = isRevoked
      ? '<span class="badge badge-alert">Revoked</span>'
      : isExpired
        ? '<span class="badge badge-warn">Expired</span>'
        : '<span class="badge badge-ok">Active</span>';
    const actions = isActive
      ? `<button class="btn btn-ghost btn-sm" data-action="rotate" data-id="${esc(k.id)}">Rotate</button>`
        + `<button class="btn btn-danger btn-sm" data-action="revoke" data-id="${esc(k.id)}">Revoke</button>`
      : '<span style="font-size:0.8rem;color:var(--dim);">—</span>';

    return `<tr>
      <td>${esc(k.name)}</td>
      <td><span class="mono">${esc(k.key_prefix)}••••</span></td>
      <td>${scopes || '<span style="color:var(--dim);">—</span>'}</td>
      <td><span class="mono" style="font-size:0.75rem;">${fmt(k.last_used_at)}</span></td>
      <td><span class="mono" style="font-size:0.75rem;">${fmt(k.expires_at)}</span></td>
      <td>${statusBadge}</td>
      <td><div class="actions-cell">${actions}</div></td>
    </tr>`;
  }).join('');

  revealTableRows(tbody); // Motion: stagger key rows

  // Attach action handlers via event delegation
  tbody.querySelectorAll('[data-action]').forEach((btn) => {
    btn.addEventListener('click', () => handleKeyAction(btn.dataset.action, btn.dataset.id));
  });
}

async function handleKeyAction(action, id) {
  if (action === 'revoke') {
    if (!confirm('Revoke this API key? It will stop working immediately.')) return;
    try {
      await API.revokeApiKey(id);
      loadApiKeys();
    } catch (err) {
      alert('Failed to revoke key: ' + window._extractError(err));
    }
  } else if (action === 'rotate') {
    if (!confirm('Rotate this key? The old key will become invalid immediately.')) return;
    try {
      const data = await API.rotateApiKey(id);
      loadApiKeys();
      if (data && data.key) showKeyReveal(data.key);
    } catch (err) {
      alert('Failed to rotate key: ' + window._extractError(err));
    }
  }
}

// ─────────────────────────────────────────────
// Services table
// ─────────────────────────────────────────────
async function loadServices() {
  const tbody = $('servicesTableBody');
  tbody.innerHTML = emptyRow(4, 'Loading services…');

  try {
    _services = await API.getServices(true) || [];
    renderServices(_services);
  } catch (err) {
    tbody.innerHTML = emptyRow(4, 'Failed to load services.');
  }
}

function renderServices(services) {
  const tbody = $('servicesTableBody');

  if (!services.length) {
    tbody.innerHTML = emptyRow(4, 'No services registered yet.');
    return;
  }

  tbody.innerHTML = services.map((s) => {
    const statusBadge = s.is_active
      ? '<span class="badge badge-ok">Active</span>'
      : '<span class="badge badge-alert">Inactive</span>';
    const actions = s.is_active
      ? `<button class="btn btn-ghost btn-sm text-accent" data-action="create-key" data-name="${esc(s.name)}">Create Key</button>`
        + `<button class="btn btn-danger btn-sm" data-action="revoke" data-id="${esc(s.id)}">Deactivate</button>`
        + `<button class="btn btn-dim btn-sm" data-action="delete" data-id="${esc(s.id)}">Delete</button>`
      : `<button class="btn btn-ghost btn-sm" data-action="reactivate" data-id="${esc(s.id)}">Reactivate</button>`
        + `<button class="btn btn-danger btn-sm" data-action="delete" data-id="${esc(s.id)}">Delete</button>`;

    return `<tr>
      <td><strong>${esc(s.name)}</strong></td>
      <td><span class="mono">${esc(s.upstream_url)}</span></td>
      <td>${statusBadge}</td>
      <td><div class="actions-cell">${actions}</div></td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('[data-action]').forEach((btn) => {
    btn.addEventListener('click', () => handleServiceAction(btn.dataset.action, btn.dataset.id, btn.dataset.name));
  });
}

async function handleServiceAction(action, id, name) {
  if (action === 'create-key') {
    openNewKeyModal(name ? `proxy:${name}` : null);
    return;
  }
  if (action === 'revoke') {
    try {
      await API.revokeService(id);
      loadServices();
    } catch (err) {
      alert('Failed to deactivate service: ' + window._extractError(err));
    }
  } else if (action === 'reactivate') {
    try {
      await API.reactivateService(id);
      loadServices();
    } catch (err) {
      alert('Failed to reactivate service: ' + window._extractError(err));
    }
  } else if (action === 'delete') {
    if (!confirm('Permanently delete this service registration? This cannot be undone.')) return;
    try {
      await API.deleteService(id);
      loadServices();
    } catch (err) {
      alert('Failed to delete service: ' + window._extractError(err));
    }
  }
}

// ─────────────────────────────────────────────
// Feedback helper
// ─────────────────────────────────────────────
function showModalError(elId, msg) {
  const el = $(elId);
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
}

function hideModalError(elId) {
  const el = $(elId);
  if (el) { el.style.display = 'none'; el.textContent = ''; }
}

// ─────────────────────────────────────────────
// Bootstrap
// ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {

  // 1. Auth guard
  const user = await Auth.requireAuth();
  if (!user) return;

  // 2. Background WebGL scene + animations (lazy, CDN-resilient)
  Promise.all([
    import('../scene-profile.js').catch(() => null),
    import('../motion-utils.js').catch(() => null),
  ]).then(([sceneM, motionM]) => {
    if (sceneM) { const c = $('bg-canvas'); if (c) sceneM.initProfileScene(c); }
    if (motionM) { revealPanels = motionM.revealPanels; revealTableRows = motionM.revealTableRows; modalOpen = motionM.modalOpen; motionM.revealPanels('.panel', 0.1); }
  });

  // Topbar user
  $('topbarUser').textContent = user.email || user.username || '';
  if (user.role === 'admin') {
    const navAdmin = $('navAdmin');
    if (navAdmin) navAdmin.style.display = '';
  }

  // 3. Tab switching
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const panel = $('tab-' + btn.dataset.tab);
      if (panel) panel.classList.add('active');

      const isServices = btn.dataset.tab === 'services';
      if ($('newKeyBtn')) $('newKeyBtn').style.display = isServices ? 'none' : '';
      if ($('headerNewServiceBtn')) $('headerNewServiceBtn').style.display = isServices ? '' : 'none';

      // Lazy-load on switch
      if (btn.dataset.tab === 'api-keys') loadApiKeys();
      if (isServices) loadServices();
    });
  });

  // 4. Initial data load (both tabs)
  loadApiKeys();
  loadServices();

  // ──────────────────────────────────────────
  // New API Key modal
  // ──────────────────────────────────────────
  async function openNewKeyModal(preselectedScope) {
    // If invoked from services tab, switch visually to API Keys tab
    document.querySelectorAll('.tab-btn').forEach((b) => {
      const isKeys = b.dataset.tab === 'api-keys';
      b.classList.toggle('active', isKeys);
      b.setAttribute('aria-selected', isKeys ? 'true' : 'false');
    });
    document.querySelectorAll('.tab-panel').forEach((p) => {
      p.classList.toggle('active', p.id === 'tab-api-keys');
    });
    if ($('newKeyBtn')) $('newKeyBtn').style.display = '';
    if ($('headerNewServiceBtn')) $('headerNewServiceBtn').style.display = 'none';

    hideModalError('newKeyFeedback');
    $('newKeyForm').reset();

    if (preselectedScope && preselectedScope.startsWith('proxy:')) {
      const svcName = preselectedScope.replace(/^proxy:/, '');
      $('newKeyName').value = `${svcName}-key`;
    }

    try {
      _services = await API.getServices(true) || [];
    } catch (_) {}

    rebuildScopeCheckboxes(_services, preselectedScope);
    $('newKeyModal').style.display = 'flex';
    $('newKeyName').focus();
  }

  $('newKeyBtn').addEventListener('click', () => openNewKeyModal());

  // Scope selection event listener (interactive toggle between All vs Specific Proxy Scopes)
  const scopesGroup = $('scopesGroup');
  if (scopesGroup) {
    scopesGroup.addEventListener('change', (e) => {
      const scopeAll = $('scopeAll');
      if (!scopeAll) return;

      if (e.target === scopeAll) {
        if (scopeAll.checked) {
          scopesGroup.querySelectorAll('.proxy-scope-cb').forEach((cb) => {
            cb.checked = false;
            cb.closest('.checkbox-item').style.opacity = '0.6';
          });
        } else {
          scopesGroup.querySelectorAll('.proxy-scope-cb').forEach((cb) => {
            cb.closest('.checkbox-item').style.opacity = '1';
          });
        }
      } else if (e.target.classList.contains('proxy-scope-cb')) {
        if (e.target.checked) {
          // A specific proxy scope was chosen -> uncheck "Full access"
          scopeAll.checked = false;
          scopesGroup.querySelectorAll('.proxy-scope-cb').forEach((cb) => {
            cb.closest('.checkbox-item').style.opacity = '1';
          });
        } else {
          // If all proxy checkboxes are unchecked, re-check "Full access"
          const anyChecked = [...scopesGroup.querySelectorAll('.proxy-scope-cb')].some((cb) => cb.checked);
          if (!anyChecked) {
            scopeAll.checked = true;
            scopesGroup.querySelectorAll('.proxy-scope-cb').forEach((cb) => {
              cb.closest('.checkbox-item').style.opacity = '0.6';
            });
          }
        }
      }
    });
  }

  $('closeNewKeyModal').addEventListener('click', () => {
    $('newKeyModal').style.display = 'none';
  });

  // Close on overlay click
  $('newKeyModal').addEventListener('click', (e) => {
    if (e.target === $('newKeyModal')) $('newKeyModal').style.display = 'none';
  });

  $('newKeyForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    hideModalError('newKeyFeedback');

    const name   = $('newKeyName').value.trim();
    const expiry = $('newKeyExpiry').value ? parseInt($('newKeyExpiry').value, 10) : null;
    const scopes = collectScopes();

    if (!name) {
      showModalError('newKeyFeedback', 'Please enter a name for this key.');
      return;
    }

    const btn = e.target.querySelector('[type=submit]');
    btn.disabled    = true;
    btn.textContent = 'Creating…';

    try {
      const data = await API.createApiKey(name, scopes, expiry);

      // Close modal first, then show reveal
      $('newKeyModal').style.display = 'none';
      $('newKeyForm').reset();

      if (data && data.key) {
        showKeyReveal(data.key);
      }

      // Refresh the keys table
      loadApiKeys();
    } catch (err) {
      showModalError('newKeyFeedback', window._extractError(err, 'Failed to create API key.'));
      btn.disabled    = false;
      btn.textContent = 'Create API Key';
    }
  });

  // ──────────────────────────────────────────
  // Key Reveal modal — copy + done
  // ──────────────────────────────────────────
  $('copyKeyBtn').addEventListener('click', async () => {
    if (!_revealKey) return;
    try {
      await navigator.clipboard.writeText(_revealKey);
      $('copyKeyBtn').textContent = 'Copied!';
    } catch (_) {
      // Fallback: select the text
      const el = $('revealKeyText');
      const range = document.createRange();
      range.selectNodeContents(el);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      $('copyKeyBtn').textContent = 'Select all — Ctrl+C to copy';
    }
  });

  $('doneRevealBtn').addEventListener('click', closeKeyReveal);

  // Close on overlay click (but NOT inside the box — key safety)
  $('keyRevealModal').addEventListener('click', (e) => {
    if (e.target === $('keyRevealModal')) closeKeyReveal();
  });

  // ──────────────────────────────────────────
  // Register Service modal
  // ──────────────────────────────────────────
  const openNewServiceModal = () => {
    hideModalError('newSvcFeedback');
    $('newServiceForm').reset();
    $('newServiceModal').style.display = 'flex';
    $('newSvcName').focus();
  };
  $('newServiceBtn').addEventListener('click', openNewServiceModal);
  if ($('headerNewServiceBtn')) $('headerNewServiceBtn').addEventListener('click', openNewServiceModal);

  $('closeNewServiceModal').addEventListener('click', () => {
    $('newServiceModal').style.display = 'none';
  });

  $('newServiceModal').addEventListener('click', (e) => {
    if (e.target === $('newServiceModal')) $('newServiceModal').style.display = 'none';
  });

  $('newServiceForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    hideModalError('newSvcFeedback');

    const name        = $('newSvcName').value.trim();
    const upstream_url = $('newSvcUrl').value.trim();
    const description  = $('newSvcDesc').value.trim();

    if (!name) {
      showModalError('newSvcFeedback', 'Service name is required.');
      return;
    }
    if (!upstream_url) {
      showModalError('newSvcFeedback', 'Upstream URL is required.');
      return;
    }
    if (!/^https?:\/\//i.test(upstream_url)) {
      showModalError('newSvcFeedback', 'Upstream URL must start with http:// or https://');
      return;
    }

    const btn = e.target.querySelector('[type=submit]');
    btn.disabled    = true;
    btn.textContent = 'Registering…';

    try {
      await API.createService({ name, upstream_url, description: description || undefined });

      $('newServiceModal').style.display = 'none';
      $('newServiceForm').reset();

      // Reload both — new service may appear in scope checkboxes
      await loadServices();
      rebuildScopeCheckboxes(_services);
    } catch (err) {
      showModalError('newSvcFeedback', window._extractError(err, 'Failed to register service.'));
      btn.disabled    = false;
      btn.textContent = 'Register Service';
    }
  });

  // ──────────────────────────────────────────
  // Logout is wired via inline onclick="Auth.logout()" in topbar
  // ──────────────────────────────────────────

  // Global keyboard: Esc closes any open modal
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if ($('keyRevealModal').style.display !== 'none') { closeKeyReveal(); return; }
    if ($('newKeyModal').style.display !== 'none')    { $('newKeyModal').style.display = 'none'; return; }
    if ($('newServiceModal').style.display !== 'none') { $('newServiceModal').style.display = 'none'; }
  });

}); // end DOMContentLoaded
