/**
 * dashboard.js — Security Console page module
 * Loaded as <script type="module"> after api.js and auth.js.
 * Requires: window.Auth, window.API
 */

// Scene + animation loaded dynamically so a CDN failure never breaks page logic.
let initDashboardScene = () => {};
let revealPanels = () => {};
let countUp = () => {};
let fillEnergyMeter = () => {};
let fadeUp = () => {};

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Decode a JWT and return the payload object (no verification).
 * @param {string} token
 * @returns {object|null}
 */
function decodeJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    return JSON.parse(atob(padded));
  } catch (_) {
    return null;
  }
}

/**
 * Format a UNIX timestamp (seconds) as HH:MM:SS (local time).
 * @param {number} exp
 * @returns {string}
 */
function formatExpiry(exp) {
  const d = new Date(exp * 1000);
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/**
 * Set the risk gauge + color based on a 0-1 score.
 * @param {number|null} score
 */
function renderRisk(score) {
  const valueEl = document.getElementById('riskValue');
  const fillEl  = document.getElementById('riskFill');
  if (!valueEl || !fillEl) return;

  if (score === null || score === undefined || isNaN(score)) {
    valueEl.textContent = 'N/A';
    valueEl.style.color = 'var(--dim)';
    fillEl.style.width = '0%';
    fillEl.className = 'risk-bar-fill risk-low';
    return;
  }

  const pct = Math.min(100, Math.max(0, score * 100));
  valueEl.textContent = pct.toFixed(0) + '%';
  fillEl.style.width = pct + '%';

  if (score < 0.3) {
    valueEl.style.color = 'var(--success)';
    fillEl.className = 'risk-bar-fill risk-low';
  } else if (score < 0.7) {
    valueEl.style.color = 'var(--warning)';
    fillEl.className = 'risk-bar-fill risk-med';
  } else {
    valueEl.style.color = 'var(--alert)';
    fillEl.className = 'risk-bar-fill risk-high';
  }

  // Animated count-up for the percentage value
  countUp(valueEl, pct, { suffix: '%', duration: 900 });

  // Energy meter (segmented Tron-style bar) if element exists
  fillEnergyMeter(document.getElementById('riskEnergyMeter'), score);
}

// ── Boot ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {

  // 1. Auth guard — redirects to login.html if unauthenticated
  const user = await Auth.requireAuth();
  if (!user) return;

  // 2. Admin link visibility
  if (user.role === 'admin') {
    const wrap = document.getElementById('adminLinkWrap');
    if (wrap) wrap.style.display = '';
  }

  // 3. Topbar username
  const topbarUser = document.getElementById('topbarUser');
  if (topbarUser) topbarUser.textContent = user.username || user.email || 'user';

  // 4. Init 3D dashboard scene + stagger animations (lazy, CDN-resilient)
  Promise.all([
    import('../scene-dashboard.js').catch(() => null),
    import('../motion-utils.js').catch(() => null),
  ]).then(([sceneM, motionM]) => {
    if (sceneM) { initDashboardScene = sceneM.initDashboardScene; const c = document.getElementById('bg-canvas'); if (c) sceneM.initDashboardScene(c); }
    if (motionM) { revealPanels = motionM.revealPanels; countUp = motionM.countUp; fillEnergyMeter = motionM.fillEnergyMeter; fadeUp = motionM.fadeUp; motionM.revealPanels('.metric-card', 0.1); motionM.revealPanels('.panel:not(.metric-card)', 0.4); }
  });

  // 5. Session expiry from JWT
  const token = Auth.getToken();
  const payload = token ? decodeJwt(token) : null;
  const sessionExpiryEl = document.getElementById('sessionExpiry');
  if (sessionExpiryEl && payload && payload.exp) {
    sessionExpiryEl.textContent = 'Session expires at ' + formatExpiry(payload.exp);
  }

  // 6. Session user display
  const sessionUserEl = document.getElementById('sessionUser');
  if (sessionUserEl) {
    sessionUserEl.textContent = user.email || user.username || 'unknown';
  }

  // 7. Risk score
  const rawScore = typeof user.risk_score === 'number' ? user.risk_score : null;
  renderRisk(rawScore);

  // 8. Account status
  const mfaDot  = document.getElementById('mfaStatusDot');
  const mfaText = document.getElementById('mfaStatusText');
  if (mfaDot && mfaText) {
    if (user.mfa_enabled) {
      mfaDot.className = 'dot dot-ok';
      mfaText.textContent = 'MFA: Enabled';
    } else {
      mfaDot.className = 'dot dot-warn';
      mfaText.textContent = 'MFA: Disabled';
    }
  }
  if (user.stepup_required) {
    const row = document.getElementById('stepUpRow');
    if (row) row.style.display = '';
  }
  if (user.account_frozen_until) {
    const row = document.getElementById('frozenRow');
    if (row) row.style.display = '';
  }

  // 9. Session info line
  const sessionInfo = document.getElementById('sessionInfo');
  if (sessionInfo) {
    sessionInfo.textContent = 'User: ' + (user.email || '—') + '  |  Role: ' + (user.role || 'user');
  }

  // 10. Health check
  try {
    const health = await API.getHealth();
    const ok = health && health.status === 'healthy';
    const healthStatus = document.getElementById('healthStatus');
    const healthBadge  = document.getElementById('healthBadge');
    const healthDetail = document.getElementById('healthDetail');
    if (healthStatus) {
      healthStatus.textContent = ok ? 'Healthy' : (health && health.status ? health.status : 'Unknown');
      healthStatus.style.color = ok ? 'var(--success)' : 'var(--warning)';
    }
    if (healthBadge) {
      healthBadge.textContent = ok ? 'Operational' : 'Degraded';
      healthBadge.className = ok ? 'badge badge-ok' : 'badge badge-warn';
    }
    if (healthDetail) {
      healthDetail.textContent = ok ? 'All systems operational' : 'Some services may be degraded';
    }
  } catch (err) {
    const healthStatus = document.getElementById('healthStatus');
    const healthBadge  = document.getElementById('healthBadge');
    const healthDetail = document.getElementById('healthDetail');
    if (healthStatus) { healthStatus.textContent = 'Offline'; healthStatus.style.color = 'var(--alert)'; }
    if (healthBadge)  { healthBadge.textContent = 'Offline'; healthBadge.className = 'badge badge-alert'; }
    if (healthDetail) { healthDetail.textContent = 'Cannot reach backend'; }
  }

  // 11. Proxy test button
  const proxyBtn = document.getElementById('proxyBtn');
  const proxyResult = document.getElementById('proxyResult');
  const proxyEndpointSel = document.getElementById('proxyEndpointSel');

  if (proxyBtn && proxyResult && proxyEndpointSel) {
    proxyBtn.addEventListener('click', async () => {
      proxyBtn.disabled = true;
      proxyBtn.textContent = 'Calling...';
      proxyResult.style.color = 'var(--dim)';
      proxyResult.textContent = 'Sending request...';
      try {
        const data = await API.proxyRequest(proxyEndpointSel.value);
        proxyResult.style.color = 'var(--success)';
        proxyResult.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        proxyResult.style.color = 'var(--alert)';
        const msg = (err && err.data && err.data.detail)
          ? String(err.data.detail)
          : (err && err.message ? err.message : 'Request failed (status ' + (err && err.status ? err.status : '?') + ')');
        proxyResult.textContent = 'Error ' + (err && err.status ? err.status : '') + ': ' + msg;
      } finally {
        proxyBtn.disabled = false;
        proxyBtn.textContent = 'Call API';
      }
    });
  }

  // 12. Logout button
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => Auth.logout());
  }

});
