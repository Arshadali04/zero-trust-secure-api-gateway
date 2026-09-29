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
 * Set the risk gauge + color + tier badge based on a 0-1 score.
 * @param {number|null} score
 */
function renderRisk(score, userObj) {
  const valueEl     = document.getElementById('riskValue');
  const fillEl      = document.getElementById('riskFill');
  const badgeEl     = document.getElementById('riskTierBadge');
  const policyEl    = document.getElementById('riskPolicyText');
  const decayTextEl = document.getElementById('riskDecayText');
  if (!valueEl || !fillEl) return;

  if (score === null || score === undefined || isNaN(score)) {
    valueEl.textContent = 'N/A';
    valueEl.style.color = 'var(--dim)';
    fillEl.style.width = '0%';
    fillEl.className = 'risk-bar-fill risk-low';
    if (badgeEl) { badgeEl.textContent = 'UNKNOWN'; badgeEl.className = 'badge badge-dim'; }
    return;
  }

  const pct = Math.round(Math.min(100, Math.max(0, score * 100)));
  valueEl.textContent = pct + '%';
  fillEl.style.width = pct + '%';

  const isAdmin = (userObj && userObj.role === 'admin') || (window.Auth && window.Auth.getCurrentUser && window.Auth.getCurrentUser()?.role === 'admin');

  if (score < 0.3) {
    valueEl.style.color = 'var(--success)';
    fillEl.className = 'risk-bar-fill risk-low';
    if (badgeEl) { badgeEl.textContent = 'LOW'; badgeEl.className = 'badge badge-ok'; }
    if (policyEl) { policyEl.textContent = 'Standard Access (Allow)'; policyEl.style.color = 'var(--success)'; }
  } else if (score < 0.55) {
    valueEl.style.color = 'var(--warning)';
    fillEl.className = 'risk-bar-fill risk-med';
    if (badgeEl) { badgeEl.textContent = 'MEDIUM'; badgeEl.className = 'badge badge-warn'; }
    if (policyEl) { policyEl.textContent = 'Monitored Traffic (Elevated)'; policyEl.style.color = 'var(--warning)'; }
  } else if (score < 0.85) {
    valueEl.style.color = 'var(--alert)';
    fillEl.className = 'risk-bar-fill risk-high';
    if (badgeEl) { badgeEl.textContent = 'HIGH'; badgeEl.className = 'badge badge-alert'; }
    if (policyEl) { policyEl.textContent = 'Step-Up Required (Sensitive Gated)'; policyEl.style.color = 'var(--alert)'; }
  } else {
    valueEl.style.color = 'var(--alert)';
    fillEl.className = 'risk-bar-fill risk-high';
    if (badgeEl) { badgeEl.textContent = 'CRITICAL'; badgeEl.className = 'badge badge-alert'; }
    if (policyEl) {
      policyEl.textContent = isAdmin
        ? 'Critical Risk (Admin Protection: Unfrozen)'
        : 'Account Frozen (Sessions Revoked)';
      policyEl.style.color = 'var(--alert)';
    }
  }

  if (decayTextEl) {
    decayTextEl.textContent = score > 0.05 ? 'Healing via 4h Exponential Decay' : 'Clean Standing (Baseline)';
  }

  // Animated count-up for the percentage value
  countUp(valueEl, pct, { suffix: '%', duration: 700 });

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

  function applyUserData(u) {
    if (!u) return;

    // Risk score
    const rawScore = typeof u.risk_score === 'number' ? u.risk_score : null;
    renderRisk(rawScore, u);

    // Account status
    const mfaDot  = document.getElementById('mfaStatusDot');
    const mfaText = document.getElementById('mfaStatusText');
    if (mfaDot && mfaText) {
      if (u.mfa_enabled) {
        mfaDot.className = 'dot dot-ok';
        mfaText.textContent = 'MFA: Enabled';
      } else {
        mfaDot.className = 'dot dot-warn';
        mfaText.textContent = 'MFA: Disabled';
      }
    }
    const stepUpRow = document.getElementById('stepUpRow');
    if (stepUpRow) {
      stepUpRow.style.display = u.stepup_required ? '' : 'none';
    }
    const frozenRow = document.getElementById('frozenRow');
    if (frozenRow) {
      let isFrozen = false;
      if (u.account_frozen_until) {
        let ts = String(u.account_frozen_until).trim();
        if (!ts.endsWith('Z') && !/[+-]\d{2}:?\d{2}$/.test(ts)) ts += 'Z';
        isFrozen = new Date(ts) > new Date();
      }
      frozenRow.style.display = isFrozen ? '' : 'none';
    }

    const sessionInfo = document.getElementById('sessionInfo');
    if (sessionInfo) {
      sessionInfo.textContent = 'User: ' + (u.email || '—') + '  |  Role: ' + (u.role || 'user');
    }
  }

  // Initial apply from login session
  applyUserData(user);

  // Auto-refresh user risk score & status periodically and on tab focus
  async function refreshUserData() {
    try {
      const updated = await API.getMe();
      if (updated) applyUserData(updated);
    } catch (_) {}
  }

  const pollInterval = setInterval(() => {
    if (!document.hidden) refreshUserData();
  }, 4000);

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) refreshUserData();
  });

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

  // ── Gateway inspection helper ──────────────────────────────────────────
  function updateInspectionBar(secHeaders) {
    const bar = document.getElementById('proxyInspectionBar');
    if (!bar) return;
    bar.style.display = '';

    const scoreEl  = document.getElementById('inspectScore');
    const actionEl = document.getElementById('inspectAction');
    const wafEl    = document.getElementById('inspectWaf');
    const rateEl   = document.getElementById('inspectRate');

    const rawScore = (secHeaders && secHeaders.riskScore != null)
      ? parseFloat(secHeaders.riskScore)
      : ((secHeaders && secHeaders.wafRiskScore != null) ? parseFloat(secHeaders.wafRiskScore) : 0.015);
    const scorePct = Math.round(rawScore * 100);
    const action   = (secHeaders && secHeaders.riskAction) ? String(secHeaders.riskAction).toUpperCase() : 'ALLOW';
    const waf      = (secHeaders && secHeaders.wafBlocked) ? `BLOCKED (${secHeaders.wafBlocked})` : 'CLEAN';
    const rate     = (secHeaders && secHeaders.rateLimitRemaining != null) ? `${secHeaders.rateLimitRemaining} reqs left` : 'Normal window';

    if (scoreEl) {
      scoreEl.textContent = `${scorePct}% (${rawScore.toFixed(3)})`;
      scoreEl.style.color = rawScore < 0.4 ? 'var(--success)' : (rawScore < 0.8 ? 'var(--warning)' : 'var(--alert)');
    }
    if (actionEl) {
      actionEl.textContent = action;
      actionEl.style.color = (action === 'ALLOW') ? 'var(--success)' : (action === 'MONITOR' ? 'var(--warning)' : 'var(--alert)');
    }
    if (wafEl) {
      wafEl.textContent = waf;
      wafEl.style.color = (waf === 'CLEAN') ? 'var(--success)' : 'var(--alert)';
    }
    if (rateEl) {
      rateEl.textContent = rate;
      rateEl.style.color = 'var(--dim)';
    }
  }

  // 11. Proxy test button
  const proxyBtn = document.getElementById('proxyBtn');
  const proxyResult = document.getElementById('proxyResult');
  const proxyEndpointSel = document.getElementById('proxyEndpointSel');

  if (proxyBtn && proxyResult && proxyEndpointSel) {
    proxyBtn.addEventListener('click', async () => {
      proxyBtn.disabled = true;
      proxyBtn.textContent = 'Evaluating...';
      proxyResult.style.color = 'var(--dim)';
      proxyResult.textContent = 'Sending request through Zero Trust Gateway middleware pipeline...';
      try {
        const data = await API.proxyRequest(proxyEndpointSel.value);
        updateInspectionBar(API.lastSecurityHeaders);
        proxyResult.style.color = 'var(--success)';
        proxyResult.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        updateInspectionBar((err && err.headers) || API.lastSecurityHeaders);
        proxyResult.style.color = 'var(--alert)';
        const msg = (err && err.data && err.data.detail)
          ? String(err.data.detail)
          : (err && err.message ? err.message : 'Request failed (status ' + (err && err.status ? err.status : '?') + ')');
        proxyResult.textContent = 'Gateway Intervention [Status ' + (err && err.status ? err.status : '') + ']: ' + msg;
      } finally {
        proxyBtn.disabled = false;
        proxyBtn.textContent = 'Call API';
        setTimeout(() => refreshUserData(), 250);
      }
    });
  }

  // 12. Traffic Burst Risk Test button
  const burstRiskBtn = document.getElementById('burstRiskBtn');
  if (burstRiskBtn && proxyBtn && proxyResult) {
    burstRiskBtn.addEventListener('click', async () => {
      burstRiskBtn.disabled = true;
      proxyBtn.disabled = true;
      proxyResult.style.color = 'var(--dim)';
      proxyResult.textContent = '⚡ Starting rapid traffic burst to test behavioral velocity engine...\n';

      const total = 45;
      let okCount = 0;
      let blockedCount = 0;

      for (let i = 1; i <= total; i++) {
        proxyResult.textContent = `⚡ Firing burst request ${i}/${total} to /api/v1/data/hello...`;
        try {
          await API.proxyRequest('data/hello');
          okCount++;
        } catch (e) {
          blockedCount++;
        }
        await new Promise(r => setTimeout(r, 20));
      }

      updateInspectionBar(API.lastSecurityHeaders);
      proxyResult.style.color = 'var(--success)';
      proxyResult.textContent = `✅ Traffic burst complete!\n- Sent: ${total} requests\n- Processed: ${okCount}\n- Throttled/Blocked: ${blockedCount}\n\nBehavioral velocity engine evaluated traffic spike. Syncing Account Risk Score...`;

      await refreshUserData();
      burstRiskBtn.disabled = false;
      proxyBtn.disabled = false;
    });
  }

  // 12. Logout button
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => Auth.logout());
  }

});
