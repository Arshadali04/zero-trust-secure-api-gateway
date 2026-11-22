/**
 * dashboard.js — Security Operations Console v2
 * Powers: 8 KPI cards, risk sparkline, live threat feed (SSE polling),
 *         threat breakdown donut chart, proxy tester, burst test.
 *
 * Loaded as <script type="module"> after api.js and auth.js.
 * Requires: window.Auth, window.API
 */

// Scene + animation loaded dynamically so a CDN failure never breaks page logic.
let initDashboardScene = () => {};
let revealPanels = () => {};
let countUp = () => {};
let fillEnergyMeter = () => {};
let fadeUp = () => {};

// ── Risk Score History (sparkline buffer) ────────────────────────────────────
const _riskHistory = [];
const _SPARK_MAX = 20;      // number of readings to keep
const _SPARK_POLL_MS = 4000; // polling interval

// ── Threat Feed State ─────────────────────────────────────────────────────────
let _lastFeedEventId = 0;
const _MAX_FEED_ITEMS = 30;
let _feedConnected = false;

// ── Helpers ──────────────────────────────────────────────────────────────────

function decodeJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
    return JSON.parse(atob(padded));
  } catch (_) { return null; }
}

function formatExpiry(exp) {
  const d = new Date(exp * 1000);
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function timeAgo(isoString) {
  if (!isoString) return '';
  const diff = (Date.now() - new Date(isoString).getTime()) / 1000;
  if (diff < 5)  return 'just now';
  if (diff < 60) return Math.floor(diff) + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  return Math.floor(diff / 3600) + 'h ago';
}

function threatClass(type) {
  const known = [
    'sql_injection','xss','path_traversal','command_injection',
    'ssrf','xxe','ldap_injection','prototype_pollution',
    'failed_login','ml_anomaly','high_risk_request',
    'impossible_travel','rapid_ip_change',
  ];
  return known.includes(type) ? 'tt-' + type : 'tt-default';
}

function threatLabel(type) {
  const labels = {
    sql_injection: 'SQLi', xss: 'XSS', path_traversal: 'Path Trav.',
    command_injection: 'CMDi', ssrf: 'SSRF', xxe: 'XXE',
    ldap_injection: 'LDAP', prototype_pollution: 'Proto Pollut.',
    failed_login: 'Brute-Force', ml_anomaly: 'ML Anomaly',
    high_risk_request: 'High Risk', impossible_travel: 'Impossible Travel',
    rapid_ip_change: 'IP Change',
  };
  return labels[type] || type.replace(/_/g, ' ');
}

// ── Risk Gauge + KPI Card 1 ───────────────────────────────────────────────────

function renderRisk(score, userObj) {
  const valueEl  = document.getElementById('riskValue');
  const fillEl   = document.getElementById('riskFill');
  const badgeEl  = document.getElementById('riskTierBadge');
  const policyEl = document.getElementById('riskPolicyText');
  const decayEl  = document.getElementById('riskDecayText');
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

  const isAdmin = userObj && userObj.role === 'admin';

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
      policyEl.textContent = isAdmin ? 'Critical Risk (Admin: Unfrozen)' : 'Account Frozen (Sessions Revoked)';
      policyEl.style.color = 'var(--alert)';
    }
  }

  if (decayEl) {
    decayEl.textContent = score > 0.05 ? 'Healing via 4h Exponential Decay' : 'Clean Standing (Baseline)';
  }

  // Buffer for sparkline
  _riskHistory.push(score);
  if (_riskHistory.length > _SPARK_MAX) _riskHistory.shift();
  drawSparkline();

  // Animated count-up
  countUp(valueEl, pct, { suffix: '%', duration: 700 });
}

// ── Sparkline Canvas ──────────────────────────────────────────────────────────

function drawSparkline() {
  const canvas = document.getElementById('riskSparkline');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const data = _riskHistory;
  if (data.length < 2) return;

  const min = 0, max = 1;
  const stepX = W / (data.length - 1);

  // Gradient fill under the line
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, 'rgba(91,140,255,0.35)');
  grad.addColorStop(1, 'rgba(91,140,255,0)');

  ctx.beginPath();
  data.forEach((v, i) => {
    const x = i * stepX;
    const y = H - ((v - min) / (max - min)) * H;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });

  // Close path for fill
  ctx.lineTo((data.length - 1) * stepX, H);
  ctx.lineTo(0, H);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Draw the line on top
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = i * stepX;
    const y = H - ((v - min) / (max - min)) * H;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });

  // Color based on latest value
  const latest = data[data.length - 1];
  const lineColor = latest < 0.3 ? '#2dd4a0' : latest < 0.55 ? '#ffb636' : '#ff5d5d';
  ctx.strokeStyle = lineColor;
  ctx.lineWidth = 1.5;
  ctx.lineJoin = 'round';
  ctx.stroke();

  // Dot at current value
  const lastX = (data.length - 1) * stepX;
  const lastY = H - ((latest - min) / (max - min)) * H;
  ctx.beginPath();
  ctx.arc(lastX, lastY, 2.5, 0, Math.PI * 2);
  ctx.fillStyle = lineColor;
  ctx.fill();
}

// ── KPI Cards 2-8 (admin analytics summary) ──────────────────────────────────

async function loadAnalyticsSummary(isAdmin) {
  if (!isAdmin) return;
  try {
    const summary = await API.request('/admin/analytics/summary');
    const kpiThreats = document.getElementById('kpiThreats');
    const kpiWafBlocks = document.getElementById('kpiWafBlocks');
    const kpiBlockedIPs = document.getElementById('kpiBlockedIPs');
    const kpiActiveUsers = document.getElementById('kpiActiveUsers');
    const kpiHighRiskUsers = document.getElementById('kpiHighRiskUsers');
    const kpiAvgRisk = document.getElementById('kpiAvgRisk');
    const kpiTopThreat = document.getElementById('kpiTopThreat');

    if (kpiThreats) { kpiThreats.textContent = summary.threats_24h; countUp(kpiThreats, summary.threats_24h, { duration: 800 }); }
    if (kpiWafBlocks) kpiWafBlocks.textContent = 'WAF blocks: ' + summary.waf_blocks_24h;
    if (kpiBlockedIPs) { kpiBlockedIPs.textContent = summary.blocked_ips; countUp(kpiBlockedIPs, summary.blocked_ips, { duration: 800 }); }
    if (kpiActiveUsers) { kpiActiveUsers.textContent = summary.active_users; countUp(kpiActiveUsers, summary.active_users, { duration: 800 }); }
    if (kpiHighRiskUsers) kpiHighRiskUsers.textContent = 'High-risk: ' + summary.high_risk_users;
    if (kpiAvgRisk) {
      const pct = Math.round(summary.avg_risk_score * 100);
      kpiAvgRisk.textContent = pct + '%';
    }
    if (kpiTopThreat && summary.top_threat_type) {
      kpiTopThreat.textContent = 'Top: ' + threatLabel(summary.top_threat_type);
    }
  } catch (_) {
    // Non-admin users: show placeholder values
    ['kpiThreats','kpiBlockedIPs','kpiActiveUsers','kpiAvgRisk'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '—';
    });
  }
}

// ── Threat Breakdown Donut Chart ─────────────────────────────────────────────

async function loadThreatBreakdown(isAdmin) {
  if (!isAdmin) {
    document.getElementById('donutLegend').innerHTML = '<div class="text-dim" style="font-size:0.75rem">Admin only</div>';
    return;
  }
  try {
    const data = await API.request('/admin/analytics/threat-breakdown?hours=24');
    if (!data || data.length === 0) {
      document.getElementById('donutLegend').innerHTML = '<div class="text-dim" style="font-size:0.75rem">No threats detected in last 24h</div>';
      drawDonut([], []);
      return;
    }
    const total = data.reduce((s, d) => s + d.count, 0);
    drawDonut(data.map(d => d.count), data.map(d => d.color));

    const legend = document.getElementById('donutLegend');
    legend.innerHTML = '';
    data.slice(0, 6).forEach(d => {
      const row = document.createElement('div');
      row.className = 'legend-row';
      row.innerHTML = `
        <span class="legend-dot" style="background:${d.color}"></span>
        <span class="legend-label">${d.label}</span>
        <span class="legend-count">${d.count}</span>
      `;
      legend.appendChild(row);
    });
    if (total > 0) {
      const totalRow = document.createElement('div');
      totalRow.className = 'legend-row';
      totalRow.style.borderTop = '1px solid var(--glass-border)';
      totalRow.style.marginTop = '4px';
      totalRow.style.paddingTop = '4px';
      totalRow.innerHTML = `<span class="legend-label" style="font-weight:600">Total</span><span class="legend-count">${total}</span>`;
      legend.appendChild(totalRow);
    }
  } catch (_) {
    document.getElementById('donutLegend').innerHTML = '<div class="text-dim" style="font-size:0.75rem">Data unavailable</div>';
  }
}

function drawDonut(values, colors) {
  const canvas = document.getElementById('donutCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2, r = 48, inner = 28;
  ctx.clearRect(0, 0, W, H);

  const total = values.reduce((s, v) => s + v, 0);
  if (total === 0) {
    // Draw empty ring
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.arc(cx, cy, inner, 0, Math.PI * 2, true);
    ctx.fillStyle = 'rgba(255,255,255,0.05)';
    ctx.fill();
    return;
  }

  let startAngle = -Math.PI / 2;
  values.forEach((v, i) => {
    const sweep = (v / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, startAngle, startAngle + sweep);
    ctx.closePath();
    ctx.fillStyle = colors[i] || '#8899aa';
    ctx.fill();
    startAngle += sweep;
  });

  // Donut hole
  ctx.beginPath();
  ctx.arc(cx, cy, inner, 0, Math.PI * 2);
  ctx.fillStyle = 'var(--bg2, #0f1620)';
  ctx.fill();

  // Center label
  ctx.fillStyle = 'rgba(240,244,255,0.7)';
  ctx.font = '700 14px JetBrains Mono, monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(total, cx, cy);
}

// ── User Risk Distribution ────────────────────────────────────────────────────

async function loadUserRiskDist(isAdmin) {
  if (!isAdmin) return;
  try {
    const dist = await API.request('/admin/analytics/user-risk-dist');
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('distLow', dist.low);
    set('distMed', dist.medium);
    set('distHigh', dist.high);
    set('distCrit', dist.critical);
  } catch (_) {}
}

// ── Live Threat Feed (polling-based, SSE-compatible) ─────────────────────────

function buildFeedItem(ev) {
  const div = document.createElement('div');
  div.className = 'threat-feed-item';
  div.setAttribute('data-id', ev.id);

  const riskColor = ev.risk_score < 0.4 ? 'var(--success)' : ev.risk_score < 0.8 ? 'var(--warning)' : 'var(--alert)';

  div.innerHTML = `
    <span class="threat-type-badge ${threatClass(ev.threat_type)}">${threatLabel(ev.threat_type)}</span>
    <div>
      <div class="feed-ip">${ev.ip_address || 'unknown'}</div>
      <div class="feed-ep">${ev.endpoint || '/'}</div>
    </div>
    <span class="feed-risk" style="color:${riskColor}">${Math.round((ev.risk_score || 0) * 100)}%</span>
    <span class="feed-time">${timeAgo(ev.timestamp)}</span>
  `;
  return div;
}

async function pollThreatFeed() {
  try {
    // Fetch latest events since our last known ID
    const url = '/events/security-feed-poll?since=' + _lastFeedEventId + '&limit=10';
    const data = await API.request(url);
    if (data && Array.isArray(data) && data.length > 0) {
      addFeedItems(data);
    }
  } catch (_) {
    // Fall back to fetching recent security events via admin endpoint
    await fallbackFeedPoll();
  }
}

async function fallbackFeedPoll() {
  try {
    // Use the admin security events endpoint if available
    const data = await API.request('/admin/security-events?limit=5&skip=0');
    if (data && Array.isArray(data) && data.length > 0) {
      // Only show items newer than what we last saw
      const newItems = data.filter(ev => ev.id > _lastFeedEventId);
      if (newItems.length > 0) {
        addFeedItems(newItems.reverse()); // chronological order
      }
    }
  } catch (_) {}
}

function addFeedItems(items) {
  const list = document.getElementById('threatFeedList');
  const empty = document.getElementById('feedEmpty');
  if (!list) return;

  if (empty) empty.style.display = 'none';

  items.forEach(ev => {
    if (ev.id > _lastFeedEventId) _lastFeedEventId = ev.id;
    const item = buildFeedItem(ev);
    // Prepend — newest at top
    if (list.firstChild && list.firstChild.classList && list.firstChild.classList.contains('threat-feed-item')) {
      list.insertBefore(item, list.firstChild);
    } else {
      list.appendChild(item);
    }
  });

  // Trim overflow
  const allItems = list.querySelectorAll('.threat-feed-item');
  if (allItems.length > _MAX_FEED_ITEMS) {
    for (let i = _MAX_FEED_ITEMS; i < allItems.length; i++) {
      allItems[i].remove();
    }
  }

  const status = document.getElementById('feedStatus');
  if (status) {
    status.textContent = 'Last update: ' + new Date().toLocaleTimeString();
  }
}

// Initialize threat feed with a direct DB poll for initial items
async function initThreatFeed() {
  const empty = document.getElementById('feedEmpty');

  // Try to get recent security events to pre-populate the feed
  try {
    const data = await API.request('/admin/security-events?limit=10&skip=0');
    if (data && Array.isArray(data) && data.length > 0) {
      // Show in chronological order (oldest first so newest appears at top after prepend)
      const sorted = [...data].reverse();
      addFeedItems(sorted);
    } else {
      if (empty) {
        empty.innerHTML = '<div class="feed-empty-icon">🛡️</div><div>No security events yet. Try triggering an attack in the proxy tester above.</div>';
      }
    }
  } catch (_) {
    if (empty) {
      empty.innerHTML = '<div class="feed-empty-icon">🔒</div><div>Threat feed requires admin access or elevated permissions.</div>';
    }
  }

  // Start periodic polling
  setInterval(pollThreatFeed, 2500);
}

// ── User data polling ─────────────────────────────────────────────────────────

function applyUserData(u) {
  if (!u) return;

  const rawScore = typeof u.risk_score === 'number' ? u.risk_score : null;
  renderRisk(rawScore, u);

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
  if (stepUpRow) stepUpRow.style.display = u.stepup_required ? '' : 'none';

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
    sessionInfo.textContent = 'User: ' + (u.email || '—') + '  ·  Role: ' + (u.role || 'user');
  }

  const sessionUserEl = document.getElementById('sessionUser');
  if (sessionUserEl) sessionUserEl.textContent = u.email || u.username || '—';
}

// ── Proxy inspection bar ─────────────────────────────────────────────────────

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

// ── Boot ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {

  // 1. Auth guard
  const user = await Auth.requireAuth();
  if (!user) return;

  const isAdmin = user.role === 'admin';

  // 2. Admin link
  if (isAdmin) {
    const wrap = document.getElementById('adminLinkWrap');
    if (wrap) wrap.style.display = '';
  }

  // 3. Topbar username
  const topbarUser = document.getElementById('topbarUser');
  if (topbarUser) topbarUser.textContent = user.username || user.email || 'user';

  // 4. 3D scene + stagger animations
  Promise.all([
    import('../scene-dashboard.js').catch(() => null),
    import('../motion-utils.js').catch(() => null),
  ]).then(([sceneM, motionM]) => {
    if (sceneM) {
      initDashboardScene = sceneM.initDashboardScene;
      const c = document.getElementById('bg-canvas');
      if (c) sceneM.initDashboardScene(c);
    }
    if (motionM) {
      revealPanels = motionM.revealPanels;
      countUp = motionM.countUp;
      fillEnergyMeter = motionM.fillEnergyMeter;
      fadeUp = motionM.fadeUp;
      motionM.revealPanels('.kpi-card', 0.06);
      motionM.revealPanels('.panel:not(.kpi-card)', 0.3);
    }
  });

  // 5. Session expiry from JWT
  const token = Auth.getToken();
  const payload = token ? decodeJwt(token) : null;
  const sessionExpiryEl = document.getElementById('sessionExpiry');
  if (sessionExpiryEl && payload && payload.exp) {
    sessionExpiryEl.textContent = 'Expires at ' + formatExpiry(payload.exp);
  }

  // 6. Apply initial user data
  applyUserData(user);

  // 7. Health check
  try {
    const health = await API.getHealth();
    const ok = health && health.status === 'healthy';
    const healthStatus = document.getElementById('healthStatus');
    const healthBadge  = document.getElementById('healthBadge');
    const healthDetail = document.getElementById('healthDetail');
    if (healthStatus) { healthStatus.textContent = ok ? 'Healthy' : (health && health.status ? health.status : 'Unknown'); healthStatus.style.color = ok ? 'var(--success)' : 'var(--warning)'; }
    if (healthBadge)  { healthBadge.textContent = ok ? 'Operational' : 'Degraded'; healthBadge.className = ok ? 'badge badge-ok' : 'badge badge-warn'; }
    if (healthDetail) { healthDetail.textContent = ok ? 'All systems operational' : 'Some services degraded'; }
  } catch (_) {
    const healthStatus = document.getElementById('healthStatus');
    const healthBadge  = document.getElementById('healthBadge');
    const healthDetail = document.getElementById('healthDetail');
    if (healthStatus) { healthStatus.textContent = 'Offline'; healthStatus.style.color = 'var(--alert)'; }
    if (healthBadge)  { healthBadge.textContent = 'Offline'; healthBadge.className = 'badge badge-alert'; }
    if (healthDetail) { healthDetail.textContent = 'Cannot reach backend'; }
  }

  // 8. Load analytics summary (admin KPI cards + donut)
  await Promise.all([
    loadAnalyticsSummary(isAdmin),
    loadThreatBreakdown(isAdmin),
    loadUserRiskDist(isAdmin),
  ]);

  // 9. Initialize live threat feed
  await initThreatFeed();

  // 10. Auto-refresh user risk score & analytics periodically
  async function refreshUserData() {
    try {
      const updated = await API.getMe();
      if (updated) applyUserData(updated);
    } catch (_) {}
  }

  const pollInterval = setInterval(() => {
    if (!document.hidden) {
      refreshUserData();
      if (isAdmin) {
        loadAnalyticsSummary(true).catch(() => {});
      }
    }
  }, _SPARK_POLL_MS);

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) refreshUserData();
  });

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
        // Refresh data after any request — attack may have elevated risk
        setTimeout(() => {
          refreshUserData();
          if (isAdmin) pollThreatFeed();
        }, 300);
      }
    });
  }

  // 12. Traffic Burst button
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
        } catch (_) {
          blockedCount++;
        }
        await new Promise(r => setTimeout(r, 20));
      }

      updateInspectionBar(API.lastSecurityHeaders);
      proxyResult.style.color = 'var(--success)';
      proxyResult.textContent = `✅ Traffic burst complete!\n- Sent: ${total} requests\n- Processed: ${okCount}\n- Throttled/Blocked: ${blockedCount}\n\nBehavioral velocity engine evaluated traffic spike. Syncing Account Risk Score...`;

      await refreshUserData();
      if (isAdmin) {
        await Promise.all([loadAnalyticsSummary(true), pollThreatFeed()]);
      }
      burstRiskBtn.disabled = false;
      proxyBtn.disabled = false;
    });
  }

  // 13. Logout button
  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) logoutBtn.addEventListener('click', () => Auth.logout());

});
