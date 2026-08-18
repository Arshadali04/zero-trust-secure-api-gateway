/**
 * js/pages/attacklab.js
 * Attack Lab page controller — WebSocket live feed + Three.js scene integration.
 *
 * Requires: window.Auth (auth.js), window.API (api.js)
 * Loaded as <script type="module"> after api.js and auth.js.
 */

// Scene + animation loaded dynamically so a CDN failure never breaks page logic.
let initAttackScene = () => null;
let slideIn = () => {};
let fadeUp = () => {};
let revealPanels = () => {};

// ─── Constants ────────────────────────────────────────────────────────────────

/** Threat types classified as outright blocked (vs. flagged/warned). */
const BLOCKED_THREAT_TYPES = new Set([
  'sql_injection',
  'xss',
  'path_traversal',
  'command_injection',
  'impossible_travel',
  'account_frozen',
]);

/** Maximum events kept in the DOM log. */
const MAX_LOG_ITEMS = 50;

// ─── Module state ─────────────────────────────────────────────────────────────

/** Reference to the Three.js attack scene (or null if WebGL unavailable). */
let labScene = null;

/** Whether the previous WS message reported running=true. */
let prevRunning = false;

/** How many events from data.events have already been rendered. */
let lastEventCount = 0;

/** Duration (seconds) of the most recently started attack, for progress bar. */
let requestedDuration = 10;

/** WebSocket instance. */
let ws = null;

/** Pending reconnect timer id. */
let reconnectTimer = null;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Escape a string for safe insertion into innerHTML.
 * @param {*} v
 * @returns {string}
 */
function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * document.getElementById shorthand.
 * @param {string} id
 * @returns {HTMLElement|null}
 */
function $id(id) {
  return document.getElementById(id);
}

// ─── User rendering ───────────────────────────────────────────────────────────

/**
 * Populate the topbar user chip and conditionally reveal the Admin nav link.
 * @param {object} user
 */
function renderUser(user) {
  if (!user) return;

  const userEl = $id('topbarUser');
  if (userEl) {
    userEl.textContent = user.username || user.email || '';
    userEl.setAttribute('aria-label', `Logged in as ${userEl.textContent}`);
  }

  if (user.role === 'admin') {
    const adminLink = $id('adminNavLink');
    if (adminLink) adminLink.style.display = '';
  }
}

// ─── WebSocket status badge ───────────────────────────────────────────────────

/**
 * Update the WebSocket connection status badge.
 * @param {'ok'|'error'|'disconnected'} state
 */
function setWsStatus(state) {
  const el = $id('wsStatus');
  if (!el) return;

  if (state === 'ok') {
    el.className = 'badge badge-ok';
    el.textContent = 'Connected';
  } else if (state === 'error') {
    el.className = 'badge badge-alert';
    el.textContent = 'Error';
  } else {
    el.className = 'badge badge-dim';
    el.textContent = 'Disconnected';
  }
}

// ─── Event log ────────────────────────────────────────────────────────────────

/**
 * Resolve an event's visual classification from its fields.
 * @param {object} ev  event object from WS state
 * @returns {'blocked'|'allowed'|'flagged'}
 */
function classifyEvent(ev) {
  if (ev.status === 'allowed') return 'allowed';
  if (ev.status === 'blocked') return 'blocked';
  if (BLOCKED_THREAT_TYPES.has(ev.threat_type)) return 'blocked';
  if (ev.threat_type) return 'flagged';
  return 'allowed';
}

/**
 * Prepend a single event to the DOM event log.
 * Keeps the log capped at MAX_LOG_ITEMS entries.
 * @param {object} ev
 */
function addEventItem(ev) {
  const log = $id('eventLog');
  if (!log) return;

  // Remove the empty-state placeholder on first event
  const empty = log.querySelector('.empty-state');
  if (empty) empty.remove();

  const cls    = classifyEvent(ev);
  const badgeCls = cls === 'blocked' ? 'badge-alert'
    : cls === 'allowed'              ? 'badge-ok'
    :                                  'badge-warn';
  const label  = cls.toUpperCase();

  // Format timestamp — prefer the event's own `time` field
  const rawTime = ev.time || ev.timestamp || '';
  let timeStr;
  if (rawTime) {
    // If it looks like an epoch number, format it; otherwise use as-is
    const n = Number(rawTime);
    timeStr = !isNaN(n) && n > 1e9
      ? new Date(n * 1000).toLocaleTimeString('en-US', { hour12: false })
      : String(rawTime).slice(0, 12); // already formatted string
  } else {
    timeStr = new Date().toLocaleTimeString('en-US', {
      hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  }

  const typeLabel = esc((ev.threat_type || 'event').replace(/_/g, ' '));
  const detail    = esc(String(ev.detail || '').slice(0, 80));

  const item = document.createElement('div');
  item.className = `event-item ${cls}`;
  item.innerHTML =
    `<span class="event-time">${esc(timeStr)}</span>` +
    `<span class="event-type">${typeLabel}</span>` +
    `<span class="event-detail">${detail}</span>` +
    `<span class="badge ${badgeCls}" style="margin-left:auto;flex-shrink:0;">${label}</span>`;

  log.insertBefore(item, log.firstChild);
  slideIn(item); // Motion: slide in from right with spring physics

  // Trim overflow
  while (log.children.length > MAX_LOG_ITEMS) {
    log.removeChild(log.lastChild);
  }
}

// ─── Sparkline ────────────────────────────────────────────────────────────────

/**
 * Draw the risk score history sparkline on #sparklineCanvas.
 * @param {Array<number|{score:number}>} samples
 */
function updateSparkline(samples) {
  const canvas = $id('sparklineCanvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  const w = Math.max(canvas.clientWidth || canvas.offsetWidth || 300, 60);
  const h = 80;

  canvas.width  = w;
  canvas.height = h;
  ctx.clearRect(0, 0, w, h);

  if (!samples || samples.length < 2) return;

  // Normalise samples to plain numbers
  const scores = samples.map(s =>
    (s !== null && typeof s === 'object') ? (s.score ?? 0) : Number(s)
  ).filter(n => !isNaN(n));

  if (scores.length < 2) return;

  const maxV  = Math.max(...scores, 0.01);
  const minV  = Math.min(...scores, 0);
  const range = maxV - minV || 0.01;
  const pad   = 6;
  const n     = scores.length;

  const xs = scores.map((_, i) => pad + (i / (n - 1)) * (w - pad * 2));
  const ys = scores.map(s => h - pad - ((s - minV) / range) * (h - pad * 2));

  // Filled gradient area
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(91,140,255,0.22)');
  grad.addColorStop(1, 'rgba(91,140,255,0)');

  ctx.beginPath();
  ctx.moveTo(xs[0], h);
  ctx.lineTo(xs[0], ys[0]);
  for (let i = 1; i < n; i++) ctx.lineTo(xs[i], ys[i]);
  ctx.lineTo(xs[n - 1], h);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Stroke line
  ctx.beginPath();
  ctx.moveTo(xs[0], ys[0]);
  for (let i = 1; i < n; i++) ctx.lineTo(xs[i], ys[i]);
  ctx.strokeStyle = '#5b8cff';
  ctx.lineWidth   = 2;
  ctx.lineJoin    = 'round';
  ctx.lineCap     = 'round';
  ctx.stroke();

  // Current-value dot with glow halo
  const lx = xs[n - 1];
  const ly = ys[n - 1];

  ctx.beginPath();
  ctx.arc(lx, ly, 7, 0, Math.PI * 2);
  ctx.strokeStyle = 'rgba(91,140,255,0.28)';
  ctx.lineWidth   = 3;
  ctx.stroke();

  ctx.beginPath();
  ctx.arc(lx, ly, 3.5, 0, Math.PI * 2);
  ctx.fillStyle = '#5b8cff';
  ctx.fill();
}

// ─── Risk gauge ───────────────────────────────────────────────────────────────

/**
 * Update the risk level bar and label.
 * @param {number} score  0-1
 */
function updateRiskGauge(score) {
  const fill = $id('riskFill');
  const val  = $id('riskVal');
  if (!fill || !val) return;

  const pct = Math.min(100, score * 100);
  fill.style.width = pct + '%';
  val.textContent  = score.toFixed(2);

  const cls = score > 0.65 ? 'risk-high' : score > 0.35 ? 'risk-med' : 'risk-low';
  fill.className = 'risk-bar-fill ' + cls;
  val.className  = 'risk-value '    + cls;

  // Sync ARIA
  const gauge = fill.closest('[role="meter"]');
  if (gauge) gauge.setAttribute('aria-valuenow', score.toFixed(2));
}

// ─── State update ─────────────────────────────────────────────────────────────

/**
 * Apply a full lab-state snapshot from either the REST seed call or a WS message.
 * @param {object} data  {running, attack_type, elapsed, total, blocked, allowed, errors, risk_samples, events}
 */
function updateLabState(data) {
  if (!data) return;

  const running = !!data.running;
  const total   = data.total   || 0;
  const blocked = data.blocked || 0;
  const allowed = data.allowed || 0;

  // ── Counters ──────────────────────────────────────────────────────────────
  $id('totalCount').textContent   = total;
  $id('blockedCount').textContent = blocked;
  $id('allowedCount').textContent = allowed;
  $id('blockRate').textContent    = total > 0
    ? (blocked / total * 100).toFixed(1) + '%'
    : '—'; // em dash

  // ── Status dot + text ─────────────────────────────────────────────────────
  const dot        = $id('labDot');
  const statusText = $id('labStatusText');
  if (dot && statusText) {
    if (running) {
      dot.className         = 'dot dot-alert';
      const typeLabel       = (data.attack_type || '').replace(/_/g, ' ');
      statusText.textContent = typeLabel ? typeLabel + ' running…' : 'Running…';
      statusText.className  = 'text-mono text-alert';
    } else if (total > 0) {
      dot.className          = 'dot dot-ok';
      statusText.textContent = 'Finished';
      statusText.className   = 'text-mono text-success';
    } else {
      dot.className          = 'dot dot-dim';
      statusText.textContent = 'Ready';
      statusText.className   = 'text-mono text-dim';
    }
  }

  // ── Buttons ───────────────────────────────────────────────────────────────
  const runBtn  = $id('runBtn');
  const stopBtn = $id('stopBtn');
  if (runBtn)  runBtn.disabled  = running;
  if (stopBtn) stopBtn.disabled = !running;

  // ── Duration progress bar ─────────────────────────────────────────────────
  const progressWrap = $id('runProgressWrap');
  const progressFill = $id('runProgressFill');
  const elapsedText  = $id('elapsedText');
  if (progressWrap) {
    if (running) {
      progressWrap.style.display = '';
      const elapsed = data.elapsed || 0;
      const dur     = requestedDuration || 10;
      const pct     = Math.min(100, (elapsed / dur) * 100);
      if (progressFill) {
        progressFill.style.width = pct + '%';
        const track = progressFill.parentElement;
        if (track) track.setAttribute('aria-valuenow', Math.round(pct));
      }
      if (elapsedText) elapsedText.textContent = elapsed + 's / ' + dur + 's';
    } else {
      progressWrap.style.display = 'none';
    }
  }

  // ── Risk sparkline + gauge ────────────────────────────────────────────────
  const samples = Array.isArray(data.risk_samples) ? data.risk_samples : [];
  const latestRisk = samples.length > 0
    ? ((s) => typeof s === 'object' && s !== null ? (s.score ?? 0) : Number(s))(samples[samples.length - 1])
    : 0;

  updateRiskGauge(isNaN(latestRisk) ? 0 : latestRisk);
  updateSparkline(samples);

  // ── Three.js scene ────────────────────────────────────────────────────────
  if (labScene) {
    labScene.setRunning(running);
    labScene.setRiskLevel(isNaN(latestRisk) ? 0 : latestRisk);
  }

  // ── Events ────────────────────────────────────────────────────────────────
  if (Array.isArray(data.events)) {
    // New attack just started — clear the log
    if (running && !prevRunning) {
      const log = $id('eventLog');
      if (log) {
        log.innerHTML = '<div class="empty-state" style="padding:16px 0;">Waiting for events…</div>';
      }
      lastEventCount = 0;
    }

    // Only append events we haven't seen yet
    const newEvents = data.events.slice(lastEventCount);
    newEvents.forEach(ev => {
      addEventItem(ev);

      // Drive Three.js particles
      if (labScene) {
        const cls = classifyEvent(ev);
        if (cls === 'blocked' || cls === 'flagged') labScene.spawnBlock();
        else                                         labScene.spawnAllow();
      }
    });
    lastEventCount = data.events.length;
  }

  prevRunning = running;
}

// ─── Slider labels ────────────────────────────────────────────────────────────

function bindSliders() {
  const durSlider = $id('durationSlider');
  const intSlider = $id('intensitySlider');

  if (durSlider) {
    durSlider.addEventListener('input', () => {
      const val = durSlider.value;
      const lbl = $id('durVal');
      if (lbl) lbl.textContent = val + 's';
    });
  }

  if (intSlider) {
    intSlider.addEventListener('input', () => {
      const val = intSlider.value;
      const lbl = $id('intVal');
      if (lbl) lbl.textContent = val;
    });
  }
}

// ─── Run / Stop buttons ───────────────────────────────────────────────────────

function bindButtons() {
  const runBtn  = $id('runBtn');
  const stopBtn = $id('stopBtn');

  if (runBtn) {
    runBtn.addEventListener('click', async () => {
      const type     = $id('attackType').value;
      const duration = parseInt($id('durationSlider').value, 10);
      const intensity = parseInt($id('intensitySlider').value, 10);

      // Store requested duration for progress bar
      requestedDuration = duration;

      runBtn.disabled = true;
      try {
        await API.runAttack(type, duration, intensity);
        if (stopBtn) stopBtn.disabled = false;
      } catch (e) {
        // Re-enable the button so the user can try again
        runBtn.disabled = false;
        console.error('[AttackLab] runAttack failed:', e);
      }
    });
  }

  if (stopBtn) {
    stopBtn.addEventListener('click', async () => {
      stopBtn.disabled = true;
      try {
        await API.stopAttack();
      } catch (e) {
        stopBtn.disabled = false;
        console.error('[AttackLab] stopAttack failed:', e);
      }
    });
  }
}

// ─── WebSocket ────────────────────────────────────────────────────────────────

/**
 * Open the WebSocket connection and wire up message/error/close handlers.
 * Automatically reconnects after 3 seconds on close.
 */
function connectWS() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }

  const wsBase = window.location.origin.replace(/^https?/, proto =>
    proto === 'https' ? 'wss' : 'ws'
  );

  try {
    ws = new WebSocket(wsBase + '/ws/attack-lab');
  } catch (e) {
    setWsStatus('error');
    reconnectTimer = setTimeout(connectWS, 3000);
    return;
  }

  ws.onopen = () => {
    setWsStatus('ok');
  };

  ws.onmessage = (ev) => {
    try {
      updateLabState(JSON.parse(ev.data));
    } catch (parseErr) {
      console.warn('[AttackLab] Unparseable WS message:', parseErr);
    }
  };

  ws.onerror = () => {
    setWsStatus('error');
  };

  ws.onclose = () => {
    setWsStatus('disconnected');
    reconnectTimer = setTimeout(connectWS, 3000);
  };
}

// ─── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  // 1. Auth guard — redirects to login.html if unauthenticated
  const user = await Auth.requireAuth();
  if (!user) return;

  // 2. Populate topbar user chip + show admin link if applicable
  renderUser(user);

  // 3. Wire up sliders and buttons
  bindSliders();
  bindButtons();

  // 4. Initialise the Three.js attack scene + animations (lazy, CDN-resilient)
  Promise.all([
    import('../scene-attacklab.js').catch(() => null),
    import('../motion-utils.js').catch(() => null),
  ]).then(([sceneM, motionM]) => {
    if (sceneM) { initAttackScene = sceneM.initAttackScene; labScene = sceneM.initAttackScene($id('bg-canvas')); }
    if (motionM) { slideIn = motionM.slideIn; fadeUp = motionM.fadeUp; revealPanels = motionM.revealPanels; motionM.revealPanels('.panel', 0.1); }
  });

  // 5. Seed initial state from REST so the page has data before the WS connects
  try {
    const state = await API.getAttackState();
    updateLabState(state);
  } catch (e) {
    // Non-fatal — WS will populate data shortly
    console.warn('[AttackLab] Could not fetch initial state:', e);
  }

  // 6. Open the live WebSocket feed
  connectWS();
});
