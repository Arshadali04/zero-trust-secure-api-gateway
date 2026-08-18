/**
 * motion-utils.js — Animation layer powered by Motion for Web (Framer Motion vanilla).
 * CDN: https://motion.dev  |  pkg: motion@10
 * ES module — import into page JS modules.
 */

import { animate, stagger } from 'https://cdn.jsdelivr.net/npm/motion@10.18.0/dist/motion.mjs';

// ── Easing constants ─────────────────────────────────────────────────────────

/** Spring-like cubic bezier: slight overshoot then settle. */
export const SPRING = [0.34, 1.56, 0.64, 1];

/** Smooth deceleration: no overshoot. */
export const SMOOTH = [0.25, 0.46, 0.45, 0.94];


// ── DOM reveal ───────────────────────────────────────────────────────────────

/**
 * Staggered fade-up reveal for a set of elements.
 * Adds `body.motion-ready` so CSS can hide elements before JS runs.
 *
 * @param {string|Element|Element[]} target - CSS selector or element(s)
 * @param {number} [startDelay=0]           - seconds before first element animates
 */
export function revealPanels(target, startDelay = 0) {
  const els = typeof target === 'string'
    ? Array.from(document.querySelectorAll(target))
    : Array.isArray(target) ? target : [target];

  if (!els.length) return;

  document.body.classList.add('motion-ready');

  animate(
    els,
    { opacity: [0, 1], y: [28, 0] },
    {
      duration: 0.45,
      easing: SPRING,
      delay: stagger(0.07, { start: startDelay }),
    }
  );
}

/**
 * Fade-up a single element.
 *
 * @param {HTMLElement|null} el
 * @param {number} [delay=0]
 */
export function fadeUp(el, delay = 0) {
  if (!el) return;
  animate(el, { opacity: [0, 1], y: [22, 0] }, { duration: 0.4, easing: SPRING, delay });
}

/**
 * Slide an element in from one side — used for streaming list entries.
 *
 * @param {HTMLElement|null} el
 * @param {'right'|'left'} [from='right']
 */
export function slideIn(el, from = 'right') {
  if (!el) return;
  const dx = from === 'right' ? 18 : -18;
  animate(el, { opacity: [0, 1], x: [dx, 0] }, { duration: 0.22, easing: SPRING });
}

/**
 * Scale-spring open for modals and dialogs.
 *
 * @param {HTMLElement|null} el
 */
export function modalOpen(el) {
  if (!el) return;
  animate(el, { opacity: [0, 1], scale: [0.93, 1] }, { duration: 0.25, easing: SPRING });
}

/**
 * Pulse an outward glow ring from an element (unlock / success feedback).
 *
 * @param {HTMLElement|null} el
 * @param {string} [color]
 */
export function pulseGlow(el, color = 'rgba(91,140,255,0.5)') {
  if (!el) return;
  const none = color.replace(/[\d.]+\)$/, '0)');
  animate(
    el,
    { boxShadow: [`0 0 0 0 ${color}`, `0 0 0 18px ${none}`] },
    { duration: 0.55, easing: 'ease-out' }
  );
}


// ── Number animation ─────────────────────────────────────────────────────────

/**
 * Animate a number counting up inside an element (ease-out cubic, no deps).
 *
 * @param {HTMLElement|null} el
 * @param {number} target
 * @param {{ duration?: number, suffix?: string, decimals?: number }} [opts]
 */
export function countUp(el, target, opts = {}) {
  if (!el || !isFinite(target)) return;
  const { duration = 1200, suffix = '', decimals = 0 } = opts;
  const t0 = performance.now();

  function tick(now) {
    const elapsed = Math.min(now - t0, duration);
    const progress = 1 - Math.pow(1 - elapsed / duration, 3); // ease-out cubic
    el.textContent = (target * progress).toFixed(decimals) + suffix;
    if (elapsed < duration) requestAnimationFrame(tick);
    else el.textContent = target.toFixed(decimals) + suffix;
  }

  requestAnimationFrame(tick);
}


// ── Energy meter (21st.dev: thegridcn/energy-meter inspired) ────────────────

/**
 * Fill a segmented energy-meter element to a given level.
 * Creates segment divs inside meterEl if not already present.
 *
 * @param {HTMLElement|null} meterEl  - element with class .energy-meter
 * @param {number}           level    - 0 to 1
 * @param {number}           [n=20]   - number of segments
 */
export function fillEnergyMeter(meterEl, level, n = 20) {
  if (!meterEl) return;

  if (meterEl.children.length !== n) {
    meterEl.innerHTML = '';
    for (let i = 0; i < n; i++) {
      const s = document.createElement('div');
      s.className = 'energy-segment';
      meterEl.appendChild(s);
    }
  }

  const active   = Math.round(Math.min(1, Math.max(0, level)) * n);
  const isDanger = level > 0.70;
  const isWarn   = level > 0.35;

  Array.from(meterEl.children).forEach((seg, i) => {
    if (i < active) {
      seg.className = 'energy-segment active' + (isDanger ? ' danger' : isWarn ? ' warn' : '');
    } else {
      seg.className = 'energy-segment';
    }
  });
}


// ── Stagger table rows ────────────────────────────────────────────────────────

/**
 * Animate table body rows in with stagger after a table is rendered.
 *
 * @param {HTMLTableSectionElement|null} tbody
 * @param {number} [startDelay=0]
 */
export function revealTableRows(tbody, startDelay = 0) {
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll('tr'));
  if (!rows.length) return;
  animate(
    rows,
    { opacity: [0, 1], x: [-12, 0] },
    { duration: 0.3, easing: SMOOTH, delay: stagger(0.03, { start: startDelay }) }
  );
}
