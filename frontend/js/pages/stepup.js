/**
 * pages/stepup.js
 * Step-up MFA re-verification.
 * Shown when the risk engine signals stepup_required (403).
 */
// Scene + animation loaded dynamically so a CDN failure never breaks page logic.
let initAuthScene = () => {};
let fadeUp = () => {};
let pulseGlow = () => {};

// ── Alert helper ──────────────────────────────────────────────────────────────

function showAlert(msg, type = 'error') {
  const el = document.getElementById('alertBanner');
  if (!el) return;
  el.textContent = msg;
  el.className = 'alert-banner alert-' + (type === 'success' ? 'success' : 'error');
  el.style.display = 'flex';
  if (type !== 'success') {
    setTimeout(() => { el.style.display = 'none'; }, 8000);
  }
}

// ── Bloom-like success flash ──────────────────────────────────────────────────

function _flashSuccess() {
  const styleEl = document.createElement('style');
  styleEl.textContent = '@keyframes _bloomFlash{0%{opacity:0}15%{opacity:1}100%{opacity:0}}';
  document.head.appendChild(styleEl);

  const overlay = document.createElement('div');
  overlay.style.cssText = [
    'position:fixed', 'inset:0', 'z-index:9998', 'pointer-events:none',
    'background:radial-gradient(circle at 50% 50%,rgba(45,212,160,0.28) 0%,rgba(91,140,255,0.12) 45%,transparent 75%)',
    'animation:_bloomFlash 0.65s ease-out forwards',
  ].join(';');
  document.body.appendChild(overlay);

  setTimeout(() => { overlay.remove(); styleEl.remove(); }, 750);
}

// ── Entry point ───────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Guard: must be authenticated (token present and not expired)
  if (!window.Auth.isAuthenticated()) {
    window.location.replace('login.html');
    return;
  }

  // Load 3D scene + animations lazily — CDN failures must not block page logic.
  Promise.all([
    import('../scene-auth.js').catch(() => null),
    import('../motion-utils.js').catch(() => null),
  ]).then(([sceneM, motionM]) => {
    if (sceneM) sceneM.initAuthScene(document.getElementById('bg-canvas'));
    if (motionM) { fadeUp = motionM.fadeUp; pulseGlow = motionM.pulseGlow; motionM.fadeUp(document.querySelector('.auth-card'), 0.1); }
  });

  const totpInput = document.getElementById('totpCode');
  const verifyBtn = document.getElementById('verifyBtn');
  const signoutLink = document.getElementById('signoutLink');

  // Guard against concurrent verification attempts
  let _verifying = false;

  // ── Input: digits only, auto-submit at 6 ─────────────────────────────────
  totpInput.addEventListener('input', () => {
    totpInput.value = totpInput.value.replace(/\D/g, '').slice(0, 6);
    if (totpInput.value.length === 6 && !_verifying) {
      verify();
    }
  });

  // ── Verify button ─────────────────────────────────────────────────────────
  verifyBtn.addEventListener('click', () => { if (!_verifying) verify(); });

  // ── Sign out ──────────────────────────────────────────────────────────────
  signoutLink.addEventListener('click', (e) => {
    e.preventDefault();
    window.Auth.logout();
  });

  // ── Core verify function ──────────────────────────────────────────────────
  async function verify() {
    const code = totpInput.value.trim();
    if (code.length !== 6) {
      showAlert('Enter the 6-digit code from your authenticator app.');
      return;
    }

    _verifying          = true;
    verifyBtn.disabled  = true;
    verifyBtn.textContent = 'Verifying…';

    try {
      const data = await window.API.verifyMfa(code);

      // Persist the new elevated token
      localStorage.setItem('token', data.access_token);
      if (data.user) localStorage.setItem('user', JSON.stringify(data.user));

      showAlert('Verified! Redirecting…', 'success');
      _flashSuccess();
      pulseGlow(document.querySelector('.auth-card'), 'rgba(45,212,160,0.5)'); // Motion: unlock glow

      // Return to the page that triggered step-up
      const returnPath = sessionStorage.getItem('stepup_return_full') || 'dashboard.html';
      sessionStorage.removeItem('stepup_return_full');

      setTimeout(() => window.location.replace(returnPath), 300);
    } catch (err) {
      _verifying          = false;
      verifyBtn.disabled  = false;
      verifyBtn.textContent = 'Verify identity';

      const msg = window._extractError
        ? window._extractError(err, 'Invalid code. Please try again.')
        : (err && err.data && err.data.detail ? err.data.detail : 'Invalid code. Please try again.');

      showAlert(msg);
      totpInput.focus();
      totpInput.select();
    }
  }
});
