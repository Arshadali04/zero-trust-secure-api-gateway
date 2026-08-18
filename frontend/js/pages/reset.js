/**
 * pages/reset.js
 * Handles both forgot-password.html and reset-password.html.
 * Detected by checking which form element is present in the DOM.
 */
// Scene + animation loaded dynamically so a CDN failure never breaks page logic.
let initAuthScene = () => {};
let fadeUp = () => {};

// ── Shared helpers ────────────────────────────────────────────────────────────

function showAlert(msg, type = 'error') {
  const el = document.getElementById('alertBanner');
  if (!el) return;
  el.textContent = msg;
  el.className = 'alert-banner alert-' + (type === 'success' ? 'success' : 'error');
  el.style.display = 'flex';
  if (type !== 'success') {
    // Auto-dismiss errors after 8 s
    setTimeout(() => { el.style.display = 'none'; }, 8000);
  }
}

function getStrengthLevel(pw) {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 8)          score++;
  if (/[A-Z]/.test(pw))        score++;
  if (/[0-9]/.test(pw))        score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return score;
}

const EYE_OPEN = `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">`
  + `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;

const EYE_CLOSED = `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">`
  + `<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94`
  + `M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/>`
  + `<line x1="1" y1="1" x2="23" y2="23"/></svg>`;

function setupPwToggle(toggleId, inputId) {
  const btn = document.getElementById(toggleId);
  const inp = document.getElementById(inputId);
  if (!btn || !inp) return;
  btn.innerHTML = EYE_OPEN;
  btn.addEventListener('click', () => {
    inp.type = inp.type === 'password' ? 'text' : 'password';
    btn.innerHTML = inp.type === 'password' ? EYE_OPEN : EYE_CLOSED;
  });
}

// ── Entry point ───────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Load 3D scene + animations lazily — CDN failures must not block page logic.
  Promise.all([
    import('../scene-auth.js').catch(() => null),
    import('../motion-utils.js').catch(() => null),
  ]).then(([sceneM, motionM]) => {
    if (sceneM) sceneM.initAuthScene(document.getElementById('bg-canvas'));
    if (motionM) motionM.fadeUp(document.querySelector('.auth-card'), 0.15);
  });

  // ── FORGOT PASSWORD PAGE ────────────────────────────────────────────────────
  const forgotForm = document.getElementById('forgotForm');
  if (forgotForm) {
    forgotForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();
      const btn   = document.getElementById('submitBtn');
      btn.disabled    = true;
      btn.textContent = 'Sending…';
      try {
        await window.API.forgotPassword(email);
      } catch (_) {
        // Always show success — never reveal whether the account exists
      } finally {
        btn.disabled    = false;
        btn.textContent = 'Send reset link';
      }
      showAlert('If this email is registered, you will receive a reset link.', 'success');
    });
    return; // nothing else to set up on the forgot-password page
  }

  // ── RESET PASSWORD PAGE ─────────────────────────────────────────────────────
  const resetForm = document.getElementById('resetForm');
  if (!resetForm) return;

  // Extract token from URL hash: /reset-password.html#token=<value>
  const token = new URLSearchParams(window.location.hash.replace(/^#/, '')).get('token');

  if (!token) {
    showAlert('Invalid or expired reset link. Please request a new one.');
    const submitBtn = document.getElementById('submitBtn');
    if (submitBtn) submitBtn.disabled = true;
  }

  // Password visibility toggles
  setupPwToggle('toggleNew',     'newPassword');
  setupPwToggle('toggleConfirm', 'confirmPassword');

  // Strength meter
  const pwInput      = document.getElementById('newPassword');
  const strengthFill = document.getElementById('strengthFill');
  if (pwInput && strengthFill) {
    pwInput.addEventListener('input', () => {
      strengthFill.dataset.level = String(getStrengthLevel(pwInput.value));
    });
  }

  // Form submit
  resetForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (!token) {
      showAlert('Invalid or expired reset link. Please request a new one.');
      return;
    }

    const newPassword     = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (newPassword !== confirmPassword) {
      showAlert('Passwords do not match.');
      document.getElementById('confirmPassword').classList.add('error');
      return;
    }

    document.getElementById('confirmPassword').classList.remove('error');

    const btn = document.getElementById('submitBtn');
    btn.disabled    = true;
    btn.textContent = 'Updating…';

    try {
      await window.API.resetPassword(token, newPassword);
      showAlert('Password updated. Redirecting to sign in…', 'success');
      setTimeout(() => window.location.replace('login.html'), 2000);
    } catch (err) {
      const msg = window._extractError
        ? window._extractError(err, 'Reset failed.')
        : (err && err.data && err.data.detail ? err.data.detail : 'Reset failed.');
      showAlert(msg);
      btn.disabled    = false;
      btn.textContent = 'Set new password';
    }
  });
});
