/**
 * register.js — Page logic for register.html
 * ES module. Requires window.API and window.Auth (api.js + auth.js).
 */

// Scene + animation loaded dynamically so a CDN failure never breaks auth.
let initAuthScene = () => {};
let fadeUp = () => {};

// ── SVG icons ─────────────────────────────────────────────────────────────────

const SVG_EYE = `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" aria-hidden="true">
  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
  <circle cx="12" cy="12" r="3"/>
</svg>`;

const SVG_EYE_OFF = `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" aria-hidden="true">
  <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/>
  <line x1="1" y1="1" x2="23" y2="23"/>
</svg>`;

// ── Alert helper ─────────────────────────────────────────────────────────────

/**
 * Display an inline alert banner inside the auth-card.
 * @param {string} msg
 * @param {'error'|'success'|'info'} type
 */
function showAlert(msg, type = 'error') {
  const banner = document.getElementById('alertBanner');
  banner.className = `alert-banner ${type}`;
  banner.textContent = msg;
  banner.style.display = 'flex';
  if (type === 'success') {
    setTimeout(() => { banner.style.display = 'none'; }, 5000);
  }
}

function hideAlert() {
  document.getElementById('alertBanner').style.display = 'none';
}

// ── Password strength ─────────────────────────────────────────────────────────

/**
 * Compute password strength level 0–4.
 *   0 = empty
 *   1 = too short (< 8 chars)
 *   2 = length OK, has upper + lower
 *   3 = level 2 + has digit
 *   4 = level 3 + has special character
 *
 * @param {string} pw
 * @returns {0|1|2|3|4}
 */
function computeStrength(pw) {
  if (!pw) return 0;
  if (pw.length < 8) return 1;

  const hasUpper   = /[A-Z]/.test(pw);
  const hasLower   = /[a-z]/.test(pw);
  const hasDigit   = /[0-9]/.test(pw);
  const hasSpecial = /[^A-Za-z0-9]/.test(pw);

  if (hasUpper && hasLower && hasDigit && hasSpecial) return 4;
  if (hasUpper && hasLower && hasDigit) return 3;
  if (hasUpper && hasLower) return 2;
  // length >= 8 but missing case diversity
  return 2;
}

const STRENGTH_HINTS = {
  0: 'Min 8 chars, upper+lower+digit+special',
  1: 'Too short — minimum 8 characters',
  2: 'Weak — add a digit to strengthen',
  3: 'Good — add a special character for maximum strength',
  4: 'Strong password',
};

function updateStrengthUI(pw) {
  const level = computeStrength(pw);
  const fill  = document.getElementById('strengthFill');
  const hint  = document.getElementById('strengthHint');
  fill.setAttribute('data-level', String(level));
  hint.textContent = STRENGTH_HINTS[level] ?? '';
}

// ── Field validation helpers ──────────────────────────────────────────────────

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Attach a red border + inline error message to a field's .form-group.
 * Removes any previous error for that field first.
 */
function setFieldError(inputId, msg) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.classList.add('error');
  const group = input.closest('.form-group');
  if (!group) return;
  // Remove existing error element, if any
  const existing = group.querySelector('.form-error');
  if (existing) existing.remove();
  const errEl = document.createElement('span');
  errEl.className = 'form-error';
  errEl.textContent = msg;
  group.appendChild(errEl);
}

function clearFieldError(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.classList.remove('error');
  const group = input.closest('.form-group');
  if (group) {
    const errEl = group.querySelector('.form-error');
    if (errEl) errEl.remove();
  }
}

// ── Toggle helper (shared for password + confirm) ─────────────────────────────

function wirePasswordToggle(inputId, btnId) {
  const input = document.getElementById(inputId);
  const btn   = document.getElementById(btnId);
  btn.innerHTML = SVG_EYE;
  btn.addEventListener('click', () => {
    const show    = input.type === 'password';
    input.type    = show ? 'text' : 'password';
    btn.innerHTML = show ? SVG_EYE_OFF : SVG_EYE;
    btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  });
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {

  // 1. Load 3D scene + animations lazily — CDN failures must not block auth.
  Promise.all([
    import('../scene-auth.js').catch(() => null),
    import('../motion-utils.js').catch(() => null),
  ]).then(([sceneM, motionM]) => {
    if (sceneM) sceneM.initAuthScene(document.getElementById('bg-canvas'));
    if (motionM) motionM.fadeUp(document.querySelector('.auth-card'), 0.15);
  });

  // 2. Password strength meter ─────────────────────────────────────────────────
  const passwordInput = document.getElementById('password');
  passwordInput.addEventListener('input', () => {
    updateStrengthUI(passwordInput.value);
  });

  // 3. Password visibility toggles ─────────────────────────────────────────────
  wirePasswordToggle('password', 'pwToggle');
  wirePasswordToggle('confirmPassword', 'confirmPwToggle');

  // 4. Inline blur-time field validation ───────────────────────────────────────
  const FIELD_LABELS = { fullName: 'Full name', email: 'Email', username: 'Username' };

  Object.keys(FIELD_LABELS).forEach((id) => {
    const input = document.getElementById(id);

    input.addEventListener('blur', () => {
      const val = input.value.trim();
      if (!val) {
        setFieldError(id, `${FIELD_LABELS[id]} is required.`);
      } else if (id === 'email' && !validateEmail(val)) {
        setFieldError(id, 'Enter a valid email address.');
      } else {
        clearFieldError(id);
      }
    });

    // Clear the error as soon as the user starts correcting the value
    input.addEventListener('input', () => clearFieldError(id));
  });

  // 5. Registration form submit ─────────────────────────────────────────────────
  const registerForm = document.getElementById('registerForm');
  const registerBtn  = document.getElementById('registerBtn');

  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const fullName        = document.getElementById('fullName').value.trim();
    const email           = document.getElementById('email').value.trim();
    const username        = document.getElementById('username').value.trim();
    const password        = passwordInput.value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    // ── Client-side validation ────────────────────────────────────────────────
    let hasError = false;

    if (!fullName) {
      setFieldError('fullName', 'Full name is required.');
      hasError = true;
    }

    if (!email || !validateEmail(email)) {
      setFieldError('email', 'Enter a valid email address.');
      hasError = true;
    }

    if (!username) {
      setFieldError('username', 'Username is required.');
      hasError = true;
    }

    if (!password || password.length < 8) {
      showAlert('Password must be at least 8 characters.');
      hasError = true;
    } else if (password !== confirmPassword) {
      showAlert('Passwords do not match.');
      hasError = true;
    }

    if (hasError) return;

    // ── Submit to backend ─────────────────────────────────────────────────────
    registerBtn.disabled    = true;
    registerBtn.textContent = 'Creating account…';

    const result = await Auth.register(email, username, password, fullName);

    registerBtn.disabled    = false;
    registerBtn.textContent = 'Create account';

    if (result.success) {
      showAlert('Account created! Redirecting to sign in…', 'success');
      setTimeout(() => window.location.replace('login.html'), 1500);
    } else if (result.error) {
      showAlert(result.error);
    }
  });

});
