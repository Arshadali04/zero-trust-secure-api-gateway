/**
 * login.js — Page logic for login.html
 * ES module. Requires window.API and window.Auth (api.js + auth.js).
 */

// Scene + animation loaded dynamically so a CDN failure never breaks auth.
let initAuthScene = () => {};
let fadeUp = () => {};

// ── State ─────────────────────────────────────────────────────────────────────

/** Holds the temporary MFA token returned by the server when mfa_required=true */
let tempToken = null;

// ── SVG icons ────────────────────────────────────────────────────────────────

const SVG_EYE = `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" aria-hidden="true">
  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
  <circle cx="12" cy="12" r="3"/>
</svg>`;

const SVG_EYE_OFF = `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" aria-hidden="true">
  <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/>
  <line x1="1" y1="1" x2="23" y2="23"/>
</svg>`;

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Display an inline alert banner inside the auth-card.
 * @param {string} msg
 * @param {'error'|'success'|'info'|'frozen'} type
 */
function showAlert(msg, type = 'error') {
  const banner = document.getElementById('alertBanner');
  banner.className = `alert-banner ${type}`;
  banner.textContent = msg;
  banner.style.display = 'flex';
  // Keep frozen alerts visible longer
  if (type === 'frozen') {
    banner.style.fontSize = '0.9rem';
    banner.style.fontWeight = '500';
  }
}

function hideAlert() {
  const banner = document.getElementById('alertBanner');
  banner.style.display = 'none';
}

/**
 * Switch the visible section to the MFA input.
 * Hides the login form and OAuth section so the card shows only MFA controls.
 */
function showMfaSection() {
  document.getElementById('loginForm').style.display = 'none';
  document.getElementById('oauthSection').style.display = 'none';
  document.getElementById('mfaSection').style.display = 'block';
  hideAlert();
  const mfaCode = document.getElementById('mfaCode');
  mfaCode.value = '';
  mfaCode.focus();
}

/**
 * Restore the login form and OAuth section; hide MFA controls.
 */
function hideMfaSection() {
  document.getElementById('mfaSection').style.display = 'none';
  document.getElementById('loginForm').style.display = 'flex';
  document.getElementById('oauthSection').style.display = 'block';
  hideAlert();
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {

  // ── Register ALL event listeners synchronously first ─────────────────────────
  // IMPORTANT: Do this before any async work so listeners are always attached,
  // regardless of whether the page arrived via OAuth redirect or direct navigation.

  // 3. Email / password login form
  const loginForm = document.getElementById('loginForm');
  const loginBtn  = document.getElementById('loginBtn');

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const email    = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;

    loginBtn.disabled    = true;
    loginBtn.textContent = 'Signing in…';

    const result = await Auth.login(email, password);

    loginBtn.disabled    = false;
    loginBtn.textContent = 'Sign in';

    if (result.mfa_required) {
      tempToken = result.temp_token;
      showMfaSection();
    } else if (result.error) {
      if (result.frozen) {
        showAlert(result.error, 'frozen');
        loginBtn.disabled = false;
      } else {
        showAlert(result.error);
      }
    }
  });

  // 4. MFA verify button
  const mfaBtn = document.getElementById('mfaBtn');

  mfaBtn.addEventListener('click', async () => {
    const code = document.getElementById('mfaCode').value.trim();

    if (!code || !/^\d{6}$/.test(code)) {
      showAlert('Enter the 6-digit code from your authenticator app.');
      return;
    }

    if (!tempToken) {
      showAlert('Session expired. Please sign in again.');
      hideMfaSection();
      return;
    }

    hideAlert();
    mfaBtn.disabled    = true;
    mfaBtn.textContent = 'Verifying…';

    const prevToken = localStorage.getItem('token');
    localStorage.setItem('token', tempToken);

    try {
      const result = await API.verifyMfa(code);

      if (result && result.access_token) {
        Auth.finishLogin(result.access_token, result.user || null, result.refresh_token || null);
      } else {
        if (prevToken) localStorage.setItem('token', prevToken);
        else localStorage.removeItem('token');
        showAlert('MFA verification failed. Please try again.');
      }
    } catch (err) {
      if (prevToken) localStorage.setItem('token', prevToken);
      else localStorage.removeItem('token');
      const msg = window._extractError
        ? window._extractError(err, 'Invalid MFA code.')
        : (err && err.data && err.data.detail) || 'Invalid MFA code.';
      showAlert(msg);
    } finally {
      mfaBtn.disabled    = false;
      mfaBtn.textContent = 'Verify';
    }
  });

  // Enter key submits MFA code
  document.getElementById('mfaCode').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      mfaBtn.click();
    }
  });

  // 5. Cancel MFA
  document.getElementById('cancelMfaBtn').addEventListener('click', () => {
    tempToken = null;
    localStorage.removeItem('token');
    hideMfaSection();
  });

  // ── Now handle OAuth callback / async boot ────────────────────────────────────
  (async () => {
  // 1. Load 3D scene + animations lazily
  Promise.all([
    import('../scene-auth.js').catch(() => null),
    import('../motion-utils.js').catch(() => null),
  ]).then(([sceneM, motionM]) => {
    if (sceneM) sceneM.initAuthScene(document.getElementById('bg-canvas'));
    if (motionM) motionM.fadeUp(document.querySelector('.auth-card'), 0.15);
  });

  // 2. OAuth callback (URL fragment contains token after OAuth redirect)
  const oauthResult = await Auth.handleOAuthCallback();

  if (oauthResult === true) return; // finishLogin called, page is navigating away

  if (oauthResult && oauthResult.mfa_required) {
    tempToken = oauthResult.temp_token;
    showMfaSection();
  }

  if (oauthResult && oauthResult.error) {
    showAlert(oauthResult.error);
  }
  })();

  // 6. Password visibility toggle ───────────────────────────────────────────────
  const pwToggle     = document.getElementById('pwToggle');
  const passwordInput = document.getElementById('password');

  // Inject initial icon
  pwToggle.innerHTML = SVG_EYE;

  pwToggle.addEventListener('click', () => {
    const isHidden = passwordInput.type === 'password';
    passwordInput.type   = isHidden ? 'text' : 'password';
    pwToggle.innerHTML   = isHidden ? SVG_EYE_OFF : SVG_EYE;
    pwToggle.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
  });

});
