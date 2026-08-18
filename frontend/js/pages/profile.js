/**
 * profile.js — Professional Profile Dashboard
 *
 * Features:
 *  - Modern tab-based navigation
 *  - Profile stats with real-time updates
 *  - Security indicators
 *  - Account management (profile, password, MFA)
 *  - Session details with JWT claims
 *  - 3D scene + smooth animations
 */

let initProfileScene = () => {};
let revealPanels = () => {};
let fadeUp = () => {};

function $(id) { return document.getElementById(id); }
function showFeedback(el, msg, type) { if (!el) return; el.textContent = msg; el.className = 'feedback-msg ' + type; el.style.display = 'block'; }
function hideFeedback(el) { if (!el) return; el.style.display = 'none'; }

// ──────────────────────────────────────────────────────────────────
// Tab Navigation
// ──────────────────────────────────────────────────────────────────
function initTabs() {
  const buttons = document.querySelectorAll('.tab-btn');
  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;

      // Update active button
      buttons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      // Update active content
      document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
      });
      const activeContent = document.getElementById(tabName);
      if (activeContent) activeContent.classList.add('active');
    });
  });
}

// ──────────────────────────────────────────────────────────────────
// Password Strength Indicator
// ──────────────────────────────────────────────────────────────────
function calcStrength(pwd) {
  let level = 0;
  if (pwd.length >= 8)           level++;
  if (/[A-Z]/.test(pwd))          level++;
  if (/[0-9]/.test(pwd))          level++;
  if (/[^A-Za-z0-9]/.test(pwd))   level++;
  return level;
}

function updateStrengthBar() {
  const pwd = $('newPwd')?.value || '';
  const level = calcStrength(pwd);
  const fill = $('strengthFill');
  if (fill) {
    fill.setAttribute('data-level', level);
  }
}

// ──────────────────────────────────────────────────────────────────
// Profile Display & Updates
// ──────────────────────────────────────────────────────────────────
function renderSecurityIndicators(user) {
  const container = document.getElementById('securityIndicators');
  if (!container) return;

  const indicators = [];

  // Risk score
  const riskScore = user.risk_score || 0;
  let riskStatus = 'ok', riskLabel = 'Low Risk';
  if (riskScore >= 0.85) {
    riskStatus = 'alert';
    riskLabel = 'Critical Risk';
  } else if (riskScore >= 0.55) {
    riskStatus = 'warn';
    riskLabel = 'Medium Risk';
  }
  indicators.push({ status: riskStatus, label: `Risk Score: ${(riskScore * 100).toFixed(0)}% — ${riskLabel}` });

  // MFA
  indicators.push({ status: user.mfa_enabled ? 'ok' : 'warn', label: user.mfa_enabled ? 'Two-Factor Auth: Enabled' : 'Two-Factor Auth: Disabled' });

  // Account status
  indicators.push({ status: user.is_active ? 'ok' : 'alert', label: user.is_active ? 'Account: Active' : 'Account: Disabled' });

  // Step-up
  if (user.stepup_required) {
    indicators.push({ status: 'warn', label: 'Step-up Required: MFA needed for sensitive operations' });
  }

  // Frozen
  if (user.account_frozen_until) {
    indicators.push({ status: 'alert', label: 'Account Frozen: Security incident detected' });
  }

  container.innerHTML = indicators.map(ind => `
    <div class="security-indicator">
      <div class="indicator-dot ${ind.status}"></div>
      <span>${ind.label}</span>
    </div>
  `).join('');
}

function updateProfileDisplay(user) {
  // Avatar + header
  const firstChar = (user.full_name || user.email || 'U').charAt(0).toUpperCase();
  const avatar = $('profileAvatar');
  if (avatar) avatar.textContent = firstChar;

  $('profileName').textContent = user.full_name || user.email || 'User';
  $('profileEmail').textContent = user.email || '—';
  $('topbarUser').textContent = user.email || 'user';

  // Quick stats
  const riskScore = user.risk_score || 0;
  $('riskScoreValue').textContent = (riskScore * 100).toFixed(0) + '%';

  // Account age
  if (user.created_at) {
    const created = new Date(user.created_at);
    const now = new Date();
    const days = Math.floor((now - created) / (1000 * 60 * 60 * 24));
    $('accountAgeValue').textContent = days === 0 ? 'New' : days + (days === 1 ? ' day' : ' days');
  }

  // Session status
  $('sessionStatusValue').textContent = user.is_active ? '✓' : '✗';

  // MFA status — show the correct section based on current state
  $('mfaStatusValue').textContent = user.mfa_enabled ? 'ON' : 'OFF';
  if (user.mfa_enabled) {
    const dis = $('mfaDisabledState');
    const ena = $('mfaEnabledState');
    if (dis) dis.style.display = 'none';
    if (ena) ena.style.display = 'block';
  }

  // Form fields
  $('emailDisplay').value = user.email || '';
  $('fullNameInput').value = user.full_name || '';
  $('usernameInput').value = user.username || '';

  // Role badge
  const badge = document.getElementById('roleBadge');
  if (badge) {
    badge.textContent = (user.role || 'user').toUpperCase();
  }

  // Admin link
  if (user.role === 'admin') {
    const link = $('navAdmin');
    if (link) link.style.display = '';
  }

  // Security indicators
  renderSecurityIndicators(user);
}

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

function formatDate(timestamp) {
  if (!timestamp) return '—';
  try {
    return new Date(timestamp * 1000).toLocaleString();
  } catch (_) {
    return '—';
  }
}

function updateSessionClaims() {
  const token = Auth.getToken();
  const payload = token ? decodeJwt(token) : null;

  if (!payload) {
    $('claimSub').textContent = '—';
    $('claimRole').textContent = '—';
    $('claimIat').textContent = '—';
    $('claimExp').textContent = '—';
    return;
  }

  $('claimSub').textContent = payload.sub || '—';
  $('claimRole').textContent = payload.role || '—';
  $('claimIat').textContent = formatDate(payload.iat);
  $('claimExp').textContent = formatDate(payload.exp);
}

function updateSessionInfo(user) {
  if (user.last_login) {
    $('lastLoginTime').textContent = new Date(user.last_login).toLocaleString();
  }
  if (user.last_login_ip) {
    $('lastLoginIp').textContent = user.last_login_ip;
  }
}

// ──────────────────────────────────────────────────────────────────
// Profile Form
// ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  // 1. Auth guard
  const user = await Auth.requireAuth();
  if (!user) return;

  // 2. Init UI
  initTabs();
  updateProfileDisplay(user);
  updateSessionClaims();
  updateSessionInfo(user);

  // 3. Load 3D scene lazily
  Promise.all([
    import('../scene-dashboard.js').catch(() => null),
    import('../motion-utils.js').catch(() => null),
  ]).then(([sceneM, motionM]) => {
    if (sceneM) sceneM.initDashboardScene(document.getElementById('bg-canvas'));
    if (motionM) {
      motionM.revealPanels('.panel', 0.15);
      motionM.revealPanels('.stat-card', 0.1);
    }
  });

  // 4. Profile form
  const profileForm = $('profileForm');
  if (profileForm) {
    profileForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fullName = $('fullNameInput').value.trim();
      const username = $('usernameInput').value.trim();
      const feedback = $('profileFeedback');

      try {
        const result = await API.request('PATCH', '/auth/me', { full_name: fullName, username });
        if (result && result.email) {
          showFeedback(feedback, 'Profile updated successfully!', 'success');
          setTimeout(() => hideFeedback(feedback), 3000);
        }
      } catch (err) {
        const msg = window._extractError(err, 'Failed to update profile');
        showFeedback(feedback, msg, 'error');
      }
    });
  }

  // 5. Password form
  $('newPwd')?.addEventListener('input', updateStrengthBar);

  const passwordForm = $('passwordForm');
  if (passwordForm) {
    passwordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const current = $('currentPwd').value;
      const newPwd = $('newPwd').value;
      const confirm = $('confirmPwd').value;
      const feedback = $('pwFeedback');

      if (newPwd !== confirm) {
        showFeedback(feedback, 'Passwords do not match', 'error');
        return;
      }

      const strength = calcStrength(newPwd);
      if (strength < 3) {
        showFeedback(feedback, 'Password is too weak', 'error');
        return;
      }

      try {
        await API.request('PATCH', '/auth/me/password', { current_password: current, new_password: newPwd });
        showFeedback(feedback, 'Password updated successfully!', 'success');
        passwordForm.reset();
        updateStrengthBar();
        setTimeout(() => hideFeedback(feedback), 3000);
      } catch (err) {
        const msg = window._extractError(err, 'Failed to update password');
        showFeedback(feedback, msg, 'error');
      }
    });
  }

  // 6. MFA flow
  const enableMfaBtn = $('enableMfaBtn');
  if (enableMfaBtn) {
    enableMfaBtn.addEventListener('click', async () => {
      try {
        const result = await API.request('POST', '/auth/mfa/setup');
        if (result && result.secret) {
          $('mfaSecretText').value = result.secret;
          const qrSrc = result.qr_code_base64
            ? `data:image/png;base64,${result.qr_code_base64}`
            : (result.qr_url || '');
          $('mfaQrWrap').innerHTML = qrSrc
            ? `<img src="${qrSrc}" alt="QR Code" style="max-width:200px;">`
            : `<p style="font-size:0.85em;opacity:0.7">Scan this secret in your authenticator app: ${result.secret}</p>`;
          $('mfaDisabledState').style.display = 'none';
          $('mfaSetupState').style.display = 'block';
          $('mfaCode').focus();
        }
      } catch (err) {
        alert(window._extractError(err, 'Failed to setup MFA'));
      }
    });
  }

  const mfaVerifyForm = $('mfaVerifyForm');
  if (mfaVerifyForm) {
    mfaVerifyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = $('mfaCode').value.trim();
      const feedback = $('mfaVerifyFeedback');

      try {
        await API.request('POST', '/auth/mfa/verify-setup', { code });
        showFeedback(feedback, 'MFA activated!', 'success');
        setTimeout(() => {
          $('mfaSetupState').style.display = 'none';
          $('mfaEnabledState').style.display = 'block';
        }, 1500);
      } catch (err) {
        showFeedback(feedback, window._extractError(err, 'Invalid code'), 'error');
      }
    });
  }

  const cancelMfaBtn = $('cancelMfaBtn');
  if (cancelMfaBtn) {
    cancelMfaBtn.addEventListener('click', () => {
      $('mfaSetupState').style.display = 'none';
      $('mfaDisabledState').style.display = 'block';
      $('mfaCode').value = '';
      hideFeedback($('mfaVerifyFeedback'));
    });
  }

  const mfaDisableForm = $('mfaDisableForm');
  if (mfaDisableForm) {
    mfaDisableForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const code = $('mfaDisableCode').value.trim();
      const feedback = $('mfaDisableFeedback');

      try {
        await API.request('POST', '/auth/mfa/disable', { code });
        showFeedback(feedback, 'MFA disabled', 'success');
        setTimeout(() => {
          $('mfaEnabledState').style.display = 'none';
          $('mfaDisabledState').style.display = 'block';
          $('mfaDisableCode').value = '';
        }, 1500);
      } catch (err) {
        showFeedback(feedback, window._extractError(err, 'Invalid code'), 'error');
      }
    });
  }

  // 7. Password visibility toggle
  document.querySelectorAll('.pw-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const input = $(targetId);
      if (!input) return;
      const isHidden = input.type === 'password';
      input.type = isHidden ? 'text' : 'password';
      btn.innerHTML = isHidden
        ? '<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
        : '<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    });
  });

  // 8. Logout
  document.querySelectorAll('[onclick="Auth.logout()"]').forEach(btn => {
    btn.addEventListener('click', () => Auth.logout());
  });
});
