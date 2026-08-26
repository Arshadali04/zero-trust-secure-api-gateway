# Testing Guide — Risk Scoring & Profile Dashboard

## Prerequisites

1. **Backend Running**:
   ```bash
   cd d:\zero-trust-api-gateway
   python run.py
   ```
   Should see: `Uvicorn running on http://127.0.0.1:8000`

2. **Database Initialized**:
   ```bash
   # Check for sqlite.db file or run migrations
   ```

3. **Frontend Accessible**:
   ```
   http://127.0.0.1:8000/frontend/login.html
   ```

---

## Test 1: Normal User Journey

### Steps
1. Go to `http://127.0.0.1:8000/frontend/login.html`
2. Register new account:
   - Email: `testuser@example.com`
   - Password: `SecurePass123!`
   - Full Name: `Test User`
   - Username: `testuser`
3. Click "Sign in"
4. Redirected to `/frontend/dashboard.html`

### Expected Results
- ✅ Dashboard loads with 3D scene background
- ✅ Risk Score shows **0%** (green, low risk)
- ✅ Account Status: ✓ Active, MFA: Disabled
- ✅ Session shows correct email and expiry
- ✅ Can navigate to Profile page

---

## Test 2: Profile Page Features

### Account Tab
1. Navigate to `/frontend/profile.html`
2. Should see profile card with:
   - Avatar initial **T** in gradient
   - Name: **Test User**
   - Email: **testuser@example.com**
   - Quick stats: Risk 0%, Account Age 0 days, Session ✓, 2FA OFF

3. Update Full Name to **"Test User Updated"`
4. Click **"Save Changes"**

### Expected Results
- ✅ Profile card updates immediately
- ✅ Success message appears: "Profile updated successfully!"
- ✅ Changes persist on page reload

### Password Tab
1. Click **"Password & Security"** tab
2. Enter:
   - Current Password: `SecurePass123!`
   - New Password: `NewSecure456!`
   - Confirm: `NewSecure456!`
3. Watch strength bar update as you type
4. Click **"Update Password"**

### Expected Results
- ✅ Strength bar shows 75%+ (green)
- ✅ Success message: "Password updated successfully!"
- ✅ Form clears
- ✅ New password works on next login

### 2FA Tab (Disabled State)
1. Click **"Two-Factor Auth"** tab
2. See message: "Two-factor authentication adds an extra layer..."
3. Click **"Enable Two-Factor Authentication"**

### Expected Results
- ✅ Section changes to show QR code
- ✅ Secret key displayed for manual entry
- ✅ Can copy/scan QR with authenticator app

### 2FA Tab (Setup State)
1. In authenticator app (Google Authenticator, Authy, etc.):
   - Scan QR code or enter manual secret
2. Get 6-digit code from app (e.g., `123456`)
3. Enter code in form
4. Click **"Activate 2FA"**

### Expected Results
- ✅ Code verified
- ✅ Success message
- ✅ Section changes to "MFA is active" state
- ✅ Shows: "Two-Factor Authentication is protecting your account"
- ✅ Stat card shows "2FA: ON"

### Session Tab
1. Click **"Session Details"** tab
2. Should see all fields populated:
   - Email (Subject): `testuser@example.com`
   - Role: `USER`
   - Issued At: `[formatted timestamp]`
   - Expires: `[formatted timestamp 1 hour later]`
   - Last Login: `[today's timestamp]`
   - Last Login IP: `[your IP address]`

### Expected Results
- ✅ All fields display correct values
- ✅ Timestamps are human-readable format
- ✅ IP address shows your connection

---

## Test 3: Risk Scoring — Simulate Elevated Risk

### Option A: Rapid Requests (Behavior Risk)
```bash
# In terminal, run rapid requests to trigger behavior risk
for i in {1..200}; do curl -H "Authorization: Bearer <token>" http://127.0.0.1:8000/api/v1/data/ping; done
```

### Option B: Use Attack Simulator
1. Go to `/frontend/attack-lab.html`
2. Click **"Brute Force"** attack simulation
3. Let it run for a few seconds

### Expected Results
- ✅ Dashboard Risk Score increases
- ✅ Color changes: Green → Yellow (30–70%)
- ✅ Account Status may show "⚠️ Step-up required"
- ✅ Behavior risk accumulates

### Check Database
```bash
# In SQLite shell
sqlite3 sqlite.db
SELECT risk_score, stepup_required, account_frozen_until FROM users WHERE email='testuser@example.com';
```

Expected: Risk increasing, stepup_required may become true

---

## Test 4: Risk Scoring — Trigger Account Freeze

### Trigger Critical Risk (0.85+)
```bash
# Option 1: Multiple WAF violations
for i in {1..50}; do 
  curl "http://127.0.0.1:8000/api/v1/data/status?q=<script>alert('xss')</script>"
done

# Option 2: Direct database update (for testing)
sqlite3 sqlite.db << 'EOF'
UPDATE users SET risk_score = 0.86, risk_updated_at = datetime('now') 
WHERE email = 'testuser@example.com';
EOF
```

### Immediate Effects
1. Token version increments (all sessions revoked)
2. `account_frozen_until` set to now + 1 hour
3. `SecurityEvent` logged with threat_type="account_frozen"

### Try to Login
1. Logout from current session
2. Go to login page
3. Enter credentials: `testuser@example.com` / password
4. Click "Sign in"

### Expected Results
- ✅ **Red alert banner** appears:
  ```
  🔒 Account frozen due to critical security risk.
     Please try again in 59 minutes.
  ```
- ✅ Login button disabled
- ✅ No authentication tokens issued
- ✅ Each retry updates remaining time countdown

---

## Test 5: Account Thaw After 1 Hour

### Advance Time (For Testing)
```python
# In Python shell or test script
from datetime import datetime, timedelta, timezone
from gateway.db.database import AsyncSessionLocal
from gateway.db.models import User

async def set_past_freeze():
    async with AsyncSessionLocal() as session:
        from sqlalchemy import select, update
        # Set frozen_until to 1 minute ago (already expired)
        result = await session.execute(
            update(User).where(User.email == 'testuser@example.com')
            .values(account_frozen_until=datetime.now(timezone.utc) - timedelta(minutes=1))
        )
        await session.commit()
        print("Freeze expired")

# Run it
import asyncio
asyncio.run(set_past_freeze())
```

### Try Login Again
1. Go to login page
2. Enter credentials
3. Click "Sign in"

### Expected Results
- ✅ Login succeeds (if password correct)
- ✅ Redirected to dashboard
- ✅ Risk score starts decaying
- ✅ No frozen indicators shown

---

## Test 6: Risk Decay Over Time

### Background
- Risk decays with **4-hour half-life**
- After **7 days** of inactivity, risk = 0.0

### Test Decay
```python
# Check risk score progression
import asyncio
from gateway.db.database import AsyncSessionLocal
from gateway.db.models import User
from gateway.detection.account_risk import get_account_risk
from sqlalchemy import select

async def check_risk():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.email == 'testuser@example.com'))
        user = result.scalar_one()
        risk = await get_account_risk(session, user.id)
        print(f"Current risk: {risk}")
        print(f"Last updated: {user.risk_updated_at}")
        print(f"Base score: {user.risk_score}")

asyncio.run(check_risk())
```

### Expected Results
- ✅ Risk score gradually decreases
- ✅ After 4 hours: ~50% of original
- ✅ After 24 hours: ~5% or less
- ✅ After 7 days: 0.0 (if no new events)

---

## Test 7: Step-Up Requirement (0.55 threshold)

### Trigger Step-Up
Set risk to 0.60:
```bash
sqlite3 sqlite.db << 'EOF'
UPDATE users SET risk_score = 0.60, risk_updated_at = datetime('now'), stepup_required = 1 
WHERE email = 'testuser@example.com';
EOF
```

### Dashboard View
1. Refresh dashboard
2. Account Status section shows:
   ```
   ⚠️ Step-up required
   ```

### Admin Routes
1. Try accessing `/admin/users` endpoint
2. Should get 401 or demand fresh MFA

### After Enabling MFA
1. Go to profile page → 2FA tab → Enable MFA
2. Verify with authenticator code
3. After verification, step-up requirement clears

### Expected Results
- ✅ Dashboard shows step-up warning
- ✅ Admin routes require MFA even if already logged in
- ✅ After 2FA step-up, warning clears
- ✅ Can access admin routes

---

## Test 8: Security Indicators

### Check Each Indicator Updates

#### Risk Score Indicator
- [ ] Low (0–30%): 🟢 Green
- [ ] Medium (30–70%): 🟡 Yellow  
- [ ] High (70%+): 🔴 Red

#### MFA Status
- [ ] Disabled: 🟡 "MFA: Disabled"
- [ ] Enabled: 🟢 "MFA: Enabled"

#### Account Status
- [ ] Active: 🟢 "Active"
- [ ] (Try disabling in DB): 🔴 "Disabled"

#### Step-Up
- [ ] Not required: Not shown
- [ ] Required: 🟡 "Step-up required"

#### Frozen Status
- [ ] Not frozen: Not shown
- [ ] Frozen: 🔴 "Account frozen"

---

## Test 9: Multiple Sessions & Token Revocation

### Test Token Revocation on Freeze

1. **Session 1**: Login normally
   - Store token in localStorage
   - Note: `token_version = 1`

2. **Session 2**: Open incognito window, login with same account

3. **Trigger Freeze** in first session
   - Database updates: `token_version = 2`
   - All existing tokens invalidated

4. **Session 1**: Refresh page
   - Expected: Redirected to login (token invalid)

5. **Session 2**: Refresh page  
   - Expected: Also redirected to login

### Expected Results
- ✅ Both sessions logout simultaneously
- ✅ No way to stay authenticated during freeze
- ✅ Must wait 1 hour and login again

---

## Test 10: Error Messages & Edge Cases

### Missing Fields
- [ ] Test login without MFA when MFA required
- [ ] Test profile update with invalid username
- [ ] Test password with weak strength
- [ ] Test password mismatch confirmation

### Network Errors
- [ ] Kill backend, try dashboard → Error message
- [ ] Kill backend, try profile save → Error handling
- [ ] Restore backend → Page recovers

### Session Expiry
- [ ] Wait until JWT expires (15 min default)
- [ ] Try to access protected route
- [ ] Should refresh token automatically or redirect to login

---

## Test 11: Responsive Design

### Mobile View (375px width)
- [ ] Dashboard displays single column
- [ ] Profile tabs work on mobile
- [ ] Buttons are touch-friendly
- [ ] Avatar and stats visible
- [ ] No horizontal scroll

### Tablet View (768px width)
- [ ] Layout adapts gracefully
- [ ] All features accessible
- [ ] Text readable

---

## Test 12: Accessibility

### Keyboard Navigation
- [ ] Tab through login form
- [ ] Tab through profile tabs
- [ ] Enter activates forms
- [ ] Escape closes modals

### Screen Reader
- [ ] Labels announced correctly
- [ ] Buttons have aria-labels
- [ ] Form errors announced

### Color Contrast
- [ ] Text meets WCAG AA (4.5:1 for normal text)
- [ ] Colored indicators have text labels too
- [ ] Not relying on color alone

---

## Debugging Checklist

### If Risk Score Not Updating
```bash
# Check logs
grep -i "risk" gateway/middleware/risk_scoring.py
# Check database
sqlite3 sqlite.db "SELECT id, email, risk_score, risk_updated_at FROM users;"
```

### If Account Not Freezing
```python
# Check freeze thresholds
from gateway.config import settings
print(f"Critical threshold: {settings.RISK_CRITICAL_THRESHOLD}")
print(f"Freeze seconds: {settings.RISK_FREEZE_SECONDS}")
# Check database
sqlite3 sqlite.db "SELECT id, account_frozen_until FROM users;"
```

### If Profile Page Not Loading
```bash
# Check JavaScript errors (browser console)
# F12 → Console tab → Look for errors
# Check network requests (F12 → Network tab)
# Verify GET /auth/me returns proper user object
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8000/auth/me | jq
```

### If 2FA Not Working
```bash
# Check MFA route exists
grep -r "mfa/setup\|mfa/verify" gateway/routes/
# Test endpoint
curl -X POST -H "Authorization: Bearer <token>" \
     http://127.0.0.1:8000/auth/mfa/setup | jq
```

---

## Performance Baselines

### Target Response Times
- Login: < 500ms
- Dashboard load: < 1s
- Profile tab switch: < 300ms
- Risk score update: < 100ms
- 3D scene init: < 2s

### Check Performance
```javascript
// In browser console
performance.measure('dashboard-load', navigationStart, loadEventEnd);
performance.getEntriesByName('dashboard-load');
```

---

## Load Testing

### Simulate Multiple Users
```bash
# Using Apache Bench
ab -n 1000 -c 10 http://127.0.0.1:8000/auth/me

# Using curl loop
for i in {1..100}; do (curl -s http://127.0.0.1:8000/health &); done
```

### Monitor Backend
```bash
# Watch processes
watch -n 1 'ps aux | grep python'

# Monitor database
watch -n 1 'sqlite3 sqlite.db "SELECT COUNT(*) FROM users;"'
```

---

## Sign-Off Checklist

- [ ] All tests pass
- [ ] No console errors
- [ ] Risk score properly calculated
- [ ] Account freezes at 0.85
- [ ] Login shows freeze message
- [ ] Dashboard displays risk
- [ ] Profile page renders all tabs
- [ ] 2FA setup/disable works
- [ ] Session details display correct info
- [ ] Security indicators update
- [ ] Mobile responsive
- [ ] No database errors
- [ ] Performance acceptable

---

**Testing Status**: Ready for QA
**Last Updated**: 2026-08-15
**Environment**: Windows 11, Python 3.9+, SQLite 3.x
