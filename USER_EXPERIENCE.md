# User Experience — Risk Scoring & Profile Dashboard

## 🔒 Scenario 1: Normal User Login

### Step 1: Login
```
Email: user@example.com
Password: ••••••••

[Sign in]
```

### Step 2: Dashboard
```
┌─────────────────────────────────────────┐
│ Security Console                    ✓ Operational │
└─────────────────────────────────────────┘

┌──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ Account Risk     │ Account Status   │ Session          │ Gateway Health   │
│ 12%              │ ✓ Active         │ user@comp.com    │ ✓ Healthy        │
│ ████░░░░░░░░░░░  │ ✓ MFA: Disabled  │ expires: 2:30 PM │ All operational  │
└──────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

---

## ⚠️ Scenario 2: Elevated Risk (0.55–0.84)

### Dashboard View
```
┌──────────────────┐
│ Account Risk     │
│ 68%              │ ← Yellow (medium risk)
│ ████████████░░░░ │
│ ⚠ Step-up Required │
└──────────────────┘

Account Status:
  ✓ Active
  ✓ MFA: Disabled
  ⚠ Step-up required (← MFA needed for /admin routes)
```

**What happens**: User can still login but certain sensitive operations require fresh MFA verification.

---

## 🛑 Scenario 3: Critical Risk Freeze (≥0.85)

### Trigger
- Multiple failed logins
- Suspicious patterns detected
- WAF blocks triggered
- Behavior anomalies detected

### First Attempt to Login While Frozen
```
Email: user@example.com
Password: ••••••••

[Sign in] ← Click

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔒 Account frozen due to critical security risk.
   Please try again in 58 minutes.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**What the user sees**:
- Red alert banner with clear explanation
- Remaining time until account thaw
- No sensitive information leaked
- Same message for all login attempts during freeze window

### In Database
```sql
-- User row
account_frozen_until: 2026-08-15 15:30:00 (1 hour from now)
token_version: 2                            (invalidates all existing tokens)

-- AccountFreeze row (for admin visibility)
user_id: 42
ip_address: "*"                             (account-wide freeze)
frozen_until: 2026-08-15 15:30:00
created_at: 2026-08-15 14:30:00
```

---

## 📊 Profile Dashboard — New Design

### Header Section
```
┌───────────────────────────────────────────────────────────────┐
│                                                           [USER]│
│  👤  Jane Doe                                     Profile      │
│       jane@company.com                                        │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │   45%    │  │  124 days│  │    ✓     │  │   ON     │     │
│  │Risk Score│  │Account Age Session  2FA│     │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘     │
└───────────────────────────────────────────────────────────────┘

Security Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🟢 Risk Score: 45% — Medium Risk
  🟢 Two-Factor Auth: Enabled
  🟢 Account: Active
  🟡 MFA: Enabled
```

### Tab Navigation
```
┌─ Account Settings ─ Password & Security ─ Two-Factor Auth ─ Session Details ─┐
│                                                                              │
│ Account Settings                                                            │
│ ────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│ Email Address                                                               │
│ jane@company.com [read-only]                                               │
│                                                                              │
│ Full Name                                                                   │
│ [Jane Doe                                  ]                               │
│                                                                              │
│ Username                                                                    │
│ [jane.doe                                  ]                               │
│                                                                              │
│ [Save Changes]                                                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Password Tab
```
┌─ Account Settings ─ Password & Security ─ Two-Factor Auth ─ Session Details ─┐
│                                                                              │
│ Password & Security                                                         │
│ ────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│ Current Password                                                            │
│ [••••••••                              ] 👁                                │
│                                                                              │
│ New Password                                                                │
│ [••••••••                              ] 👁                                │
│ ████████████░░░░  (Strength: 75% — Strong)                                │
│ 8+ chars · uppercase · digit · special char                                │
│                                                                              │
│ Confirm Password                                                            │
│ [••••••••                              ] 👁                                │
│                                                                              │
│ [Update Password]                                                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2FA Tab — Enabled State
```
┌─ Account Settings ─ Password & Security ─ Two-Factor Auth ─ Session Details ─┐
│                                                                              │
│ Two-Factor Authentication                                                   │
│ ────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│  🟢 Two-Factor Authentication is active and protecting your account       │
│                                                                              │
│ To disable 2FA, enter your current authenticator code:                     │
│                                                                              │
│ Authenticator Code                                                          │
│ [000000                                ]                                   │
│                                                                              │
│ [Disable 2FA]                                                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Session Tab
```
┌─ Account Settings ─ Password & Security ─ Two-Factor Auth ─ Session Details ─┐
│                                                                              │
│ Session Details                                                             │
│ ────────────────────────────────────────────────────────────────────────   │
│                                                                              │
│ Email (Subject)                          jane@company.com                  │
│ ─────────────────────────────────────────────────────────────             │
│ Role                                     USER                              │
│ ─────────────────────────────────────────────────────────────             │
│ Issued At                                8/15/2026, 2:15:30 PM             │
│ ─────────────────────────────────────────────────────────────             │
│ Expires                                  8/15/2026, 3:15:30 PM             │
│ ─────────────────────────────────────────────────────────────             │
│ Last Login                               8/15/2026, 2:12:45 PM             │
│ ─────────────────────────────────────────────────────────────             │
│ Last Login IP                            192.168.1.100                     │
│ ─────────────────────────────────────────────────────────────             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Risk Score Color Coding

```
        0%          30%         50%         70%        100%
        |-----------|-----------|-----------|-----------|
        🟢          🟡          🟠          🔴
      GREEN       YELLOW      ORANGE       RED
      Low Risk    Medium      High      Critical
      (Allow)     Risk        Risk       (Freeze)
                (Monitor)   (Challenge)
```

**User sees**:
- **Green (0–30%)**: Padlock icon, "Low Risk"
- **Yellow (30–70%)**: Warning icon, "Medium Risk"
- **Red (70%+)**: Alert icon, "High Risk / Critical"

---

## 📱 Mobile Responsive

All views adapt to mobile:
- Single column layout
- Tabs remain functional
- Stats cards stack vertically
- Touch-friendly buttons (larger hit area)

---

## ⏰ Timeline: Account Freeze to Thaw

```
14:30:00 → Risk reaches 0.85 (CRITICAL)
├─ Database: account_frozen_until = 15:30:00
├─ token_version incremented (all sessions revoked)
└─ SecurityEvent logged

14:30:05 → User tries to login
└─ Error: "Account frozen... 59 minutes 55 seconds"

14:45:00 → User tries again
└─ Error: "Account frozen... 44 minutes 55 seconds"

15:30:00 → Freeze window expires
├─ account_frozen_until check passes
└─ Login succeeds (if credentials correct)
```

---

## 🎨 Design System

### Colors
- **Primary**: #5b8cff (Blue) — Accent, clickable elements
- **Success**: #2dd4a0 (Teal) — Safe, enabled, active
- **Warning**: #ffb636 (Amber) — Caution, step-up required
- **Alert**: #ff5d5d (Red) — Error, frozen, critical
- **Text**: #f0f4ff (Light blue) — Primary text
- **Muted**: rgba(240,244,255,0.55) — Secondary text
- **Dim**: rgba(240,244,255,0.28) — Tertiary text
- **Glass**: rgba(255,255,255,0.04) — Background overlay

### Typography
- **Sans**: Space Grotesk (600–700 weight for headers)
- **Mono**: JetBrains Mono (session tokens, values)

### Effects
- **Blur**: 12–20px backdrop filter
- **Border**: 1px rgba(255,255,255,0.08)
- **Shadow**: 0 8px 32px rgba(0,0,0,0.4)
- **Rounded**: 8–12px border radius

---

## ✨ Smooth Animations

```
LOGIN PAGE
└─ Auth card fades in (150ms)
   
DASHBOARD
└─ Panels reveal (100–150ms stagger)
└─ Risk score animates count-up (900ms)

PROFILE PAGE
└─ Header section reveals (150ms)
└─ Stat cards fade in (100ms stagger)
└─ 3D scene particles animate continuously
└─ Tab content fades (300ms)
```

---

**Designed for**: Professional security teams and end users
**Target Audience**: Enterprise API gateway users
**Accessibility**: WCAG 2.1 Level AA compliant
