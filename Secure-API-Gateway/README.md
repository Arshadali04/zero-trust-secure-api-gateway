# 🛡️ Zero Trust Secure API Gateway

A secure API gateway with **JWT authentication**, **Role-Based Access Control (RBAC)**, **rate limiting**, and **request monitoring** — built as a CSE final year major project.

## Architecture

```
Frontend (HTML/CSS/JS)  →  FastAPI Backend (API Gateway)
     ↓                           ↓
  Login Page              JWT Authentication
  Dashboard               RBAC Authorization
  API Tester              Rate Limiting (10/min)
  Request Logs            Request Logging
```

## Phase 1 (25%) — Current Implementation

- ✅ User authentication (login/register)
- ✅ JWT token generation & validation
- ✅ Role-Based Access Control (admin, user, moderator)
- ✅ Rate limiting (10 requests/minute per IP)
- ✅ Request logging & monitoring dashboard
- ✅ Protected API endpoints
- ✅ Admin-only user management

## Project Structure

```
zero-trust-api-gateway/
├── backend/
│   ├── main.py          # FastAPI app with all routes
│   ├── auth.py          # JWT + RBAC logic
│   ├── models.py        # Pydantic data models
│   ├── middleware.py     # Request logging middleware
│   ├── config.py        # Centralized configuration
│   └── requirements.txt # Python dependencies
├── frontend/
│   ├── index.html       # Single-page app
│   ├── css/style.css    # Styles
│   └── js/
│       ├── api.js       # API client
│       └── app.js       # UI logic
└── README.md
```

## Setup & Run

### 1. Backend (FastAPI)

```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Backend runs at: **http://localhost:8000**
API docs at: **http://localhost:8000/docs**

### 2. Frontend

Open `frontend/index.html` in a browser, or serve it:

```bash
cd frontend
python -m http.server 5500
```

Frontend at: **http://localhost:5500**

### Demo Accounts

| Username | Password  | Role  |
|----------|-----------|-------|
| admin    | admin123  | Admin |
| user1    | user123   | User  |

## API Endpoints

| Method | Path               | Auth     | Description              |
|--------|--------------------|----------|--------------------------|
| POST   | /api/login         | Public   | Authenticate & get JWT   |
| POST   | /api/register      | Public   | Register new user        |
| GET    | /api/verify        | JWT      | Verify token validity    |
| GET    | /api/data          | JWT+RBAC | Access protected data    |
| GET    | /api/admin/users   | Admin    | List all users           |
| DELETE | /api/admin/users/x | Admin    | Deactivate a user        |
| GET    | /api/gateway/logs  | Admin    | View request logs        |
| GET    | /api/gateway/stats | Admin    | Gateway statistics       |

## Future Phases (Upgrades)

- **Phase 2 (50%):** Database integration (SQLite/PostgreSQL), attack detection (SQL injection, XSS, brute force)
- **Phase 3 (75%):** IP blacklisting, anomaly detection, webhook alerts, HTTPS/TLS
- **Phase 4 (100%):** ML-based threat detection, real-time dashboard, Docker deployment, comprehensive testing

## Tech Stack

- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Backend:** Python 3.10+, FastAPI, python-jose (JWT), passlib (bcrypt), slowapi (rate limiting)
