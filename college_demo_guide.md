# 🎓 Zero Trust API Gateway - Project Review Demo Guide

This guide contains the best features of your Zero Trust API Gateway to show off during your college project review. Follow these scenarios step-by-step to impress your professors!

---

## 🟢 Demo 1: The "Zero Trust" Authentication Flow (MFA)
*Showcases how the system enforces strict identity verification, refusing to trust just a password.*

1. **Setup**: Go to your Profile (`/frontend/profile.html`) and **Enable MFA**. Scan the QR code with Google Authenticator.
2. **Action**: Log out, then try to log back in using your Email/Password.
3. **What happens**: The system **intercepts** the login. Instead of letting you into the dashboard, it slides in a Two-Factor Authentication prompt.
4. **Action**: Enter the 6-digit TOTP code from your phone.
5. **The Magic**: Explain that the backend issues a temporary *unverified* JWT first. Only when the TOTP code is verified does it issue a fully trusted JWT. The API strictly blocks the unverified token from accessing any real data.

---

## 🟡 Demo 2: Web Application Firewall (WAF) SQL Injection Block
*Showcases active traffic inspection and immediate threat neutralization.*

1. **Setup**: Ensure you are logged in so you have a valid token (otherwise you just get a generic 401 Unauthorized).
2. **Action**: Open your browser and try to access a URL with a malicious payload, simulating a hacker trying to bypass authentication:
   `http://127.0.0.1:8000/auth/me?q=1'%20OR%20'1'='1`
3. **What happens**: You immediately get a **403 Forbidden** with `{"detail": "WAF Blocked: Malicious payload detected"}`.
4. **The Magic**: Show the **Admin Panel -> Audit Logs**. Point out the event logged as `sqli` with a Status of **Blocked**. Explain that the middleware intercepts the request *before* it ever reaches the database or the routing logic.

---

## 🔴 Demo 3: Adaptive Risk Scoring (The "High Risk" Block)
*Showcases the intelligent, behavioral analysis engine that scores users dynamically.*

The Risk Engine scores traffic based on Identity (30%), Behavior/Rate (40%), and Request Patterns (30%). To show a "Critical Risk" block, we need to act like a noisy automated hacking tool.

1. **Action**: Open your terminal/command prompt.
2. **Run the Hacker Script**: Run the included python script to simulate a brute-force or scanner attack:
   `python simulate_attack.py`
3. **What happens**: The script will fire dozens of requests per second using an invalid token and a suspicious User-Agent (`sqlmap`). 
4. **The Magic**: The first few requests will return `401 Unauthorized` (Risk = Medium). But within a second, the Adaptive Risk Score will shoot past **0.80**, and the system will actively **Block** the IP address with a `403 Request blocked: risk score too high`.
5. **Admin Panel**: Go to the **Admin Panel -> Dashboard**. Show the **Current Risk Score** gauge, and show the blocked requests in the **Audit Logs** labeled as `high_risk_request`.

---

## 🔵 Demo 4: Reverse Proxy Engine
*Showcases how the Gateway actually protects backend microservices.*

1. **Action**: Open a terminal and run the mock microservice:
   `python tests/mock_server.py`
2. **Action**: Using a tool like Postman or your browser, try to hit `http://127.0.0.1:8000/api/v1/data`. 
3. **What happens**: Without a token, you are blocked.
4. **Action**: To pass your token in the browser, go to your Dashboard, open the **Developer Tools** (Press `F12`), go to the **Console** tab, and run this Javascript command:
   ```javascript
   fetch("/api/v1/data", { headers: { "Authorization": "Bearer " + localStorage.getItem("token") } })
     .then(r => r.json()).then(console.log);
   ```
5. **The Magic**: The console will instantly print the `{"message": "Hello from the backend microservice!"}` JSON response! The API Gateway intercepted the JS request, validated your token and MFA, securely proxied it to `127.0.0.1:8001`, and returned the data. Check the **Audit Logs** to see it logged as `proxied`.

---

### Tips for your Presentation:
* **Start with the Admin Dashboard**: It looks highly professional. The dynamic tables and real-time logs will instantly grab attention.
* **Talk about "Zero Trust"**: Remind them that the core concept of Zero Trust is *"Never Trust, Always Verify"*. Point out how every single request is verified for MFA, scanned by the WAF, and evaluated by the Risk Engine.
