# Zero Trust Secure API Gateway with Attack Detection

## Overview

This project is a secure API Gateway built using the Zero Trust approach. The idea behind Zero Trust is simple: no request is trusted by default, whether it comes from inside or outside the system.

The gateway sits between the client and backend services and checks every request for authentication, authorization, and possible threats. It also includes a machine learning component that helps detect suspicious or malicious API usage patterns.

The goal of this project is to provide a secure and scalable way to manage API traffic while protecting applications from common attacks.

---

## Features

* User authentication using JWT tokens
* OAuth login support (Google and GitHub)
* Zero Trust based request validation
* API routing through a centralized gateway
* Rate limiting to control excessive requests
* Machine learning based attack detection
* Logging and monitoring of incoming requests
* Scalable structure suitable for microservices

---

## Tech Stack

Backend

* Python
* FastAPI

Frontend

* HTML
* CSS
* JavaScript

Security

* JWT Authentication
* OAuth (Google, GitHub)
* Rate Limiting

Machine Learning

* Scikit-learn (for attack detection)

---

## Project Structure

frontend
Contains login page and basic UI

backend
Contains main application logic

backend/gateway
Handles request routing and validation

backend/auth
Handles authentication and token generation

backend/ml_model
Contains logic for attack detection

backend/routes
Defines API endpoints

logs
Stores request logs

requirements.txt
Project dependencies

---

## How to Run the Project

Clone the repository
git clone https://github.com/your-username/zero-trust-secure-api-gateway.git

Go to the project folder
cd zero-trust-secure-api-gateway

Create a virtual environment
python -m venv venv

Activate the environment
Windows: venv\Scripts\activate
Linux/Mac: source venv/bin/activate

Install dependencies
pip install -r requirements.txt

Run the backend server
uvicorn main:app --reload

Open the frontend
Open login.html in your browser or use Live Server

---

## How It Works

1. The user logs in using email/password or OAuth
2. A JWT token is generated after successful login
3. Every request goes through the API Gateway
4. The gateway verifies the token
5. The request is analyzed for suspicious behavior
6. If the request is safe, it is forwarded to the backend
7. If not, it is blocked

---

## Attack Detection

The system uses a machine learning model to identify unusual patterns in API requests. It checks things like request frequency, payload behavior, and access patterns.

This helps in detecting:

* brute force attempts
* unusual traffic spikes
* suspicious API usage

---

## Use Cases

* Securing microservices architecture
* Protecting public APIs
* Backend security for web applications
* Systems handling sensitive data

---

## Future Improvements

* Dashboard for monitoring traffic and attacks
* More advanced machine learning models
* Docker support for deployment
* Alert system for suspicious activity

---

## Author

Arshadali Athani
