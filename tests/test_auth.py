import pytest
from fastapi.testclient import TestClient
from gateway.main import app

@pytest.fixture
def client():
    """Create test client"""
    return TestClient(app)

def test_register_user(client):
    response = client.post("/auth/register", json={
        "email": "unique1@example.com",
        "username": "unique1user",
        "password": "securepassword123",
        "full_name": "Test User"
    })
    assert response.status_code == 201
    assert response.json()["username"] == "unique1user"

def test_register_duplicate_email(client):
    # Register first user
    client.post("/auth/register", json={
        "email": "dup@example.com",
        "username": "dup1",
        "password": "securepassword123",
        "full_name": "User One"
    })
    
    # Try to register with same email
    response = client.post("/auth/register", json={
        "email": "dup@example.com",
        "username": "dup2",
        "password": "securepassword123",
        "full_name": "User Two"
    })
    assert response.status_code == 400

def test_login_user(client):
    # Register user
    client.post("/auth/register", json={
        "email": "login2@example.com",
        "username": "loginuser2",
        "password": "securepassword123",
        "full_name": "Login User"
    })
    
    # Login with query parameters
    response = client.post("/auth/login?email=login2@example.com&password=securepassword123")
    assert response.status_code == 200
    assert "access_token" in response.json()
