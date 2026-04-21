import pytest
from fastapi.testclient import TestClient
from gateway.main import app

@pytest.fixture
def client():
    return TestClient(app)
