import pytest
from fastapi.testclient import TestClient

def test_register_user(client: TestClient):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "test@example.com",
            "username": "testuser",
            "password": "testpass123",
            "full_name": "Test User"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["username"] == "testuser"

def test_login_user(client: TestClient):
    # First register a user
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "test2@example.com",
            "username": "testuser2",
            "password": "testpass123"
        }
    )
    
    # Then login
    response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "test2@example.com",
            "password": "testpass123"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_read_current_user(client: TestClient):
    # Register and login
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "test3@example.com",
            "username": "testuser3",
            "password": "testpass123",
            "full_name": "Test User 3"
        }
    )
    
    login_response = client.post(
        "/api/v1/auth/login",
        data={
            "username": "test3@example.com",
            "password": "testpass123"
        }
    )
    token = login_response.json()["access_token"]
    
    # Get current user
    response = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test3@example.com"
    assert data["username"] == "testuser3"
