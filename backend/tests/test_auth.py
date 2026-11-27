from fastapi.testclient import TestClient
from app.main import app
from app.auth import hasher, verify_password, digest

def test_password_hash():
    encoded = hasher.hash("example-password-for-test")
    assert encoded.startswith("$argon2id$")
    assert verify_password(encoded, "example-password-for-test")
    assert not verify_password(encoded, "wrong")
    assert not verify_password("invalid", "wrong")

def test_token_digest():
    assert len(digest("test-token")) == 64
    assert digest("test-token") != "test-token"

def test_me_requires_authentication():
    assert TestClient(app).get("/api/v1/auth/me").status_code == 401

def test_login_validation():
    assert TestClient(app).post("/api/v1/auth/login", json={}).status_code == 422
