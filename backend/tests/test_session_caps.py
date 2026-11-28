"""Unit tests for PHASE 1 session hardening (no database required).

Run by the ``api`` CI job alongside the other ``test_*.py`` files. These cover
the pure logic and auth-gating of the new endpoints; the behavioral cap is
exercised against a real database by ``session_integration.py`` in the
``docker`` CI job.
"""
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.main import app
from app.auth import MAX_SESSIONS, require_admin_mfa


def test_max_sessions_is_sane():
    assert isinstance(MAX_SESSIONS, int)
    assert 1 <= MAX_SESSIONS <= 10, "MAX_SESSIONS must be small and bounded"


def test_require_admin_mfa_blocks_non_admin():
    with pytest.raises(HTTPException) as exc:
        require_admin_mfa({"role": "manager", "mfa_enabled": True})
    assert exc.value.status_code == 403


def test_require_admin_mfa_blocks_admin_without_mfa():
    with pytest.raises(HTTPException) as exc:
        require_admin_mfa({"role": "admin", "mfa_enabled": False})
    assert exc.value.status_code == 403


def test_require_admin_mfa_allows_admin_with_mfa():
    identity = {"role": "admin", "mfa_enabled": True, "account_id": "any"}
    assert require_admin_mfa(identity) is identity


def test_sessions_endpoints_require_authentication():
    client = TestClient(app)
    assert client.get("/api/v1/auth/sessions").status_code == 401
    assert client.post("/api/v1/auth/sessions/revoke-others").status_code == 401


def test_login_validation_unchanged():
    # Regression guard: the login payload contract is not altered by the patch.
    assert TestClient(app).post("/api/v1/auth/login", json={}).status_code == 422
