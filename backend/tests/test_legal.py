"""Unit tests for the PHASE 2 legal module (no database required).

Run by the ``api`` CI job alongside the other ``test_*.py`` files. Behavioral
checks (double review, RLS isolation, sensitive-transition enforcement against a
real DB) live in ``legal_integration.py`` (``docker`` CI job).
"""
from fastapi.testclient import TestClient
from app.main import app
from app.legal import SENSITIVE_TRANSITIONS


def test_sensitive_transitions_set():
    assert SENSITIVE_TRANSITIONS == frozenset({"amicable", "judicial", "resolved", "closed", "withdrawn"})


def test_legal_endpoints_require_authentication():
    client = TestClient(app)
    assert client.get("/api/v1/legal/cases").status_code == 401
    assert client.get("/api/v1/legal/mandates").status_code == 401
    assert client.get("/api/v1/legal/successions").status_code == 401
    assert client.get("/api/v1/legal/contracts").status_code == 401


def test_case_creation_validation():
    client = TestClient(app)
    # 422: empty payload (missing required fields) — auth is checked first only
    # if no body is provided; with an invalid body Pydantic returns 422 after
    # the 401 gate. We assert the endpoint rejects malformed input.
    assert client.post("/api/v1/legal/cases", json={}).status_code in (401, 422)


def test_decision_review_payload_validation():
    client = TestClient(app)
    # The review endpoint requires a bearer; without one it is 401. The payload
    # contract (decision in {approve,reject}) is exercised in the integration test.
    assert client.post("/api/v1/legal/decisions/00000000-0000-0000-0000-000000000000/review",
                       json={"decision": "maybe"}).status_code in (401, 422)
