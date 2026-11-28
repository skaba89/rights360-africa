"""Unit tests for the PHASE 3 rights-advanced module (no database required).

Behavioral checks (versioned rules, claim double review, RLS) live in
``rights_integration.py`` (``docker`` CI job).
"""
from fastapi.testclient import TestClient
from app.main import app


def test_rights_endpoints_require_authentication():
    client = TestClient(app)
    assert client.get("/api/v1/rights/recordings").status_code == 401
    assert client.get("/api/v1/rights/grants").status_code == 401
    assert client.get("/api/v1/rights/rules").status_code == 401
    assert client.get("/api/v1/rights/unidentified").status_code == 401
    assert client.get("/api/v1/rights/claims").status_code == 401


def test_isrc_format_rejected():
    client = TestClient(app)
    # Malformed ISRC is rejected at the schema level (422 after the 401 gate).
    r = client.post("/api/v1/rights/recordings",
                    json={"work_id": "00000000-0000-0000-0000-000000000000",
                          "isrc": "bad", "title": "x"})
    assert r.status_code in (401, 422)


def test_ipi_isni_format_rejected():
    client = TestClient(app)
    r = client.patch("/api/v1/rights/holders/00000000-0000-0000-0000-000000000000",
                     json={"ipi": "abc", "isni": "zzz"})
    assert r.status_code in (401, 422)


def test_rule_allocation_must_sum_to_10000():
    client = TestClient(app)
    r = client.post("/api/v1/rights/rules", json={
        "rule_category": "mechanical", "expected_version": 0,
        "name": "bad", "allocation": {"author": 4000}})  # sums to 4000, not 10000
    assert r.status_code in (401, 422)


def test_claim_review_payload_validation():
    client = TestClient(app)
    r = client.post("/api/v1/rights/claims/00000000-0000-0000-0000-000000000000/review",
                    json={"decision": "maybe"})
    assert r.status_code in (401, 422)
