"""Unit tests for the PHASE 5 payments module (no database required).

Run by the ``api`` CI job. Covers pure logic + auth-gating; the behavioral
flow (execute, idempotency, webhook HMAC, reconciliation, DSIG gate) is
exercised against a real database by ``payments_integration.py`` in the
``docker`` CI job.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.payments import (
    ProviderData, BeneficiaryData, ExecuteData, ReconcileData, _payout_state,
)


def test_provider_validation():
    p = ProviderData(provider="orange_money")
    assert p.mode == "sandbox" and p.enabled is True
    with pytest.raises(ValueError):
        ProviderData(provider="wave")  # unknown provider
    with pytest.raises(ValueError):
        ProviderData(provider="orange_money", mode="production")  # bad mode


def test_beneficiary_validation():
    b = BeneficiaryData(artist_id="00000000-0000-0000-0000-000000000001",
                        channel="orange_money", msisdn="22507070707")
    assert b.msisdn == "22507070707"
    with pytest.raises(ValueError):
        BeneficiaryData(artist_id="00000000-0000-0000-0000-000000000001",
                        channel="orange_money", msisdn="ABC123")  # non-digit msisdn
    with pytest.raises(ValueError):
        BeneficiaryData(artist_id="00000000-0000-0000-0000-000000000001",
                        channel="orange_money")  # no msisdn/iban/account
    with pytest.raises(ValueError):
        BeneficiaryData(artist_id="00000000-0000-0000-0000-000000000001",
                        channel="cash")  # bad channel


def test_execute_idempotency_key_format():
    e = ExecuteData(provider="mtn_momo", beneficiary_id="00000000-0000-0000-0000-000000000002",
                    idempotency_key="key-Abc123_X")
    assert e.provider == "mtn_momo"
    for bad in ("short", "x" * 65, "with space", "symb@l"):
        with pytest.raises(ValueError):
            ExecuteData(provider="mtn_momo", beneficiary_id="00000000-0000-0000-0000-000000000002", idempotency_key=bad)


def test_payout_state_machine():
    assert _payout_state([]) == "pending"
    assert _payout_state([{"decision": "approve"}]) == "pending"
    assert _payout_state([{"decision": "approve"}, {"decision": "approve"}]) == "approved_for_review_only"
    assert _payout_state([{"decision": "approve"}, {"decision": "approve"}, {"decision": "reject"}]) == "rejected"


def test_reconcile_validation():
    r = ReconcileData(attempt_id="00000000-0000-0000-0000-000000000003",
                      webhook_id="00000000-0000-0000-0000-000000000004")
    assert r.note is None


def test_payments_routes_require_auth():
    # Read endpoints reject unauthenticated requests with 401.
    for path in ("/api/v1/payments/providers", "/api/v1/payments/beneficiaries",
                 "/api/v1/payments/attempts", "/api/v1/payments/reconciliations",
                 "/api/v1/payments/execution-status"):
        assert TestClient(app).get(path).status_code == 401, path
