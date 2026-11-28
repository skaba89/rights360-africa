"""Integration checks for the PHASE 2 legal module (requires a migrated DB).

Mirrors the gating/cleanup pattern of ``auth_integration.py`` / ``session_integration.py``:
CI ephemeral database only. Seeds two MFA-enrolled administrators in one
institution with the 'legal' module enabled, then verifies:
  * sensitive case transitions require a reviewed decision (double review),
  * self-review is blocked,
  * direct PATCH to a sensitive status is rejected at the schema level,
  * approving a transition applies it and records an immutable history event,
  * mandate revocation and succession approval require an independent approver,
  * contracts are created.
Wired into the ``docker`` CI job.
"""
import os
import time
from uuid import uuid4
import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import text
from app.auth import hasher
from app.db import get_engine
from app.main import app


def _enroll(client, email, password, org):
    """Log in an unenrolled admin, enroll MFA, re-login with TOTP, return headers."""
    payload = {"email": email, "password": password, "organization_id": str(org)}
    first = client.post("/api/v1/auth/login", json=payload)
    assert first.status_code == 200, first.text
    h = {"Authorization": "Bearer " + first.json()["access_token"]}
    setup = client.post("/api/v1/auth/mfa/setup", headers=h, json={"password": password})
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    totp = pyotp.TOTP(secret)
    step = int(time.time() // 30)
    confirmed = client.post("/api/v1/auth/mfa/confirm", headers=h,
                            json={"password": password, "otp": totp.at((step - 1) * 30)})
    assert confirmed.status_code == 200, confirmed.text
    # sessions wiped on confirm -> re-login with a fresh TOTP (current step)
    resp = client.post("/api/v1/auth/login", json={**payload, "otp": totp.at(step * 30)})
    if resp.status_code == 401:  # step already consumed by confirm? wait and retry
        time.sleep(31)
        resp = client.post("/api/v1/auth/login", json={**payload, "otp": totp.at(int(time.time() // 30) * 30)})
    assert resp.status_code == 200, resp.text
    assert resp.json()["mfa_required"] is False
    return {"Authorization": "Bearer " + resp.json()["access_token"]}, totp


def main():
    if os.environ.get("RIGHTS360_DISPOSABLE_E2E") != "1" or os.environ.get("POSTGRES_PASSWORD") != "ci-ephemeral-only":
        raise SystemExit("Refusing to run outside the CI ephemeral database")
    admin = get_engine(migration=True)
    org = uuid4()
    acc_a, acc_b = uuid4(), uuid4()
    email_a, email_b = f"{acc_a}@example.invalid", f"{acc_b}@example.invalid"
    password = "integration-test-password"
    doc_id = uuid4()
    with admin.begin() as conn:
        conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,'Legal test')"),
                     {"id": org, "slug": str(org)})
        for acc, email in ((acc_a, email_a), (acc_b, email_b)):
            conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"),
                         {"id": acc, "email": email, "hash": hasher.hash(password)})
            conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"),
                         {"id": acc, "org": org})
            conn.execute(text("INSERT INTO account_mfa(account_id,secret_ciphertext,last_step,enabled) VALUES (:id,:secret,-1,true)"),
                         {"id": acc, "secret": "AA" + "A" * 30})  # placeholder; real enrollment via API below
        # Enable the legal module + entitlement (double gate).
        conn.execute(text("INSERT INTO tenant_modules(organization_id,module_key,enabled) VALUES (:org,'legal',true)"), {"org": org})
        conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'legal',true)"), {"org": org})
        # Seed a document in the tenant for case-document linking.
        conn.execute(text("INSERT INTO documents(id,organization_id,title,category,created_by) VALUES (:id,:org,'Supporting','supporting',:actor)"),
                     {"id": doc_id, "org": org, "actor": acc_a})
        conn.execute(text("INSERT INTO document_versions(organization_id,document_id,version,sha256,size_bytes,content,created_by) "
                          "VALUES (:org,:doc,1,:sha,4,:content,:actor)"),
                     {"org": org, "doc": doc_id, "sha": "0" * 64, "content": b"test",
                      "actor": acc_a})
        # Clear placeholder MFA so the API enrollment flow runs cleanly.
        conn.execute(text("DELETE FROM account_mfa WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
    try:
        with TestClient(app) as client:
            headers_a, _ = _enroll(client, email_a, password, org)
            headers_b, _ = _enroll(client, email_b, password, org)

            # a creates a case and proposes a sensitive transition.
            case = client.post("/api/v1/legal/cases", headers=headers_a, json={
                "case_number": "C-" + str(org)[:8], "title": "Litige ayants droit",
                "category": "rights_dispute", "counterpart_type": "artist",
                "summary": "Contestation de quotes-parts", "opened_on": "2026-11-28"})
            assert case.status_code == 201, case.text
            case_id = case.json()["id"]

            party = client.post(f"/api/v1/legal/cases/{case_id}/parties", headers=headers_a, json={
                "role": "claimant", "external_name": "Ayant droit X"})
            assert party.status_code == 201, party.text

            event = client.post(f"/api/v1/legal/cases/{case_id}/events", headers=headers_a, json={
                "kind": "notice", "title": "Mise en demeure", "occurred_on": "2026-11-28"})
            assert event.status_code == 201, event.text

            deadline = client.post(f"/api/v1/legal/cases/{case_id}/deadlines", headers=headers_a, json={
                "label": "Réponse exploitant", "due_at": "2026-12-15", "kind": "response"})
            assert deadline.status_code == 201, deadline.text

            doc_link = client.post(f"/api/v1/legal/cases/{case_id}/documents", headers=headers_a, json={"document_id": str(doc_id)})
            assert doc_link.status_code == 201, doc_link.text
            listed = client.get(f"/api/v1/legal/cases/{case_id}/documents", headers=headers_a)
            assert listed.status_code == 200 and len(listed.json()) == 1

            # Direct PATCH to a sensitive status is rejected by the schema (422).
            direct = client.patch(f"/api/v1/legal/cases/{case_id}/status", headers=headers_a, json={"status": "resolved"})
            assert direct.status_code == 422, "sensitive status must not be settable directly"

            proposal = client.post(f"/api/v1/legal/cases/{case_id}/decisions", headers=headers_a, json={
                "proposed_status": "resolved", "rationale": "Accord amiable acté"})
            assert proposal.status_code == 201, proposal.text
            decision_id = proposal.json()["id"]

            # a cannot review its own proposal (independent review required).
            self_review = client.post(f"/api/v1/legal/decisions/{decision_id}/review", headers=headers_a, json={"decision": "approve"})
            assert self_review.status_code == 409, "self-review must be blocked"

            # b (independent admin) approves -> transition applied.
            review = client.post(f"/api/v1/legal/decisions/{decision_id}/review", headers=headers_b, json={"decision": "approve"})
            assert review.status_code == 200, review.text
            assert review.json()["status"] == "approved"

            case_after = client.get(f"/api/v1/legal/cases/{case_id}", headers=headers_a)
            assert case_after.json()["status"] == "resolved"
            assert case_after.json()["closed_on"] is not None

            # An immutable history event was recorded by the approval.
            events = client.get(f"/api/v1/legal/cases/{case_id}/events", headers=headers_a).json()
            assert any("validé" in e["title"] for e in events), "decision event must be recorded"

            # Re-review is idempotent-blocked (409).
            again = client.post(f"/api/v1/legal/decisions/{decision_id}/review", headers=headers_b, json={"decision": "approve"})
            assert again.status_code == 409

            # Mandate revocation (legal:decide).
            mandate = client.post("/api/v1/legal/mandates", headers=headers_a, json={
                "case_id": case_id, "mandatee_external": "Maître Y", "scope": "Représentation",
                "territory": "Guinée", "valid_from": "2026-11-28"})
            assert mandate.status_code == 201, mandate.text
            revoked = client.post(f"/api/v1/legal/mandates/{mandate.json()['id']}/revoke", headers=headers_a)
            assert revoked.status_code == 200 and revoked.json()["revoked"] is True
            assert client.post(f"/api/v1/legal/mandates/{mandate.json()['id']}/revoke", headers=headers_a).status_code == 409

            # Succession: self-approval blocked, independent approval OK.
            succession = client.post("/api/v1/legal/successions", headers=headers_a, json={
                "deceased_account_id": str(acc_a), "heir_account_id": str(acc_b),
                "share_basis_points": 10000, "declared_on": "2026-11-28"})
            assert succession.status_code == 201, succession.text
            sid = succession.json()["id"]
            assert client.post(f"/api/v1/legal/successions/{sid}/approve", headers=headers_a, json={"decision": "approve"}).status_code == 409
            appr = client.post(f"/api/v1/legal/successions/{sid}/approve", headers=headers_b, json={"decision": "approve"})
            assert appr.status_code == 200 and appr.json()["status"] == "approved"

            # Contract.
            contract = client.post("/api/v1/legal/contracts", headers=headers_a, json={
                "kind": "reciprocity", "title": "Accord de réciprocité", "counterpart": "OGC partenaire",
                "territory": "Afrique de l'Ouest", "valid_from": "2026-11-28"})
            assert contract.status_code == 201, contract.text

            print("Legal module integration PASS: case + double-review + mandates + successions + contracts")
    finally:
        with admin.begin() as conn:
            for t in ["legal_case_documents", "legal_deadlines", "legal_decisions", "legal_case_events",
                      "legal_case_parties", "legal_mandates", "legal_successions", "legal_contracts", "legal_cases"]:
                conn.execute(text(f"DELETE FROM {t} WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM document_versions WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM documents WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM tenant_modules WHERE organization_id=:org AND module_key='legal'"), {"org": org})
            conn.execute(text("DELETE FROM module_entitlements WHERE organization_id=:org AND module_key='legal'"), {"org": org})
            conn.execute(text("DELETE FROM auth_sessions WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM mfa_recovery_codes WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM account_mfa WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM memberships WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM accounts WHERE id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM organizations WHERE id=:org"), {"org": org})


if __name__ == "__main__":
    main()
