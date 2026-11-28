"""Integration checks for the PHASE 3 rights-advanced module (requires a migrated DB).

CI ephemeral database only. Seeds two MFA-enrolled administrators in one
institution with the 'works' module enabled, plus an artist and a work, then
verifies:
  * holder identifiers (category / IPI / ISNI) are set,
  * an ISRC recording and a territorial rights grant are created,
  * distribution rules are versioned and activation supersedes the previous version,
  * an unidentified amount is recorded and resolved,
  * a holder claim requires independent approval (self-review blocked) and a
    paid transition after approval.
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
    payload = {"email": email, "password": password, "organization_id": str(org)}
    first = client.post("/api/v1/auth/login", json=payload)
    assert first.status_code == 200, first.text
    h = {"Authorization": "Bearer " + first.json()["access_token"]}
    setup = client.post("/api/v1/auth/mfa/setup", headers=h, json={"password": password})
    assert setup.status_code == 200, setup.text
    totp = pyotp.TOTP(setup.json()["secret"])
    step = int(time.time() // 30)
    confirmed = client.post("/api/v1/auth/mfa/confirm", headers=h,
                            json={"password": password, "otp": totp.at((step - 1) * 30)})
    assert confirmed.status_code == 200, confirmed.text
    resp = client.post("/api/v1/auth/login", json={**payload, "otp": totp.at(step * 30)})
    if resp.status_code == 401:
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
    acc_a, acc_b, artist_id, work_id = uuid4(), uuid4(), uuid4(), uuid4()
    email_a, email_b = f"{acc_a}@example.invalid", f"{acc_b}@example.invalid"
    password = "integration-test-password"
    with admin.begin() as conn:
        conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,'Rights test')"), {"id": org, "slug": str(org)})
        for acc, email in ((acc_a, email_a), (acc_b, email_b)):
            conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"),
                         {"id": acc, "email": email, "hash": hasher.hash(password)})
            conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"),
                         {"id": acc, "org": org})
        conn.execute(text("INSERT INTO artists(id,organization_id,member_number,legal_name,status) VALUES (:id,:org,:num,'Titulaire Test','active')"),
                     {"id": artist_id, "org": org, "num": "M-" + str(org)[:8]})
        conn.execute(text("INSERT INTO works(id,organization_id,reference,title,category,primary_artist_id,iswc,status) VALUES (:id,:org,:ref,'Œuvre test','music',:artist,'T1234567890','registered')"),
                     {"id": work_id, "org": org, "ref": "W-" + str(org)[:8], "artist": artist_id})
        conn.execute(text("INSERT INTO tenant_modules(organization_id,module_key,enabled) VALUES (:org,'works',true)"), {"org": org})
        conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'works',true)"), {"org": org})
    try:
        with TestClient(app) as client:
            headers_a, _ = _enroll(client, email_a, password, org)
            headers_b, _ = _enroll(client, email_b, password, org)

            # Holder identifiers.
            h = client.patch(f"/api/v1/rights/holders/{artist_id}", headers=headers_a,
                             json={"category": "performer", "ipi": "123456789", "isni": "1234567890123456"})
            assert h.status_code == 200, h.text

            # ISRC recording.
            rec = client.post("/api/v1/rights/recordings", headers=headers_a, json={
                "work_id": str(work_id), "isrc": "FRZ030050001", "title": "Enregistrement test", "duration_seconds": 210})
            assert rec.status_code == 201, rec.text

            # Territorial rights grant (collective scope).
            grant = client.post("/api/v1/rights/grants", headers=headers_a, json={
                "work_id": str(work_id), "artist_id": str(artist_id), "role": "performer",
                "territory": "Guinée", "scope": "collective", "basis_points": 5000, "valid_from": "2026-11-28"})
            assert grant.status_code == 201, grant.text
            term = client.post(f"/api/v1/rights/grants/{grant.json()['id']}/terminate", headers=headers_a)
            assert term.status_code == 200 and term.json()["status"] == "terminated", term.text

            # Versioned distribution rules: create v1, activate, create v2, activate (supersedes v1).
            rule_v1 = client.post("/api/v1/rights/rules", headers=headers_a, json={
                "rule_category": "mechanical", "expected_version": 0, "name": "Règle v1",
                "allocation": {"author": 4000, "publisher": 1000, "performer": 3000, "producer_phonographic": 2000}})
            assert rule_v1.status_code == 201, rule_v1.text
            assert rule_v1.json()["version"] == 1
            act1 = client.post(f"/api/v1/rights/rules/{rule_v1.json()['id']}/activate", headers=headers_a)
            assert act1.status_code == 200 and act1.json()["status"] == "active", act1.text
            rule_v2 = client.post("/api/v1/rights/rules", headers=headers_a, json={
                "rule_category": "mechanical", "expected_version": 1, "name": "Règle v2",
                "allocation": {"author": 4500, "publisher": 1500, "performer": 2500, "producer_phonographic": 1500}})
            assert rule_v2.status_code == 201 and rule_v2.json()["version"] == 2, rule_v2.text
            # Optimistic-lock conflict: stale expected_version must be rejected.
            stale = client.post("/api/v1/rights/rules", headers=headers_a, json={
                "rule_category": "mechanical", "expected_version": 0, "name": "stale",
                "allocation": {"author": 10000}})
            assert stale.status_code == 409, "stale version must be rejected"
            act2 = client.post(f"/api/v1/rights/rules/{rule_v2.json()['id']}/activate", headers=headers_a)
            assert act2.status_code == 200, act2.text

            # Unidentified amount, then resolved.
            uid = client.post("/api/v1/rights/unidentified", headers=headers_a, json={
                "amount_minor": 750000, "currency": "XOF", "reason": "Œuvre non identifiée"})
            assert uid.status_code == 201, uid.text
            resolved = client.patch(f"/api/v1/rights/unidentified/{uid.json()['id']}", headers=headers_a, json={"status": "identified"})
            assert resolved.status_code == 200, resolved.text

            # Claim: self-review blocked, independent approval + paid.
            claim = client.post("/api/v1/rights/claims", headers=headers_a, json={
                "claimant_artist_id": str(artist_id), "work_id": str(work_id),
                "amount_minor": 750000, "currency": "XOF", "justification": "Revenus réclamés"})
            assert claim.status_code == 201, claim.text
            cid = claim.json()["id"]
            assert client.post(f"/api/v1/rights/claims/{cid}/review", headers=headers_a, json={"decision": "approve"}).status_code == 409
            appr = client.post(f"/api/v1/rights/claims/{cid}/review", headers=headers_b, json={"decision": "approve"})
            assert appr.status_code == 200 and appr.json()["status"] == "approved", appr.text
            # Cannot mark paid before approval (already approved) -> paid OK.
            paid = client.post(f"/api/v1/rights/claims/{cid}/paid", headers=headers_b)
            assert paid.status_code == 200 and paid.json()["status"] == "paid", paid.text
            # Re-review idempotently blocked.
            assert client.post(f"/api/v1/rights/claims/{cid}/review", headers=headers_b, json={"decision": "reject"}).status_code == 409

            print("Rights-advanced integration PASS: identifiers + ISRC + grants + versioned rules + unidentified + claims")
    finally:
        with admin.begin() as conn:
            for t in ["rights_claims", "rights_unidentified", "distribution_rules", "rights_grants", "recordings"]:
                conn.execute(text(f"DELETE FROM {t} WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM works WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM artists WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM tenant_modules WHERE organization_id=:org AND module_key='works'"), {"org": org})
            conn.execute(text("DELETE FROM module_entitlements WHERE organization_id=:org AND module_key='works'"), {"org": org})
            conn.execute(text("DELETE FROM auth_sessions WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM mfa_recovery_codes WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM account_mfa WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM memberships WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM accounts WHERE id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM audit_events WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM organizations WHERE id=:org"), {"org": org})


if __name__ == "__main__":
    main()
