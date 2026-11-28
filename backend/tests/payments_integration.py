"""Integration checks for the PHASE 5 payments module (requires a migrated DB).

Mirrors the gating/cleanup pattern of finance_integration.py / rights_integration.py:
CI ephemeral database only. Seeds one MFA-enrolled administrator with the
'finance' module enabled, plus the full payout prerequisite chain (artist ->
work -> operator -> license -> tariff -> declaration -> invoice -> receipt ->
distribution -> distribution_line -> payout_order with 2 independent approvals),
a payment provider (Orange Money, sandbox) and a verified beneficiary. Then
verifies:
  * the DSIG gate reports sandbox (payments_execution_enabled=false),
  * execute runs in sandbox (external_ref=sandbox-..., status=succeeded),
  * re-executing the same payout is idempotent (returns the existing attempt),
  * an authenticated webhook (HMAC) is ingested + matched to the attempt,
  * a bad-signature webhook is rejected (401) and a duplicate is deduped,
  * reconciliation links a webhook to an attempt, and is not repeatable,
  * attempts + reconciliations lists work.
Wired into the ``docker`` CI job.
"""
import hashlib
import hmac
import json
import os
import time
from datetime import date
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
    secret = setup.json()["secret"]
    totp = pyotp.TOTP(secret)
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
    acc_a = uuid4()
    email_a = f"{acc_a}@example.invalid"
    password = "integration-test-password"
    artist = uuid4()
    work = uuid4()
    operator = uuid4()
    lic = uuid4()
    tariff = uuid4()
    decl = uuid4()
    invoice = uuid4()
    receipt = uuid4()
    dist = uuid4()
    payout = uuid4()
    reviewer_b, reviewer_c = uuid4(), uuid4()  # independent approvers (no FK to accounts)
    today = date(2026, 1, 15)
    with admin.begin() as conn:
        conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,'Payments test')"),
                     {"id": org, "slug": str(org)})
        conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"),
                     {"id": acc_a, "email": email_a, "hash": hasher.hash(password)})
        conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"),
                     {"id": acc_a, "org": org})
        # Payout prerequisite chain (11 tables), minimal balanced rows.
        conn.execute(text("INSERT INTO artists(id,organization_id,member_number,legal_name,status) VALUES (:id,:org,:num,'Ayant droit test','active')"),
                     {"id": artist, "org": org, "num": "PAY-" + str(artist)[:6]})
        conn.execute(text("INSERT INTO works(id,organization_id,reference,title,category,primary_artist_id,status) VALUES (:id,:org,:ref,'Oeuvre test','music',:artist,'registered')"),
                     {"id": work, "org": org, "ref": "W-" + str(work)[:6], "artist": artist})
        conn.execute(text("INSERT INTO operators(id,organization_id,reference,name,category) VALUES (:id,:org,:ref,'Operateur test','radio')"),
                     {"id": operator, "org": org, "ref": "O-" + str(operator)[:6]})
        conn.execute(text("INSERT INTO exploitation_licenses(id,organization_id,operator_id,reference,territory,usage_type,starts_on,ends_on,status) VALUES (:id,:org,:op,:ref,'CI','radio',:s,:e,'active')"),
                     {"id": lic, "org": org, "op": operator, "ref": "L-" + str(lic)[:6], "s": today, "e": date(2026, 12, 31)})
        conn.execute(text("INSERT INTO tariffs(id,organization_id,reference,version,category,usage_type,method,currency,rate,starts_on,ends_on) VALUES (:id,:org,:ref,1,'radio','radio','flat','XOF',100,:s,:e)"),
                     {"id": tariff, "org": org, "ref": "T-" + str(tariff)[:6], "s": today, "e": date(2026, 12, 31)})
        conn.execute(text("INSERT INTO work_rights_declarations(id,organization_id,work_id,version,status,created_by) VALUES (:id,:org,:work,1,'draft',:actor)"),
                     {"id": decl, "org": org, "work": work, "actor": acc_a})
        conn.execute(text("INSERT INTO royalty_invoices(id,organization_id,reference,license_id,tariff_id,usage_date,due_on,amount_minor,currency) VALUES (:id,:org,:ref,:lic,:tariff,:d,:due,1000,'XOF')"),
                     {"id": invoice, "org": org, "ref": "I-" + str(invoice)[:6], "lic": lic, "tariff": tariff, "d": today, "due": date(2026, 2, 15)})
        conn.execute(text("INSERT INTO royalty_receipts(id,organization_id,invoice_id,reference,amount_minor,received_on) VALUES (:id,:org,:inv,:ref,1000,:d)"),
                     {"id": receipt, "org": org, "inv": invoice, "ref": "R-" + str(receipt)[:6], "d": today})
        # gross=commission+net (1000=100+900); line sums to net + bps=10000.
        conn.execute(text("INSERT INTO royalty_distributions(id,organization_id,receipt_id,declaration_id,currency,gross_minor,commission_bps,commission_minor,net_minor,created_by) VALUES (:id,:org,:rec,:decl,'XOF',1000,1000,100,900,:actor)"),
                     {"id": dist, "org": org, "rec": receipt, "decl": decl, "actor": acc_a})
        conn.execute(text("INSERT INTO royalty_distribution_lines(organization_id,distribution_id,artist_id,role,basis_points,amount_minor) VALUES (:org,:dist,:artist,'author',10000,900)"),
                     {"org": org, "dist": dist, "artist": artist})
        # Payout order (channel orange_money) + 2 independent approvals.
        conn.execute(text("INSERT INTO payout_orders(id,organization_id,distribution_id,artist_id,channel,amount_minor,currency,created_by) VALUES (:id,:org,:dist,:artist,'orange_money',900,'XOF',:actor)"),
                     {"id": payout, "org": org, "dist": dist, "artist": artist, "actor": acc_a})
        conn.execute(text("INSERT INTO payout_reviews(organization_id,order_id,reviewer_id,decision) VALUES (:org,:payout,:rb,'approve'),(:org,:payout,:rc,'approve')"),
                     {"org": org, "payout": payout, "rb": reviewer_b, "rc": reviewer_c})
        # Payment provider (Orange Money, sandbox) + verified beneficiary.
        conn.execute(text("INSERT INTO payment_providers(id,organization_id,provider,mode,webhook_secret,enabled,created_by) VALUES (:id,:org,'orange_money','sandbox','wh-secret-test',true,:actor)"),
                     {"id": uuid4(), "org": org, "actor": acc_a})
        conn.execute(text("INSERT INTO payment_beneficiaries(id,organization_id,artist_id,channel,msisdn,verified,verified_by,verified_at,created_by) VALUES (:id,:org,:artist,'orange_money','22507070707',true,:actor,now(),:actor)"),
                     {"id": uuid4(), "org": org, "artist": artist, "actor": acc_a})
        # Enable the finance module + entitlement (the payments router gates on it).
        conn.execute(text("INSERT INTO tenant_modules(organization_id,module_key,enabled) VALUES (:org,'finance',true)"), {"org": org})
        conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'finance',true)"), {"org": org})

    try:
        with TestClient(app) as client:
            headers, _ = _enroll(client, email_a, password, org)
            ben_id = client.get("/api/v1/payments/beneficiaries", headers=headers).json()[0]["id"]

            # 1. DSIG gate: sandbox by default.
            st = client.get("/api/v1/payments/execution-status", headers=headers).json()
            assert st["payments_execution_enabled"] is False and st["mode"] == "sandbox", st

            # 2. Execute (sandbox): attempt succeeded, external_ref=sandbox-...
            exec1 = client.post(f"/api/v1/payments/payouts/{payout}/execute", headers=headers, json={
                "provider": "orange_money", "beneficiary_id": ben_id, "idempotency_key": "key-aaaaaaaa"})
            assert exec1.status_code == 201, exec1.text
            assert exec1.json()["status"] == "succeeded", exec1.text
            assert exec1.json()["external_ref"].startswith("sandbox-"), exec1.text
            ext_ref = exec1.json()["external_ref"]

            # 3. Idempotency: re-execute (same payout, different key) -> same attempt.
            exec2 = client.post(f"/api/v1/payments/payouts/{payout}/execute", headers=headers, json={
                "provider": "orange_money", "beneficiary_id": ben_id, "idempotency_key": "key-bbbbbbbb"})
            assert exec2.status_code == 201, exec2.text
            assert exec2.json()["external_ref"] == ext_ref, "re-execute must return the same attempt"

            # 4. Webhook ingestion (HMAC-authenticated) + matched to the attempt.
            body = json.dumps({"event_ref": "evt-001", "external_ref": ext_ref, "status": "succeeded"}).encode()
            sig = hmac.new(b"wh-secret-test", body, hashlib.sha256).hexdigest()
            wh = client.post("/api/v1/payments/webhooks/orange_money", content=body,
                             headers={"X-Signature": sig}, params={"org": str(org)})
            assert wh.status_code == 201, wh.text
            assert wh.json()["matched_attempt_id"] is not None, "webhook must match the attempt by external_ref"
            webhook_id = wh.json()["id"]

            # 5. Bad signature -> 401.
            bad = client.post("/api/v1/payments/webhooks/orange_money", content=body,
                              headers={"X-Signature": "deadbeef"}, params={"org": str(org)})
            assert bad.status_code == 401, bad.text

            # 6. Duplicate event_ref -> deduped.
            dup = client.post("/api/v1/payments/webhooks/orange_money", content=body,
                              headers={"X-Signature": sig}, params={"org": str(org)})
            assert dup.status_code == 201 and dup.json()["status"] == "duplicate", dup.text

            # 7. Reconciliation links the webhook to the attempt; not repeatable.
            attempt_id = exec1.json()["id"]
            rec1 = client.post("/api/v1/payments/reconcile", headers=headers, json={
                "attempt_id": attempt_id, "webhook_id": webhook_id, "note": "matched"})
            assert rec1.status_code == 201, rec1.text
            rec2 = client.post("/api/v1/payments/reconcile", headers=headers, json={
                "attempt_id": attempt_id, "webhook_id": webhook_id})
            assert rec2.status_code == 409, "attempt already reconciled"

            # 8. Lists.
            attempts = client.get("/api/v1/payments/attempts", headers=headers).json()
            assert any(a["id"] == attempt_id for a in attempts), attempts
            recs = client.get("/api/v1/payments/reconciliations", headers=headers).json()
            assert any(r["attempt_id"] == attempt_id for r in recs), recs

            print("Payments module integration PASS: DSIG sandbox gate, execute idempotent, "
                  "webhook HMAC + matching + dedup, reconciliation non-repeatable")
    finally:
        with admin.begin() as conn:
            # Delete in FK-dependency order: payout_orders (beneficiary_id FK)
            # before payment_beneficiaries; attempts before payout_orders.
            for t in ["payment_reconciliations", "payment_webhooks", "payment_attempts"]:
                conn.execute(text(f"DELETE FROM {t} WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM payout_reviews WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM payout_orders WHERE organization_id=:org"), {"org": org})
            for t in ["payment_beneficiaries", "payment_providers"]:
                conn.execute(text(f"DELETE FROM {t} WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM accounting_lines WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM accounting_entries WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM royalty_distribution_lines WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM royalty_distributions WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM royalty_receipts WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM royalty_invoices WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM work_rights_declarations WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM tariffs WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM exploitation_licenses WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM operators WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM works WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM artists WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM audit_events WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM tenant_modules WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM module_entitlements WHERE organization_id=:org AND module_key='finance'"), {"org": org})
            conn.execute(text("DELETE FROM auth_sessions WHERE account_id=:a"), {"a": acc_a})
            conn.execute(text("DELETE FROM mfa_recovery_codes WHERE account_id=:a"), {"a": acc_a})
            conn.execute(text("DELETE FROM account_mfa WHERE account_id=:a"), {"a": acc_a})
            conn.execute(text("DELETE FROM memberships WHERE account_id=:a"), {"a": acc_a})
            conn.execute(text("DELETE FROM accounts WHERE id=:a"), {"a": acc_a})
            conn.execute(text("DELETE FROM organizations WHERE id=:org"), {"org": org})


if __name__ == "__main__":
    main()
