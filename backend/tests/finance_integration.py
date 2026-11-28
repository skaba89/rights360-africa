"""Integration checks for the PHASE 4 finance/SYSCOHADA module (requires a migrated DB).

Mirrors the gating/cleanup pattern of legal_integration.py / session_integration.py:
CI ephemeral database only. Seeds two MFA-enrolled administrators in one
institution with the 'finance' module enabled, then verifies:
  * the default OHADA chart + 5 generic-key mappings seed idempotently,
  * a journal + fiscal period can be created,
  * a posted accounting entry appears in the SYSCOHADA trial balance (mapped),
  * a contrepassation (reversal) nets the entry out in the trial balance,
  * closing a fiscal period requires >= 2 independent approvals (multi-level),
    rejects a 3rd approval, and blocks reviews after close,
  * withholding tax rules can be created/listed,
  * a beneficiary statement aggregates per-account balances for an artist.
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
    resp = client.post("/api/v1/auth/login", json={**payload, "otp": totp.at(step * 30)})
    if resp.status_code == 401:
        time.sleep(31)
        resp = client.post("/api/v1/auth/login", json={**payload, "otp": totp.at(int(time.time() // 30) * 30)})
    assert resp.status_code == 200, resp.text
    assert resp.json()["mfa_required"] is False
    return {"Authorization": "Bearer " + resp.json()["access_token"]}, totp


def _balance_for(rows, account_code, currency="XOF"):
    for r in rows:
        if r["account_code"] == account_code and r["currency"] == currency:
            return int(r["balance_minor"])
    return None


def main():
    if os.environ.get("RIGHTS360_DISPOSABLE_E2E") != "1" or os.environ.get("POSTGRES_PASSWORD") != "ci-ephemeral-only":
        raise SystemExit("Refusing to run outside the CI ephemeral database")
    admin = get_engine(migration=True)
    org = uuid4()
    acc_a, acc_b = uuid4(), uuid4()
    artist = uuid4()
    email_a, email_b = f"{acc_a}@example.invalid", f"{acc_b}@example.invalid"
    password = "integration-test-password"
    with admin.begin() as conn:
        conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,'Finance test')"),
                     {"id": org, "slug": str(org)})
        for acc, email in ((acc_a, email_a), (acc_b, email_b)):
            conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"),
                         {"id": acc, "email": email, "hash": hasher.hash(password)})
            conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"),
                         {"id": acc, "org": org})
        # An artist for the beneficiary-payable line + statement.
        conn.execute(text("INSERT INTO artists(id,organization_id,member_number,legal_name,status) "
                          "VALUES (:id,:org,:num,'Ayant droit test','active')"),
                     {"id": artist, "org": org, "num": "FIN-" + str(artist)[:6]})
        # Enable the finance module + entitlement (double gate).
        conn.execute(text("INSERT INTO tenant_modules(organization_id,module_key,enabled) VALUES (:org,'finance',true)"), {"org": org})
        conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'finance',true)"), {"org": org})

    try:
        with TestClient(app) as client:
            headers_a, _ = _enroll(client, email_a, password, org)
            headers_b, _ = _enroll(client, email_b, password, org)

            # 1. Seed the default OHADA chart + mappings (idempotent).
            seed = client.post("/api/v1/finance/chart-of-accounts/seed", headers=headers_a)
            assert seed.status_code == 201, seed.text
            assert seed.json()["seeded_mappings"] == 5, seed.text
            # Idempotent: re-seed inserts 0.
            reseed = client.post("/api/v1/finance/chart-of-accounts/seed", headers=headers_a)
            assert reseed.json()["seeded_accounts"] == 0 and reseed.json()["seeded_mappings"] == 0

            chart = client.get("/api/v1/finance/chart-of-accounts", headers=headers_a).json()
            assert any(a["account_code"] == "411000" for a in chart), "411000 Clients must be seeded"
            mappings = client.get("/api/v1/finance/account-mappings", headers=headers_a).json()
            assert {m["generic_key"] for m in mappings} == {"receivable", "royalties_unallocated",
                "cash_unverified", "management_commission", "beneficiary_payable"}

            # 2. Create a journal + a fiscal period.
            journal = client.post("/api/v1/finance/journals", headers=headers_a, json={
                "code": "VTE", "name": "Journal des ventes", "kind": "sales"})
            assert journal.status_code == 201, journal.text
            period = client.post("/api/v1/finance/fiscal-periods", headers=headers_a, json={
                "fiscal_year": 2026, "period_index": 0, "starts_on": "2026-01-01", "ends_on": "2026-12-31"})
            assert period.status_code == 201, period.text
            pid = period.json()["id"]

            # 3. Post a balanced accounting entry directly (source_type='invoice',
            #    no FK on source_id): receivable 1000 debit, royalties_unallocated
            #    500 credit + beneficiary_payable 500 credit (artist). Balanced.
            entry_id = uuid4()
            with admin.begin() as conn:
                conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(org)})
                conn.execute(text("""INSERT INTO accounting_entries(id,organization_id,source_type,source_id,
                    currency,fiscal_period_id,posted_by)
                    VALUES(:id,:org,'invoice',:src,'XOF',:pid,:actor)"""),
                    {"id": entry_id, "org": org, "src": uuid4(), "pid": pid, "actor": acc_a})
                conn.execute(text("""INSERT INTO accounting_lines(organization_id,entry_id,line_no,account_key,artist_id,debit_minor,credit_minor) VALUES
                    (:org,:e,1,'receivable',NULL,1000,0),
                    (:org,:e,2,'royalties_unallocated',NULL,0,500),
                    (:org,:e,3,'beneficiary_payable',:artist,0,500)"""),
                    {"org": org, "e": entry_id, "artist": artist})

            # 4. Trial balance (balance generale): mapped to SYSCOHADA accounts.
            tb = client.get("/api/v1/finance/trial-balance", headers=headers_a).json()
            assert _balance_for(tb, "411000") == 1000, "receivable (411000) debit 1000"
            assert _balance_for(tb, "471000") == -500, "royalties_unallocated (471000) credit 500"
            assert _balance_for(tb, "422000") == -500, "beneficiary_payable (422000) credit 500"

            # 5. Beneficiary statement: artist is owed 500 (credit balance).
            stmt = client.get(f"/api/v1/finance/beneficiaries/{artist}/statement", headers=headers_a).json()
            ben = [r for r in stmt["balances"] if r["account_key"] == "beneficiary_payable"][0]
            assert int(ben["balance_minor"]) == -500, stmt

            # 6. Contrepassation: reverse the entry -> nets out in the trial balance.
            rev = client.post(f"/api/v1/finance/accounting/entries/{entry_id}/reverse", headers=headers_a,
                              json={"reason": "Erreur de saisie"})
            assert rev.status_code == 201, rev.text
            # Reversing twice is blocked (one reversal per entry).
            assert client.post(f"/api/v1/finance/accounting/entries/{entry_id}/reverse", headers=headers_a,
                               json={"reason": "again"}).status_code == 409
            tb2 = client.get("/api/v1/finance/trial-balance", headers=headers_a).json()
            assert _balance_for(tb2, "411000") == 0, "reversal nets receivable to 0"
            assert _balance_for(tb2, "422000") == 0, "reversal nets beneficiary_payable to 0"

            # 7. Multi-level fiscal-period close.
            # 0 approvals -> close rejected (needs 2).
            early = client.post(f"/api/v1/finance/fiscal-periods/{pid}/close", headers=headers_a)
            assert early.status_code == 409, "close without 2 approvals must be rejected"
            # 1st approval (a).
            r1 = client.post(f"/api/v1/finance/fiscal-periods/{pid}/reviews", headers=headers_a,
                             json={"decision": "approve", "rationale": "OK"})
            assert r1.status_code == 201, r1.text
            # Still <2 -> close rejected.
            assert client.post(f"/api/v1/finance/fiscal-periods/{pid}/close", headers=headers_a).status_code == 409
            # 2nd approval (b, independent).
            r2 = client.post(f"/api/v1/finance/fiscal-periods/{pid}/reviews", headers=headers_b,
                             json={"decision": "approve"})
            assert r2.status_code == 201, r2.text
            # 3rd approval blocked (already 2).
            assert client.post(f"/api/v1/finance/fiscal-periods/{pid}/reviews", headers=headers_a,
                               json={"decision": "approve"}).status_code == 409
            # Close now succeeds.
            closed = client.post(f"/api/v1/finance/fiscal-periods/{pid}/close", headers=headers_a)
            assert closed.status_code == 200, closed.text
            # Re-close blocked (already closed).
            assert client.post(f"/api/v1/finance/fiscal-periods/{pid}/close", headers=headers_a).status_code == 409
            # Review after close blocked.
            assert client.post(f"/api/v1/finance/fiscal-periods/{pid}/reviews", headers=headers_b,
                               json={"decision": "approve"}).status_code == 409

            # 8. Withholding tax rules.
            tax = client.post("/api/v1/finance/tax-rules", headers=headers_a, json={
                "category": "performance", "country": "CI", "rate_bps": 2000, "account_code": "422000"})
            assert tax.status_code == 201, tax.text
            rules = client.get("/api/v1/finance/tax-rules", headers=headers_a).json()
            assert any(r["country"] == "CI" and r["rate_bps"] == 2000 for r in rules)

            print("Finance module integration PASS: chart+mappings seed, trial balance, reversal, "
                  "multi-level close, tax rules, beneficiary statement")
    finally:
        with admin.begin() as conn:
            # Delete in FK-dependency order: entries (reversals, lines, entries)
            # before the finance tables they reference (fiscal_periods, journals).
            conn.execute(text("DELETE FROM accounting_reversals WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM accounting_lines WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM accounting_entries WHERE organization_id=:org"), {"org": org})
            for t in ["tax_rules", "account_mappings", "fiscal_period_reviews",
                      "fiscal_periods", "chart_of_accounts", "journals"]:
                conn.execute(text(f"DELETE FROM {t} WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM audit_events WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM artists WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM tenant_modules WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM module_entitlements WHERE organization_id=:org AND module_key='finance'"), {"org": org})
            conn.execute(text("DELETE FROM auth_sessions WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM mfa_recovery_codes WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM account_mfa WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM memberships WHERE account_id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM accounts WHERE id IN (:a,:b)"), {"a": acc_a, "b": acc_b})
            conn.execute(text("DELETE FROM organizations WHERE id=:org"), {"org": org})


if __name__ == "__main__":
    main()
