"""Integration checks for PHASE 1 session hardening (requires a migrated DB).

Mirrors the gating and self-cleaning pattern of ``auth_integration.py``: only
runs against the CI ephemeral database, seeds an admin, enrolls MFA, then
verifies the concurrent-session cap, the /sessions diagnostic endpoint, and the
revoke-others endpoint. Wired into the ``docker`` CI job.

Run in CI:
    docker compose run --rm --no-deps -T -e RIGHTS360_DISPOSABLE_E2E=1 \
      -v "${PWD}/backend:/workspace:ro" -w /workspace migrate \
      sh -c 'PYTHONPATH=/workspace python tests/session_integration.py'
"""
import os
from uuid import uuid4
import pyotp
import time
from fastapi.testclient import TestClient
from sqlalchemy import text
from app.auth import hasher, MAX_SESSIONS
from app.db import get_engine
from app.main import app


def main():
    if os.environ.get("RIGHTS360_DISPOSABLE_E2E") != "1" or os.environ.get("POSTGRES_PASSWORD") != "ci-ephemeral-only":
        raise SystemExit("Refusing to run outside the CI ephemeral database")
    admin = get_engine(migration=True)
    org, account = uuid4(), uuid4()
    email = f"{account}@example.invalid"
    password = "integration-test-password"
    with admin.begin() as conn:
        conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,'Session cap test')"),
                     {"id": org, "slug": str(org)})
        conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"),
                     {"id": account, "email": email, "hash": hasher.hash(password)})
        conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"),
                     {"id": account, "org": org})
    try:
        with TestClient(app) as client:
            payload = {"email": email, "password": password, "organization_id": str(org)}
            # Enroll MFA so the admin can reach protected endpoints.
            first = client.post("/api/v1/auth/login", json=payload)
            assert first.status_code == 200, first.text
            headers = {"Authorization": "Bearer " + first.json()["access_token"]}
            setup = client.post("/api/v1/auth/mfa/setup", headers=headers, json={"password": password})
            assert setup.status_code == 200
            totp = pyotp.TOTP(setup.json()["secret"])
            step = int(time.time() // 30)
            confirmed = client.post("/api/v1/auth/mfa/confirm", headers=headers,
                                    json={"password": password, "otp": totp.at((step - 1) * 30)})
            assert confirmed.status_code == 200, confirmed.text

            # Login with OTP MAX_SESSIONS+1 times; the oldest must be revoked.
            tokens = []
            for _ in range(MAX_SESSIONS + 1):
                resp = client.post("/api/v1/auth/login",
                                   json={**payload, "otp": totp.at(int(time.time() // 30) * 30)})
                # The TOTP step may be reused within the same 30s window only if
                # last_step has not advanced; consume_code rejects step <= last_step.
                # To avoid flakiness, sleep across a step boundary if needed.
                if resp.status_code == 401:
                    time.sleep(31)
                    resp = client.post("/api/v1/auth/login",
                                       json={**payload, "otp": totp.at(int(time.time() // 30) * 30)})
                assert resp.status_code == 200, resp.text
                tokens.append(resp.json()["access_token"])

            # The very first token must now be revoked by the cap.
            oldest = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + tokens[0]})
            assert oldest.status_code == 401, "oldest session should have been revoked by the cap"
            # The newest token must still be valid.
            newest = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + tokens[-1]})
            assert newest.status_code == 200

            # /sessions diagnostic: admin-with-MFA can list, no full hash exposed.
            listed = client.get("/api/v1/auth/sessions", headers={"Authorization": "Bearer " + tokens[-1]})
            assert listed.status_code == 200, listed.text
            rows = listed.json()
            assert len(rows) <= MAX_SESSIONS
            for row in rows:
                assert "token_hash" not in row, "full token hash must never be exposed"
                assert len(row["token_suffix"]) == 8

            # revoke-others: every session except the current one becomes invalid.
            revoked = client.post("/api/v1/auth/sessions/revoke-others",
                                  headers={"Authorization": "Bearer " + tokens[-1]})
            assert revoked.status_code == 204
            for tok in tokens[:-1]:
                assert client.get("/api/v1/auth/me",
                                  headers={"Authorization": "Bearer " + tok}).status_code == 401
            assert client.get("/api/v1/auth/me",
                              headers={"Authorization": "Bearer " + tokens[-1]}).status_code == 200
            print("Session cap + diagnostics + revoke-others PASS")
    finally:
        with admin.begin() as conn:
            from app.login_limits import bucket_key
            conn.execute(text("DELETE FROM auth_sessions WHERE account_id=:id"), {"id": account})
            conn.execute(text("DELETE FROM mfa_recovery_codes WHERE account_id=:id"), {"id": account})
            conn.execute(text("DELETE FROM account_mfa WHERE account_id=:id"), {"id": account})
            conn.execute(text("DELETE FROM login_buckets WHERE bucket=:key"),
                         {"key": bucket_key("account", email)})
            conn.execute(text("DELETE FROM memberships WHERE account_id=:id"), {"id": account})
            conn.execute(text("DELETE FROM accounts WHERE id=:id"), {"id": account})
            conn.execute(text("DELETE FROM organizations WHERE id=:id"), {"id": org})


if __name__ == "__main__":
    main()
