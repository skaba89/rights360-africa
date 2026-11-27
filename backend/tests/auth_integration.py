import os
from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy import text
from app.auth import hasher
from app.db import get_engine
from app.main import app

def main():
    admin = get_engine(migration=True)
    org_a, org_b, account = uuid4(), uuid4(), uuid4()
    email = f"{account}@example.invalid"
    password = "integration-test-password"
    with admin.begin() as conn:
        for org in (org_a, org_b):
            conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,'Integration test')"), {"id":org,"slug":str(org)})
        conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"), {"id":account,"email":email,"hash":hasher.hash(password)})
        conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"), {"id":account,"org":org_a})
    try:
        with TestClient(app) as client:
            payload = {"email":email,"password":password,"organization_id":str(org_a)}
            assert client.post("/api/v1/auth/login",json={**payload,"password":"wrong"}).status_code == 401
            assert client.post("/api/v1/auth/login",json={**payload,"organization_id":str(org_b)}).status_code == 401
            response = client.post("/api/v1/auth/login",json=payload)
            assert response.status_code == 200, response.text
            headers = {"Authorization":"Bearer "+response.json()["access_token"]}
            identity = client.get("/api/v1/auth/me",headers=headers)
            assert identity.status_code == 200
            assert identity.json()["organization_id"] == str(org_a)
            assert response.json()["mfa_required"] is True
            assert identity.json()["mfa_required"] is True
            assert client.get("/api/v1/organization",headers=headers).status_code == 403
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":True}).status_code == 403
            # Enroll this administrator before exercising privileged operations.
            import pyotp
            import time
            setup_admin = client.post("/api/v1/auth/mfa/setup",headers=headers,json={"password":password})
            assert setup_admin.status_code == 200
            admin_totp = pyotp.TOTP(setup_admin.json()["secret"])
            admin_step = int(time.time() // 30)
            confirmed_admin = client.post("/api/v1/auth/mfa/confirm",headers=headers,json={"password":password,"otp":admin_totp.at((admin_step-1)*30)})
            assert confirmed_admin.status_code == 200
            admin_codes = confirmed_admin.json()["recovery_codes"]
            assert client.get("/api/v1/auth/me",headers=headers).status_code == 401
            response = client.post("/api/v1/auth/login",json={**payload,"otp":admin_totp.at(admin_step*30)})
            assert response.status_code == 200
            assert response.json()["mfa_required"] is False
            headers = {"Authorization":"Bearer "+response.json()["access_token"]}
            assert client.get("/api/v1/organization",headers=headers).json()["id"] == str(org_a)
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":True}).status_code == 200
            assert client.put("/api/v1/organization/modules/unknown",headers=headers,json={"enabled":True}).status_code == 404
            with admin.begin() as conn:
                assert conn.execute(text("SELECT count(*) FROM audit_events WHERE organization_id=:org AND action='module.updated'"), {"org":org_a}).scalar_one() == 1
                conn.execute(text("UPDATE memberships SET role='auditor' WHERE account_id=:id"), {"id":account})
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":False}).status_code == 403
            assert client.post("/api/v1/auth/logout",headers=headers).status_code == 204
            assert client.get("/api/v1/auth/me",headers=headers).status_code == 401
            response = client.post("/api/v1/auth/login",json={**payload,"recovery_code":admin_codes[0]})
            assert response.status_code == 200
            headers = {"Authorization":"Bearer "+response.json()["access_token"]}
            with admin.begin() as conn:
                conn.execute(text("UPDATE memberships SET active=false WHERE account_id=:id"), {"id":account})
            assert client.get("/api/v1/auth/me",headers=headers).status_code == 401
            # Exercise MFA with a separate account to isolate rate limits.
            mfa_account = uuid4()
            mfa_email = f"{mfa_account}@example.invalid"
            import pyotp
            import time
            from app.mfa import cipher
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"), {"id":mfa_account,"email":mfa_email,"hash":hasher.hash(password)})
                conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"), {"id":mfa_account,"org":org_a})
            try:
                mfa_payload = {"email":mfa_email,"password":password,"organization_id":str(org_a)}
                logged = client.post("/api/v1/auth/login",json=mfa_payload)
                assert logged.status_code == 200
                mfa_headers = {"Authorization":"Bearer "+logged.json()["access_token"]}
                setup = client.post("/api/v1/auth/mfa/setup",headers=mfa_headers,json={"password":password})
                assert setup.status_code == 200
                secret = setup.json()["secret"]
                with admin.begin() as conn:
                    encrypted = conn.execute(text("SELECT secret_ciphertext FROM account_mfa WHERE account_id=:id"), {"id":mfa_account}).scalar_one()
                    assert encrypted != secret
                    assert cipher().decrypt(encrypted.encode()).decode() == secret
                totp = pyotp.TOTP(secret)
                step = int(time.time() // 30)
                confirmed = client.post("/api/v1/auth/mfa/confirm",headers=mfa_headers,json={"password":password,"otp":totp.at((step-1)*30)})
                assert confirmed.status_code == 200, confirmed.text
                codes = confirmed.json()["recovery_codes"]
                assert len(set(codes)) == 10
                assert client.get("/api/v1/auth/me",headers=mfa_headers).status_code == 401
                assert client.post("/api/v1/auth/login",json=mfa_payload).status_code == 401
                code = totp.at(step*30)
                assert client.post("/api/v1/auth/login",json={**mfa_payload,"otp":code}).status_code == 200
                assert client.post("/api/v1/auth/login",json={**mfa_payload,"otp":code}).status_code == 401
                assert client.post("/api/v1/auth/login",json={**mfa_payload,"recovery_code":codes[0]}).status_code == 200
                assert client.post("/api/v1/auth/login",json={**mfa_payload,"recovery_code":codes[0]}).status_code == 401
            finally:
                with admin.begin() as conn:
                    conn.execute(text("DELETE FROM memberships WHERE account_id=:id"), {"id":mfa_account})
                    conn.execute(text("DELETE FROM accounts WHERE id=:id"), {"id":mfa_account})
                    from app.login_limits import bucket_key
                    conn.execute(text("DELETE FROM login_buckets WHERE bucket=:key"), {"key":bucket_key("account",mfa_email)})
            # Seed the current window at its threshold to avoid clock-boundary flakiness.
            from app.login_limits import bucket_key
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO login_buckets VALUES (:key,date_trunc('minute',now()),10) ON CONFLICT (bucket) DO UPDATE SET attempts=10,window_start=EXCLUDED.window_start"), {"key":bucket_key("account",email)})
            blocked = client.post("/api/v1/auth/login",json=payload)
            assert blocked.status_code == 429
            assert blocked.headers["Retry-After"] == "60"
    finally:
        with admin.begin() as conn:
            from app.login_limits import bucket_key
            conn.execute(text("DELETE FROM login_buckets WHERE bucket IN (:account,:peer)"), {"account":bucket_key("account",email),"peer":bucket_key("peer","testclient")})
            conn.execute(text("DELETE FROM audit_events WHERE organization_id=:org"), {"org":org_a})
            conn.execute(text("DELETE FROM tenant_modules WHERE organization_id=:org"), {"org":org_a})
            conn.execute(text("DELETE FROM memberships WHERE account_id=:id"), {"id":account})
            conn.execute(text("DELETE FROM accounts WHERE id=:id"), {"id":account})
            conn.execute(text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a":org_a,"b":org_b})

if __name__ == "__main__":
    main()
