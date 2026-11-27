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
            assert client.get("/api/v1/platform/me",headers=headers).status_code == 403
            with admin.begin() as conn:
                conn.execute(text("INSERT INTO platform_admins(account_id,organization_id) VALUES (:id,:org)"), {"id":account,"org":org_a})
            platform = client.get("/api/v1/platform/me",headers=headers)
            assert platform.status_code == 200
            assert platform.json()["platform_role"] == "super_admin"
            entitlement_url=f"/api/v1/platform/organizations/{org_a}/entitlements"
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":True}).status_code == 403
            assert client.put(entitlement_url+"/artists",headers=headers,json={"granted":True,"expires_at":"2000-01-01T00:00:00Z"}).status_code == 422
            assert client.put(entitlement_url+"/artists",headers=headers,json={"granted":True}).status_code == 200
            assert client.get(entitlement_url,headers=headers).json()[0]["granted"] is True
            assert client.put(entitlement_url+"/artists",headers=headers,json={"granted":False}).status_code == 200
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":True}).status_code == 403
            assert client.put(entitlement_url+"/artists",headers=headers,json={"granted":True}).status_code == 200
            slug = "test-" + str(uuid4())
            created = client.post("/api/v1/platform/organizations",headers=headers,json={"slug":slug,"name":"Test client"})
            assert created.status_code == 201, created.text
            created_id = created.json()["id"]
            invited_email = f"{uuid4()}@example.invalid"
            try:
                assert client.post("/api/v1/platform/organizations",headers=headers,json={"slug":slug,"name":"Duplicate"}).status_code == 409
                listing = client.get("/api/v1/platform/organizations",headers=headers)
                assert listing.status_code == 200
                assert any(item["id"] == created_id for item in listing.json())
                assert client.patch(f"/api/v1/platform/organizations/{org_a}/status",headers=headers,json={"active":False}).status_code == 409
                assert client.patch(f"/api/v1/platform/organizations/{created_id}/status",headers=headers,json={"active":False}).status_code == 200
                assert client.patch(f"/api/v1/platform/organizations/{created_id}/status",headers=headers,json={"active":True}).status_code == 200
                with admin.begin() as conn:
                    assert conn.execute(text("SELECT count(*) FROM platform_audit_events WHERE organization_id=CAST(:id AS uuid)"), {"id":created_id}).scalar_one() == 3
                with get_engine().connect() as conn:
                    assert conn.execute(text("SELECT count(*) FROM organizations WHERE id=CAST(:id AS uuid)"), {"id":created_id}).scalar_one() == 0
                url = f"/api/v1/platform/organizations/{created_id}/invitations"
                first = client.post(url,headers=headers,json={"email":invited_email})
                assert first.status_code == 201, first.text
                second = client.post(url,headers=headers,json={"email":invited_email})
                assert second.status_code == 201, second.text
                accept_url = "/api/v1/auth/invitations/accept"
                assert client.post(accept_url,json={"token":first.json()["token"],"password":password}).status_code == 400
                invited = client.post(accept_url,json={"token":second.json()["token"],"password":password})
                assert invited.status_code == 201, invited.text
                assert invited.json()["organization_id"] == created_id
                assert client.post(accept_url,json={"token":second.json()["token"],"password":password}).status_code == 400
                login_new = client.post("/api/v1/auth/login",json={"email":invited_email,"password":password,"organization_id":created_id})
                assert login_new.status_code == 200
                assert login_new.json()["mfa_required"] is True
                new_headers = {"Authorization":"Bearer "+login_new.json()["access_token"]}
                assert client.get("/api/v1/platform/me",headers=new_headers).status_code == 403
                assert client.get("/api/v1/organization",headers=new_headers).status_code == 403
                assert client.patch(f"/api/v1/platform/organizations/{created_id}/status",headers=headers,json={"active":False}).status_code == 200
                assert client.get("/api/v1/auth/me",headers=new_headers).status_code == 401
            finally:
                with admin.begin() as conn:
                    conn.execute(text("DELETE FROM customer_invitations WHERE organization_id=CAST(:id AS uuid)"), {"id":created_id})
                    conn.execute(text("DELETE FROM memberships WHERE organization_id=CAST(:id AS uuid)"), {"id":created_id})
                    conn.execute(text("DELETE FROM accounts WHERE email=:email"), {"email":invited_email})
                    conn.execute(text("DELETE FROM platform_audit_events WHERE organization_id=CAST(:id AS uuid)"), {"id":created_id})
                    conn.execute(text("DELETE FROM organizations WHERE id=CAST(:id AS uuid)"), {"id":created_id})
            with admin.begin() as conn:
                conn.execute(text("UPDATE platform_admins SET active=false WHERE account_id=:id"), {"id":account})
            assert client.get("/api/v1/platform/me",headers=headers).status_code == 403
            assert client.get("/api/v1/platform/organizations",headers=headers).status_code == 403
            assert client.put(entitlement_url+"/artists",headers=headers,json={"granted":True}).status_code == 403
            invite_email = f"{uuid4()}@example.invalid"
            invite_url = "/api/v1/organization/invitations"
            accept_url = "/api/v1/auth/member-invitations/accept"
            try:
                assert client.post(invite_url,headers=headers,json={"email":invite_email,"role":"admin"}).status_code == 422
                first = client.post(invite_url,headers=headers,json={"email":invite_email,"role":"artist"})
                assert first.status_code == 201, first.text
                assert client.delete(invite_url+"/"+first.json()["id"],headers=headers).status_code == 204
                assert client.post(accept_url,json={"token":first.json()["token"],"password":password}).status_code == 400
                second = client.post(invite_url,headers=headers,json={"email":invite_email,"role":"manager"})
                assert second.status_code == 201, second.text
                third = client.post(invite_url,headers=headers,json={"email":invite_email,"role":"auditor"})
                assert third.status_code == 201, third.text
                assert client.post(accept_url,json={"token":second.json()["token"],"password":password}).status_code == 400
                accepted = client.post(accept_url,json={"token":third.json()["token"],"password":password})
                assert accepted.status_code == 201, accepted.text
                assert accepted.json()["organization_id"] == str(org_a)
                assert client.post(accept_url,json={"token":third.json()["token"],"password":password}).status_code == 400
                logged = client.post("/api/v1/auth/login",json={"email":invite_email,"password":password,"organization_id":str(org_a)})
                assert logged.status_code == 200
                invited_headers = {"Authorization":"Bearer "+logged.json()["access_token"]}
                assert client.get("/api/v1/auth/me",headers=invited_headers).json()["role"] == "auditor"
                assert client.post(invite_url,headers=invited_headers,json={"email":f"{uuid4()}@example.invalid","role":"artist"}).status_code == 403
                assert client.post(invite_url,headers=headers,json={"email":invite_email,"role":"artist"}).status_code == 409
            finally:
                with admin.begin() as conn:
                    conn.execute(text("DELETE FROM member_invitations WHERE organization_id=:org"),{"org":org_a})
                    conn.execute(text("DELETE FROM memberships WHERE account_id IN (SELECT id FROM accounts WHERE email=:email)"),{"email":invite_email})
                    conn.execute(text("DELETE FROM accounts WHERE email=:email"),{"email":invite_email})
            collaborator, outside = uuid4(), uuid4()
            with admin.begin() as conn:
                for member_id, org in ((collaborator,org_a),(outside,org_b)):
                    conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"), {"id":member_id,"email":f"{member_id}@example.invalid","hash":hasher.hash(password)})
                    conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'artist')"), {"id":member_id,"org":org})
            try:
                members_url = "/api/v1/organization/members"
                members = client.get(members_url,headers=headers)
                assert members.status_code == 200, members.text
                assert str(collaborator) in [row["account_id"] for row in members.json()]
                assert str(outside) not in [row["account_id"] for row in members.json()]
                change = {"role":"manager","active":False}
                assert client.patch(f"{members_url}/{outside}",headers=headers,json=change).status_code == 404
                assert client.patch(f"{members_url}/{account}",headers=headers,json=change).status_code == 403
                assert client.patch(f"{members_url}/{collaborator}",headers=headers,json={"role":"admin","active":True}).status_code == 422
                member_login = {"email":f"{collaborator}@example.invalid","password":password,"organization_id":str(org_a)}
                logged_member = client.post("/api/v1/auth/login",json=member_login)
                assert logged_member.status_code == 200
                member_headers = {"Authorization":"Bearer "+logged_member.json()["access_token"]}
                assert client.get(members_url,headers=member_headers).status_code == 403
                assert client.patch(f"{members_url}/{collaborator}",headers=headers,json=change).status_code == 200
                assert client.get("/api/v1/auth/me",headers=member_headers).status_code == 401
                assert client.post("/api/v1/auth/login",json=member_login).status_code == 401
                assert client.patch(f"{members_url}/{collaborator}",headers=headers,json={"role":"auditor","active":True}).status_code == 200
                assert client.get("/api/v1/auth/me",headers=member_headers).status_code == 401
                logged_member = client.post("/api/v1/auth/login",json=member_login)
                assert logged_member.status_code == 200
                member_headers = {"Authorization":"Bearer "+logged_member.json()["access_token"]}
                assert client.get("/api/v1/auth/me",headers=member_headers).json()["role"] == "auditor"
                with admin.begin() as conn:
                    assert conn.execute(text("SELECT count(*) FROM audit_events WHERE organization_id=:org AND action='member.updated'"),{"org":org_a}).scalar_one() == 2
            finally:
                with admin.begin() as conn:
                    for member_id in (collaborator,outside):
                        conn.execute(text("DELETE FROM memberships WHERE account_id=:id"),{"id":member_id})
                        conn.execute(text("DELETE FROM accounts WHERE id=:id"),{"id":member_id})
            assert client.put("/api/v1/organization/modules/artists",headers=headers,json={"enabled":True}).status_code == 200
            assert client.put("/api/v1/organization/modules/unknown",headers=headers,json={"enabled":True}).status_code == 404
            assert next(m for m in client.get("/api/v1/organization/modules",headers=headers).json() if m["module_key"]=="artists")["enabled"] is True
            with admin.begin() as conn:
                conn.execute(text("UPDATE module_entitlements SET expires_at=now()-interval '1 second' WHERE organization_id=:org"),{"org":org_a})
            assert next(m for m in client.get("/api/v1/organization/modules",headers=headers).json() if m["module_key"]=="artists")["enabled"] is False
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
            conn.execute(text("DELETE FROM module_entitlements WHERE organization_id=:org"),{"org":org_a})
            conn.execute(text("DELETE FROM platform_audit_events WHERE organization_id=:org"),{"org":org_a})
            conn.execute(text("DELETE FROM tenant_modules WHERE organization_id=:org"), {"org":org_a})
            conn.execute(text("DELETE FROM memberships WHERE account_id=:id"), {"id":account})
            conn.execute(text("DELETE FROM accounts WHERE id=:id"), {"id":account})
            conn.execute(text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a":org_a,"b":org_b})

if __name__ == "__main__":
    main()
