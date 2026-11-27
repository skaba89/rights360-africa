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
            assert client.post("/api/v1/auth/logout",headers=headers).status_code == 204
            assert client.get("/api/v1/auth/me",headers=headers).status_code == 401
            response = client.post("/api/v1/auth/login",json=payload)
            assert response.status_code == 200
            headers = {"Authorization":"Bearer "+response.json()["access_token"]}
            with admin.begin() as conn:
                conn.execute(text("UPDATE memberships SET active=false WHERE account_id=:id"), {"id":account})
            assert client.get("/api/v1/auth/me",headers=headers).status_code == 401
    finally:
        with admin.begin() as conn:
            conn.execute(text("DELETE FROM memberships WHERE account_id=:id"), {"id":account})
            conn.execute(text("DELETE FROM accounts WHERE id=:id"), {"id":account})
            conn.execute(text("DELETE FROM organizations WHERE id IN (:a,:b)"), {"a":org_a,"b":org_b})

if __name__ == "__main__":
    main()
