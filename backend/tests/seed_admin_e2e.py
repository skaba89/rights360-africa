"""Synthetic admin fixture for disposable GitHub Actions database only.

Creates an organization + an administrator account with MFA NOT yet enrolled,
plus an ``artists`` entitlement, so the admin MFA enrollment flow can be
exercised end-to-end through the portal (the existing business_browser E2E
seeds a manager and never touches admin enrollment).
"""
import os, json
from uuid import uuid4
from sqlalchemy import text
from app.db import get_engine
from app.auth import hasher

if os.environ.get("RIGHTS360_DISPOSABLE_E2E") != "1" or os.environ.get("POSTGRES_PASSWORD") != "ci-ephemeral-only":
    raise SystemExit("Refusing to seed a non-CI database")
org, account = uuid4(), uuid4()
email = f"{account}@example.invalid"
password = uuid4().hex + uuid4().hex  # >= 12 chars, synthetic
with get_engine(migration=True).begin() as conn:
    conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,'Synthetic admin institution')"),
                 {"id": org, "slug": str(org)})
    conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"),
                 {"id": account, "email": email, "hash": hasher.hash(password)})
    conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"),
                 {"id": account, "org": org})
    conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'artists',true)"),
                 {"org": org})
print(json.dumps({"org": str(org), "email": email, "password": password}))
