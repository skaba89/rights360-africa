"""Synthetic fixture for disposable GitHub Actions database only."""
import os,json
from uuid import uuid4
from sqlalchemy import text
from app.db import get_engine
from app.auth import hasher

if os.environ.get("RIGHTS360_DISPOSABLE_E2E")!="1" or os.environ.get("POSTGRES_PASSWORD")!="ci-ephemeral-only":
    raise SystemExit("Refusing to seed a non-CI database")
org,account=uuid4(),uuid4()
email=f"{account}@example.invalid"
password=uuid4().hex+uuid4().hex
with get_engine(migration=True).begin() as conn:
    conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,'Synthetic browser institution')"),{"id":org,"slug":str(org)})
    conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"),{"id":account,"email":email,"hash":hasher.hash(password)})
    conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'manager')"),{"id":account,"org":org})
    for module in ("artists","works","documents"):
        conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,:module,true)"),{"org":org,"module":module})
        conn.execute(text("INSERT INTO tenant_modules(organization_id,module_key,enabled) VALUES (:org,:module,true)"),{"org":org,"module":module})
print(json.dumps({"org":str(org),"email":email,"password":password}))
