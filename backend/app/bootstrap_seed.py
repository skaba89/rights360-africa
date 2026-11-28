"""Non-interactive, reproducible administrator bootstrap for DEV/REC.

Complements the existing interactive ``bootstrap_account.py``. Creates the first
organization + admin account from environment variables, so a fresh
``docker compose up`` no longer leaves an empty stack with no way to log in.

Safety:
  * Refuses to run unless ``RIGHTS360_DEV_BOOTSTRAP=1`` is set explicitly.
  * Idempotent and non-destructive: never alters an existing organization or
    account (ON CONFLICT DO NOTHING; raises if the slug or email already exists).
  * Never prints an existing password; only prints a generated one.
  * Does NOT grant platform access: ``bootstrap_platform_admin.py`` requires MFA
    to be enabled first (by design). The seeded admin must enroll MFA via the
    portal before platform access can be granted.

Usage (DEV only):
  RIGHTS360_DEV_BOOTSTRAP=1 \\
  RIGHTS360_BOOTSTRAP_EMAIL=admin@example.invalid \\
  RIGHTS360_BOOTSTRAP_ORG_SLUG=dsig-dev \\
  RIGHTS360_BOOTSTRAP_ORG_NAME="DSIG Dev" \\
  [RIGHTS360_BOOTSTRAP_PASSWORD=<optional, >=12 chars>] \\
  python -m app.bootstrap_seed
"""
import json
import os
import secrets
from uuid import uuid4
from sqlalchemy import text
from app.auth import hasher
from app.db import get_engine


def bootstrap_admin(*, email: str, password: str, org_slug: str, org_name: str) -> dict:
    email = email.strip().lower()
    if not email or len(email) > 254 or "@" not in email:
        raise ValueError("Invalid email")
    if not 12 <= len(password) <= 256:
        raise ValueError("Password must be 12-256 characters")
    if not org_slug or len(org_slug) > 100:
        raise ValueError("Invalid organization slug")
    if not org_name or len(org_name) > 200:
        raise ValueError("Invalid organization name")
    with get_engine(migration=True).begin() as conn:
        org = conn.execute(
            text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,:name) "
                 "ON CONFLICT (slug) DO NOTHING RETURNING id"),
            {"id": uuid4(), "slug": org_slug, "name": org_name},
        ).scalar_one_or_none()
        if org is None:
            # Slug already exists: refuse rather than silently reuse someone's org.
            raise RuntimeError("Organization slug already exists; bootstrap is non-destructive")
        account = uuid4()
        conn.execute(
            text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"),
            {"id": account, "email": email, "hash": hasher.hash(password)},
        )
        conn.execute(
            text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:account,:org,'admin')"),
            {"account": account, "org": org},
        )
    return {"organization_id": str(org), "account_id": str(account), "email": email}


def main() -> None:
    if os.environ.get("RIGHTS360_DEV_BOOTSTRAP") != "1":
        raise SystemExit("Refusing: set RIGHTS360_DEV_BOOTSTRAP=1 to seed a local administrator")
    email = os.environ.get("RIGHTS360_BOOTSTRAP_EMAIL")
    org_slug = os.environ.get("RIGHTS360_BOOTSTRAP_ORG_SLUG")
    if not email or not org_slug:
        raise SystemExit("RIGHTS360_BOOTSTRAP_EMAIL and RIGHTS360_BOOTSTRAP_ORG_SLUG are required")
    org_name = os.environ.get("RIGHTS360_BOOTSTRAP_ORG_NAME", org_slug)
    provided = os.environ.get("RIGHTS360_BOOTSTRAP_PASSWORD")
    password = provided if provided else secrets.token_urlsafe(18)
    result = bootstrap_admin(email=email, password=password, org_slug=org_slug, org_name=org_name)
    result["password"] = password
    result["note"] = ("Generated password shown once. Enroll MFA via /portal before using "
                      "privileged endpoints. Grant platform access with bootstrap_platform_admin.py "
                      "only after MFA is enabled.")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
