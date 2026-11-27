import argparse
from uuid import UUID
from sqlalchemy import text
from app.db import get_engine

def main():
    parser = argparse.ArgumentParser(description="Grant or revoke platform access for an existing dedicated administrator")
    parser.add_argument("action",choices=["grant","revoke"])
    parser.add_argument("--account-id",type=UUID,required=True)
    parser.add_argument("--organization-id",type=UUID,required=True)
    args = parser.parse_args()
    params = {"account":args.account_id,"org":args.organization_id}
    with get_engine(migration=True).begin() as conn:
        if args.action == "grant":
            eligible = conn.execute(text("""
                SELECT 1 FROM memberships m JOIN accounts a ON a.id=m.account_id
                JOIN account_mfa f ON f.account_id=a.id
                WHERE m.account_id=:account AND m.organization_id=:org
                AND m.role='admin' AND m.active AND a.active AND f.enabled
            """),params).scalar_one_or_none()
            if not eligible:
                raise SystemExit("Active administrator with MFA required")
            conn.execute(text("""
                INSERT INTO platform_admins(account_id,organization_id,active)
                VALUES (:account,:org,true)
                ON CONFLICT(account_id) DO UPDATE SET active=true,organization_id=EXCLUDED.organization_id
            """),params)
        else:
            result = conn.execute(text("UPDATE platform_admins SET active=false WHERE account_id=:account AND organization_id=:org"),params)
            if result.rowcount != 1:
                raise SystemExit("Platform grant not found")
        conn.execute(text("DELETE FROM auth_sessions WHERE account_id=:account"),params)
    print("Platform authorization updated; fresh login required")

if __name__ == "__main__":
    main()
