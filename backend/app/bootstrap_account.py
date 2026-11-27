import argparse
import getpass
from uuid import uuid4
from sqlalchemy import text
from app.auth import hasher
from app.db import get_engine

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", required=True)
    parser.add_argument("--organization", required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    email = args.email.strip().lower()
    if not email or len(email)>254 or "@" not in email:
        parser.error("Invalid email")
    password = getpass.getpass("Password (12-256 characters): ")
    if not 12 <= len(password) <= 256 or password != getpass.getpass("Confirm password: "):
        parser.error("Password invalid or confirmation mismatch")
    with get_engine(migration=True).begin() as conn:
        org = conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,:name) ON CONFLICT (slug) DO NOTHING RETURNING id"), {"id":uuid4(),"slug":args.organization,"name":args.name}).scalar_one_or_none()
        if org is None:
            raise RuntimeError("Organization already exists; bootstrap does not alter existing organizations")
        account = uuid4()
        conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"), {"id":account,"email":email,"hash":hasher.hash(password)})
        conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:account,:org,'admin')"), {"account":account,"org":org})
    print("Organization ID:", org)

if __name__ == "__main__":
    main()
