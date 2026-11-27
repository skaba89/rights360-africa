import os
import psycopg
from psycopg import sql

def main():
    password = os.environ["RUNTIME_DB_PASSWORD"]
    if len(password) < 24 or password == os.environ["POSTGRES_PASSWORD"]:
        raise RuntimeError("Runtime password must be distinct and at least 24 characters")
    with psycopg.connect(host=os.environ.get("POSTGRES_HOST", "db"), dbname="rights360", user="rights360", password=os.environ["POSTGRES_PASSWORD"]) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'rights360_runtime'")
            if not cur.fetchone():
                cur.execute("CREATE ROLE rights360_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS")
            cur.execute(sql.SQL("ALTER ROLE rights360_runtime WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD {}").format(sql.Literal(password)))
            cur.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            cur.execute("GRANT USAGE ON SCHEMA public TO rights360_runtime")

if __name__ == "__main__":
    main()
