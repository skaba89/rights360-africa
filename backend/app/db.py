import os
from functools import lru_cache
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, URL

@lru_cache(maxsize=1)
def get_engine(migration: bool = False) -> Engine:
    url = URL.create("postgresql+psycopg", username="rights360" if migration else "rights360_runtime", password=os.environ["POSTGRES_PASSWORD" if migration else "RUNTIME_DB_PASSWORD"], host=os.environ.get("POSTGRES_HOST", "db"), database="rights360")
    return create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 3})

def check_database() -> None:
    with get_engine().connect() as conn:
        conn.execute(text("SELECT 1"))
