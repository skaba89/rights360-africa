from hashlib import sha256
from fastapi import HTTPException
from sqlalchemy import text
from app.db import get_engine

def bucket_key(kind: str, value: str) -> str:
    return kind + ":" + sha256(value.encode()).hexdigest()

def reserve_login(email: str, organization_id, peer: str):
    # Fixed window, shared by all workers. Never trust forwarded headers here.
    limits = [(bucket_key("peer", peer), 100), (bucket_key("account", email.strip().lower()), 10)]
    blocked = False
    with get_engine().begin() as conn:
        for key, limit in limits:
            count = conn.execute(text("""
                INSERT INTO login_buckets(bucket,window_start,attempts)
                VALUES (:key, date_trunc('minute',now()),1)
                ON CONFLICT (bucket) DO UPDATE SET
                  attempts=CASE WHEN login_buckets.window_start=EXCLUDED.window_start
                    THEN LEAST(login_buckets.attempts+1,1000) ELSE 1 END,
                  window_start=EXCLUDED.window_start
                RETURNING attempts
            """), {"key":key}).scalar_one()
            blocked = blocked or count > limit
    if blocked:
        raise HTTPException(status_code=429, detail="Too many login attempts", headers={"Retry-After":"60","Cache-Control":"no-store"})
