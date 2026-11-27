import hashlib
import re
import secrets
from sqlalchemy import text

def normalize(code: str) -> str:
    return code.replace("-", "").upper()

def code_hash(code: str) -> str:
    return hashlib.sha256(normalize(code).encode("ascii")).hexdigest()

def generate_codes(conn, account_id):
    codes = []
    for _ in range(10):
        raw = secrets.token_hex(16).upper()
        codes.append("-".join(raw[i:i+8] for i in range(0,32,8)))
    conn.execute(text("DELETE FROM mfa_recovery_codes WHERE account_id=:id"), {"id":account_id})
    conn.execute(text("INSERT INTO mfa_recovery_codes(account_id,code_hash) VALUES (:id,:hash)"), [{"id":account_id,"hash":code_hash(code)} for code in codes])
    return codes

def consume_recovery(conn, account_id, code):
    if not code or not re.fullmatch(r"(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{8}){3})",code):
        return False
    return conn.execute(text("DELETE FROM mfa_recovery_codes WHERE account_id=:id AND code_hash=:hash RETURNING account_id"), {"id":account_id,"hash":code_hash(code)}).scalar_one_or_none() is not None
