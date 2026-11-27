import os
import time
import secrets
import pyotp
from cryptography.fernet import Fernet
from sqlalchemy import text

def cipher():
    return Fernet(os.environ["MFA_ENCRYPTION_KEY"].encode())

def new_secret():
    return pyotp.random_base32()

def matching_step(secret: str, code: str, now: float | None = None):
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    step = int((time.time() if now is None else now) // 30)
    totp = pyotp.TOTP(secret)
    for candidate in (step, step-1, step+1):
        if candidate >= 0 and secrets.compare_digest(totp.at(candidate*30),code):
            return candidate
    return None

def consume_code(conn, account_id, code, *, require_enabled=True):
    row = conn.execute(text("SELECT secret_ciphertext,last_step,enabled FROM account_mfa WHERE account_id=:id FOR UPDATE"), {"id":account_id}).mappings().first()
    if row is None or row["enabled"] != require_enabled:
        return False
    if not code:
        return False
    secret = cipher().decrypt(row["secret_ciphertext"].encode()).decode()
    step = matching_step(secret,code)
    if step is None or step <= row["last_step"]:
        return False
    conn.execute(text("UPDATE account_mfa SET last_step=:step WHERE account_id=:id"), {"step":step,"id":account_id})
    return True
