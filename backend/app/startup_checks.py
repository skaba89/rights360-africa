"""Fail-fast runtime checks executed at application startup (FastAPI lifespan).

Validates that required secrets are present and well-formed BEFORE the first
request, so a misconfigured ``uvicorn app.main:app`` fails with a clear message
instead of crashing inside ``app.mfa.cipher()`` on the first MFA operation.
Invoked from the app lifespan, not at import time: plain imports and plain
``TestClient(app)`` usage do not trigger it (only server startup and
``with TestClient(app)`` do), so pytest collection is safe without a key.
"""
import os
from cryptography.fernet import Fernet


def validate_mfa_encryption_key() -> None:
    key = os.environ.get("MFA_ENCRYPTION_KEY")
    if not key:
        raise SystemExit(
            "MFA_ENCRYPTION_KEY is required. Generate one with:\n"
            "  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    try:
        Fernet(key.encode())
    except Exception:
        raise SystemExit(
            "MFA_ENCRYPTION_KEY is not a valid Fernet key "
            "(must be 32 url-safe base64-encoded bytes)."
        )


def validate_runtime() -> None:
    validate_mfa_encryption_key()
