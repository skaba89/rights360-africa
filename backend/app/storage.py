"""PHASE 6 — Storage backend abstraction for the GED module.

Provider-independent object storage with a local-filesystem backend for
sandbox/CI (production swaps in S3/B2). Handles:
  * put/get objects by key (content-addressed under org/doc/version),
  * AES-GCM-ish encryption at rest (Fernet) when encryption_enabled,
  * presigned URL tokens (HMAC-signed, time-limited) for temporary access.

The Postgres ``document_versions.content`` bytea is kept as the source of
truth (dual-write when object storage is enabled) so the existing integrity
CC + download path still work; ``object_key`` marks versions that also live
in object storage. Controlled migration: flip
``documents_object_storage_enabled`` to start dual-writing.
"""
import base64
import hashlib
import hmac
import os
import time
from pathlib import Path
from cryptography.fernet import Fernet

STORAGE_DIR = Path(os.environ.get("RIGHTS360_STORAGE_DIR", "/tmp/rights360-storage"))
_STORAGE_SECRET = os.environ.get("RIGHTS360_STORAGE_SECRET", "rights360-sandbox-storage-key-do-not-use-in-prod")


def _fernet() -> Fernet:
    key = hashlib.sha256(_STORAGE_SECRET.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def put(key: str, data: bytes, encrypt: bool) -> str:
    """Write an object; returns the object_key. Creates the storage dir tree."""
    path = STORAGE_DIR / key
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = _fernet().encrypt(data) if encrypt else data
    path.write_bytes(blob)
    return key


def get(key: str, encrypted: bool) -> bytes:
    """Read an object back. Raises FileNotFoundError if missing."""
    blob = (STORAGE_DIR / key).read_bytes()
    return _fernet().decrypt(blob) if encrypted else blob


def delete(key: str) -> None:
    p = STORAGE_DIR / key
    if p.exists():
        p.unlink()


def presign(key: str, expires_in: int = 900) -> str:
    """Return an HMAC-signed token encoding (key, expiry). Default 15 min."""
    exp = int(time.time()) + expires_in
    payload = f"{key}|{exp}"
    sig = hmac.new(_STORAGE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def verify_presign(token: str) -> str:
    """Verify a presign token; returns the object_key or raises ValueError."""
    try:
        payload, sig = base64.urlsafe_b64decode(token.encode()).decode().rsplit("|", 1)
        key, exp = payload.rsplit("|", 1)
    except Exception:
        raise ValueError("malformed token")
    expected = hmac.new(_STORAGE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise ValueError("invalid signature")
    if int(time.time()) > int(exp):
        raise ValueError("expired")
    return key
