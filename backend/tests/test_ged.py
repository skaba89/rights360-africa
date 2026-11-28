"""Unit tests for the PHASE 6 GED module (no database required).

Run by the ``api`` CI job. Covers Pydantic validation, the storage backend
(presign/verify round-trip, encryption round-trip), and auth-gating. The
behavioral flow (quarantine, quotas, litigation, presign download, access log)
is exercised against a real database by ``ged_integration.py`` in the ``docker``
job.
"""
import time
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.ged import StorageData, QuotaData, RetentionData, LitigationData, MetadataData, ScanData
from app import storage


def test_storage_validation():
    s = StorageData(backend="s3", bucket="my-bucket", encryption_enabled=True)
    assert s.backend == "s3" and s.encryption_enabled is True
    with pytest.raises(ValueError):
        StorageData(backend="azure")  # unknown backend


def test_quota_validation():
    q = QuotaData(max_bytes=1024, max_documents=10)
    assert q.enforced is True
    with pytest.raises(ValueError):
        QuotaData(max_bytes=0, max_documents=10)
    with pytest.raises(ValueError):
        QuotaData(max_bytes=10, max_documents=-1)


def test_retention_validation():
    r = RetentionData(category="contract", retain_days=365)
    assert r.legal_hold_default is False
    with pytest.raises(ValueError):
        RetentionData(category="", retain_days=10)
    with pytest.raises(ValueError):
        RetentionData(category="contract", retain_days=-1)


def test_litigation_metadata_scan_validation():
    LitigationData(reason="Audit pending")
    with pytest.raises(ValueError):
        LitigationData(reason="")
    MetadataData(key="invoice_ref", value="INV-2026-001")
    with pytest.raises(ValueError):
        MetadataData(key="", value="x")
    ScanData(verdict="clean")
    with pytest.raises(ValueError):
        ScanData(verdict="suspicious")


def test_storage_presign_roundtrip():
    key = "org-xyz/doc-abc/v1.bin"
    token = storage.presign(key, expires_in=60)
    assert storage.verify_presign(token) == key


def test_storage_presign_rejects_tamper_and_expiry():
    token = storage.presign("k/1", expires_in=60)
    bad = token[:-4] + "AAAA"
    with pytest.raises(ValueError):
        storage.verify_presign(bad)
    expired = storage.presign("k/2", expires_in=-1)  # already expired
    with pytest.raises(ValueError):
        storage.verify_presign(expired)


def test_storage_encryption_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "STORAGE_DIR", tmp_path)
    data = b"%PDF-1.4\n%%EOF" * 10
    storage.put("enc/test.bin", data, encrypt=True)
    assert storage.get("enc/test.bin", encrypted=True) == data
    # plaintext path is distinct from ciphertext on disk
    assert (tmp_path / "enc/test.bin").read_bytes() != data


def test_ged_routes_require_auth():
    for path in ("/api/v1/ged/storage", "/api/v1/ged/quotas",
                 "/api/v1/ged/retention-policies", "/api/v1/ged/search"):
        assert TestClient(app).get(path).status_code == 401, path
