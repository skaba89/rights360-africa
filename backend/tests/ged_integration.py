"""Integration checks for the PHASE 6 GED module (requires a migrated DB).

Seeds one MFA-enrolled administrator with the 'documents' module enabled,
creates a document + uploads a PDF version, then exercises:
  * storage backend config + quotas (tight quota -> 413, relaxed -> OK),
  * quarantine: flag on -> new version quarantined; download blocked (409);
    scan clears it; download then works (200),
  * metadata + search,
  * litigation hold (hold -> 201, re-hold -> 409, release),
  * presigned URL: anonymous download with ?token= works (no Bearer),
    bad token -> 401,
  * access journal records every action.
Wired into the ``docker`` CI job.
"""
import os
import time
from uuid import uuid4
from datetime import date
import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import text
from app.auth import hasher
from app.db import get_engine
from app.main import app

PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
PDF2 = b"%PDF-1.4\n2 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"  # distinct sha256 (dedup guard)


def _enroll(client, email, password, org):
    payload = {"email": email, "password": password, "organization_id": str(org)}
    first = client.post("/api/v1/auth/login", json=payload)
    assert first.status_code == 200, first.text
    h = {"Authorization": "Bearer " + first.json()["access_token"]}
    setup = client.post("/api/v1/auth/mfa/setup", headers=h, json={"password": password})
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    totp = pyotp.TOTP(secret)
    step = int(time.time() // 30)
    confirmed = client.post("/api/v1/auth/mfa/confirm", headers=h,
                            json={"password": password, "otp": totp.at((step - 1) * 30)})
    assert confirmed.status_code == 200, confirmed.text
    resp = client.post("/api/v1/auth/login", json={**payload, "otp": totp.at(step * 30)})
    if resp.status_code == 401:
        time.sleep(31)
        resp = client.post("/api/v1/auth/login", json={**payload, "otp": totp.at(int(time.time() // 30) * 30)})
    assert resp.status_code == 200, resp.text
    return {"Authorization": "Bearer " + resp.json()["access_token"]}, totp


def main():
    if os.environ.get("RIGHTS360_DISPOSABLE_E2E") != "1" or os.environ.get("POSTGRES_PASSWORD") != "ci-ephemeral-only":
        raise SystemExit("Refusing to run outside the CI ephemeral database")
    admin = get_engine(migration=True)
    org = uuid4()
    acc_a = uuid4()
    email_a = f"{acc_a}@example.invalid"
    password = "integration-test-password"
    with admin.begin() as conn:
        conn.execute(text("INSERT INTO organizations(id,slug,name) VALUES (:id,:slug,'GED test')"),
                     {"id": org, "slug": str(org)})
        conn.execute(text("INSERT INTO accounts(id,email,password_hash) VALUES (:id,:email,:hash)"),
                     {"id": acc_a, "email": email_a, "hash": hasher.hash(password)})
        conn.execute(text("INSERT INTO memberships(account_id,organization_id,role) VALUES (:id,:org,'admin')"),
                     {"id": acc_a, "org": org})
        conn.execute(text("INSERT INTO tenant_modules(organization_id,module_key,enabled) VALUES (:org,'documents',true)"), {"org": org})
        conn.execute(text("INSERT INTO module_entitlements(organization_id,module_key,granted) VALUES (:org,'documents',true)"), {"org": org})

    try:
        with TestClient(app) as client:
            headers, _ = _enroll(client, email_a, password, org)

            # 1. Create a document + upload v1 (no flags -> quarantine_status=clean).
            doc = client.post("/api/v1/documents", headers=headers,
                              json={"title": "Contrat 2026", "category": "contract"}).json()
            doc_id = doc["id"]
            pdf_headers = {**headers, "content-type": "application/pdf"}
            up1 = client.post(f"/api/v1/documents/{doc_id}/versions", headers=pdf_headers,
                              params={"expected_version": 0}, content=PDF)
            assert up1.status_code == 201, up1.text
            assert up1.json()["quarantine_status"] == "clean", up1.text

            # 2. Storage backend config.
            st = client.post("/api/v1/ged/storage", headers=headers,
                             json={"backend": "local", "encryption_enabled": True}).json()
            assert st["backend"] == "local" and st["encryption_enabled"] is True, st

            # 3. Quotas: tight -> upload 413; relaxed -> OK.
            client.post("/api/v1/ged/quotas", headers=headers, json={"max_bytes": 5, "max_documents": 100})
            q413 = client.post(f"/api/v1/documents/{doc_id}/versions", headers=pdf_headers,
                               params={"expected_version": 1}, content=PDF2)
            assert q413.status_code == 413, q413.text
            client.post("/api/v1/ged/quotas", headers=headers, json={"max_bytes": 1000000, "max_documents": 100})

            # 4. Quarantine flag ON -> new version quarantined; download blocked; scan clears.
            with admin.begin() as conn:
                conn.execute(text("UPDATE platform_settings SET value='true' WHERE key='documents_quarantine_enabled'"))
            up2 = client.post(f"/api/v1/documents/{doc_id}/versions", headers=pdf_headers,
                              params={"expected_version": 1}, content=PDF2)
            assert up2.status_code == 201 and up2.json()["quarantine_status"] == "quarantine", up2.text
            dl_q = client.get(f"/api/v1/documents/{doc_id}/versions/2/content", headers=headers)
            assert dl_q.status_code == 409, dl_q.text  # jamais de téléchargement en quarantaine
            scan = client.post(f"/api/v1/ged/documents/{doc_id}/versions/2/scan", headers=headers, json={"verdict": "clean"})
            assert scan.status_code == 201 and scan.json()["quarantine_status"] == "clean", scan.text
            dl_ok = client.get(f"/api/v1/documents/{doc_id}/versions/2/content", headers=headers)
            assert dl_ok.status_code == 200, dl_ok.text

            # 5. Metadata + search.
            md = client.post(f"/api/v1/ged/documents/{doc_id}/metadata", headers=headers,
                            json={"key": "invoice_ref", "value": "INV-2026-001"}).json()
            assert md["key"] == "invoice_ref", md
            search = client.get("/api/v1/ged/search", headers=headers, params={"q": "INV-2026-001"}).json()
            assert any(s["id"] == doc_id for s in search), search

            # 6. Litigation hold: hold -> 201, re-hold -> 409, release.
            hold = client.post(f"/api/v1/ged/documents/{doc_id}/litigation-hold", headers=headers,
                              json={"reason": "Audit en cours"}).json()
            assert "held_at" in hold, hold
            re_hold = client.post(f"/api/v1/ged/documents/{doc_id}/litigation-hold", headers=headers,
                                 json={"reason": "again"})
            assert re_hold.status_code == 409, re_hold.text
            rel = client.delete(f"/api/v1/ged/documents/{doc_id}/litigation-hold", headers=headers)
            assert rel.status_code == 200 and rel.json()["released"] is True, rel.text

            # 7. Presigned URL: anonymous download with ?token= works; bad token -> 401.
            presign = client.post(f"/api/v1/ged/documents/{doc_id}/versions/1/presign", headers=headers).json()
            assert "token" in presign and presign["url"], presign
            anon = client.get(f"/api/v1/documents/{doc_id}/versions/1/content",
                              params={"token": presign["token"]})  # NO Authorization header
            assert anon.status_code == 200, anon.text
            bad = client.get(f"/api/v1/documents/{doc_id}/versions/1/content", params={"token": "deadbeef"})
            assert bad.status_code == 401, bad.text

            # 8. Access journal records actions.
            log = client.get(f"/api/v1/ged/documents/{doc_id}/access-log", headers=headers).json()
            actions = {e["action"] for e in log}
            assert {"download", "presign", "scan", "hold", "release"} <= actions, actions

            print("GED module integration PASS: quarantine+scan, quotas, litigation hold/release, "
                  "metadata+search, presigned anonymous download, access journal")
    finally:
        with admin.begin() as conn:
            conn.execute(text("UPDATE platform_settings SET value='false' WHERE key='documents_quarantine_enabled'"))
            for t in ["document_access_log", "document_metadata", "document_litigation_holds",
                      "document_versions", "document_archives", "documents"]:
                conn.execute(text(f"DELETE FROM {t} WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM document_quotas WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM document_storage WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM document_retention_policies WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM audit_events WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM tenant_modules WHERE organization_id=:org"), {"org": org})
            conn.execute(text("DELETE FROM module_entitlements WHERE organization_id=:org AND module_key='documents'"), {"org": org})
            conn.execute(text("DELETE FROM auth_sessions WHERE account_id=:a"), {"a": acc_a})
            conn.execute(text("DELETE FROM mfa_recovery_codes WHERE account_id=:a"), {"a": acc_a})
            conn.execute(text("DELETE FROM account_mfa WHERE account_id=:a"), {"a": acc_a})
            conn.execute(text("DELETE FROM memberships WHERE account_id=:a"), {"a": acc_a})
            conn.execute(text("DELETE FROM accounts WHERE id=:a"), {"a": acc_a})
            conn.execute(text("DELETE FROM organizations WHERE id=:org"), {"org": org})


if __name__ == "__main__":
    main()
