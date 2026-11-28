"""PHASE 6 — GED entreprise router (`/api/v1/ged`).

Enterprise document-management endpoints layered on the existing documents
flow (0026 + documents.py): storage backend config, quotas, retention
policies, litigation holds, metadata + search, presigned URLs, quarantine
scan, access journal. The behavioral hooks (quarantine on upload, quota
enforcement, access logging) live in documents.py; this router exposes the
configuration + read surfaces.

RBAC: documents:read / documents:write (existing) + documents:admin (new:
storage, quotas, retention, litigation, scan, access-log).
"""
from typing import Literal
from uuid import UUID, uuid4
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.billing import serialize
from app.exploitation import audit, conflict
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app import storage

router = APIRouter(prefix="/api/v1/ged", tags=["ged"])


# ── Pydantic payloads ────────────────────────────────────────────────────────
class StorageData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    backend: Literal["local", "s3", "b2"] = "local"
    bucket: str | None = None
    endpoint: str | None = None
    region: str | None = None
    credentials_ref: str | None = None
    encryption_enabled: bool = False


class QuotaData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_bytes: int
    max_documents: int
    enforced: bool = True

    @field_validator("max_bytes", "max_documents")
    @classmethod
    def _positive(cls, v):
        if v <= 0:
            raise ValueError("must be positive")
        return v


class RetentionData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str
    retain_days: int
    legal_hold_default: bool = False

    @field_validator("category")
    @classmethod
    def _cat(cls, v):
        if not v or len(v) > 30:
            raise ValueError("category must be 1-30 chars")
        return v

    @field_validator("retain_days")
    @classmethod
    def _days(cls, v):
        if v < 0:
            raise ValueError("retain_days must be >= 0")
        return v


class LitigationData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str

    @field_validator("reason")
    @classmethod
    def _reason(cls, v):
        if not v or len(v) > 500:
            raise ValueError("reason must be 1-500 chars")
        return v


class MetadataData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    value: str

    @field_validator("key")
    @classmethod
    def _key(cls, v):
        if not v or len(v) > 80:
            raise ValueError("key must be 1-80 chars")
        return v


class ScanData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["clean", "infected"]


# ── Storage backend config ───────────────────────────────────────────────────
@router.get("/storage")
def get_storage(response: Response, identity=Depends(require_permission("documents:admin"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        row = conn.execute(text("""SELECT backend, bucket, endpoint, region, credentials_ref, encryption_enabled
            FROM document_storage WHERE organization_id=:org"""), {"org": identity["organization_id"]}).mappings().one_or_none()
    response.headers["Cache-Control"] = "no-store"
    return dict(row) if row else {"backend": "local", "encryption_enabled": False}


@router.post("/storage", status_code=201)
def set_storage(payload: StorageData, response: Response, identity=Depends(require_permission("documents:admin"))):
    sid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            row = conn.execute(text("""INSERT INTO document_storage(id,organization_id,backend,bucket,endpoint,region,
                credentials_ref,encryption_enabled,created_by)
                VALUES(:id,:org,:backend,:bucket,:endpoint,:region,:creds,:enc,:actor)
                ON CONFLICT (organization_id) DO UPDATE SET
                  backend=EXCLUDED.backend, bucket=EXCLUDED.bucket, endpoint=EXCLUDED.endpoint,
                  region=EXCLUDED.region, credentials_ref=EXCLUDED.credentials_ref,
                  encryption_enabled=EXCLUDED.encryption_enabled
                RETURNING backend, bucket, encryption_enabled"""),
                {"id": sid, "org": identity["organization_id"], "backend": payload.backend,
                 "bucket": payload.bucket, "endpoint": payload.endpoint, "region": payload.region,
                 "creds": payload.credentials_ref, "enc": payload.encryption_enabled,
                 "actor": identity["account_id"]}).mappings().one()
            audit(conn, identity, "ged.storage.configured", sid)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


# ── Quotas ───────────────────────────────────────────────────────────────────
@router.get("/quotas")
def get_quota(response: Response, identity=Depends(require_permission("documents:admin"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        row = conn.execute(text("""SELECT max_bytes, max_documents, enforced,
            (SELECT COALESCE(sum(size_bytes),0) FROM document_versions WHERE organization_id=:org) AS used_bytes,
            (SELECT count(*) FROM documents WHERE organization_id=:org) AS used_documents
            FROM document_quotas WHERE organization_id=:org"""), {"org": identity["organization_id"]}).mappings().one_or_none()
    response.headers["Cache-Control"] = "no-store"
    return dict(row) if row else {"enforced": False, "used_bytes": 0, "used_documents": 0}


@router.post("/quotas", status_code=201)
def set_quota(payload: QuotaData, response: Response, identity=Depends(require_permission("documents:admin"))):
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            row = conn.execute(text("""INSERT INTO document_quotas(organization_id,max_bytes,max_documents,enforced,updated_by)
                VALUES(:org,:max_bytes,:max_docs,:enforced,:actor)
                ON CONFLICT (organization_id) DO UPDATE SET
                  max_bytes=EXCLUDED.max_bytes, max_documents=EXCLUDED.max_documents,
                  enforced=EXCLUDED.enforced, updated_by=EXCLUDED.updated_by, updated_at=now()
                RETURNING max_bytes, max_documents, enforced"""),
                {"org": identity["organization_id"], "max_bytes": payload.max_bytes,
                 "max_docs": payload.max_documents, "enforced": payload.enforced,
                 "actor": identity["account_id"]}).mappings().one()
            audit(conn, identity, "ged.quota.set", identity["organization_id"])
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


# ── Retention policies ───────────────────────────────────────────────────────
@router.get("/retention-policies")
def list_retention(response: Response, identity=Depends(require_permission("documents:admin"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        rows = conn.execute(text("""SELECT category, retain_days, legal_hold_default
            FROM document_retention_policies WHERE organization_id=:org ORDER BY category"""),
            {"org": identity["organization_id"]}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/retention-policies", status_code=201)
def set_retention(payload: RetentionData, response: Response, identity=Depends(require_permission("documents:admin"))):
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            row = conn.execute(text("""INSERT INTO document_retention_policies(organization_id,category,retain_days,legal_hold_default,updated_by)
                VALUES(:org,:category,:days,:lh,:actor)
                ON CONFLICT (organization_id, category) DO UPDATE SET
                  retain_days=EXCLUDED.retain_days, legal_hold_default=EXCLUDED.legal_hold_default,
                  updated_by=EXCLUDED.updated_by, updated_at=now()
                RETURNING category, retain_days, legal_hold_default"""),
                {"org": identity["organization_id"], "category": payload.category,
                 "days": payload.retain_days, "lh": payload.legal_hold_default,
                 "actor": identity["account_id"]}).mappings().one()
            audit(conn, identity, "ged.retention.set", identity["organization_id"])
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


# ── Litigation hold ──────────────────────────────────────────────────────────
@router.post("/documents/{doc_id}/litigation-hold", status_code=201)
def hold(doc_id: UUID, payload: LitigationData, response: Response,
         identity=Depends(require_permission("documents:admin"))):
    hid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            exists = conn.execute(text("SELECT 1 FROM documents WHERE id=:id AND organization_id=:org"),
                                  {"id": doc_id, "org": identity["organization_id"]}).scalar_one_or_none()
            if exists is None:
                raise HTTPException(404, "Document not found")
            row = conn.execute(text("""INSERT INTO document_litigation_holds(id,organization_id,document_id,reason,held_by)
                VALUES(:id,:org,:doc,:reason,:actor)
                ON CONFLICT (organization_id, document_id) WHERE released_at IS NULL DO NOTHING
                RETURNING id, reason, held_at"""),
                {"id": hid, "org": identity["organization_id"], "doc": doc_id,
                 "reason": payload.reason, "actor": identity["account_id"]}).mappings().one_or_none()
            if row is None:
                raise HTTPException(409, "Document already under hold")
            conn.execute(text("UPDATE documents SET litigation_hold=true WHERE id=:id AND organization_id=:org"),
                         {"id": doc_id, "org": identity["organization_id"]})
            conn.execute(text("""INSERT INTO document_access_log(id,organization_id,document_id,action,account_id)
                VALUES(:lid,:org,:doc,'hold',:actor)"""),
                {"lid": uuid4(), "org": identity["organization_id"], "doc": doc_id, "actor": identity["account_id"]})
            audit(conn, identity, "ged.litigation.held", hid)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


@router.delete("/documents/{doc_id}/litigation-hold")
def release_hold(doc_id: UUID, response: Response,
                 identity=Depends(require_permission("documents:admin"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        row = conn.execute(text("""UPDATE document_litigation_holds SET released_at=now()
            WHERE document_id=:doc AND organization_id=:org AND released_at IS NULL
            RETURNING id"""),
            {"doc": doc_id, "org": identity["organization_id"]}).mappings().one_or_none()
        if row is None:
            raise HTTPException(404, "No active hold")
        conn.execute(text("UPDATE documents SET litigation_hold=false WHERE id=:id AND organization_id=:org"),
                     {"id": doc_id, "org": identity["organization_id"]})
        conn.execute(text("""INSERT INTO document_access_log(id,organization_id,document_id,action,account_id)
            VALUES(:lid,:org,:doc,'release',:actor)"""),
            {"lid": uuid4(), "org": identity["organization_id"], "doc": doc_id, "actor": identity["account_id"]})
        audit(conn, identity, "ged.litigation.released", row["id"])
    response.headers["Cache-Control"] = "no-store"
    return {"released": True}


# ── Metadata ─────────────────────────────────────────────────────────────────
@router.get("/documents/{doc_id}/metadata")
def list_metadata(doc_id: UUID, response: Response, identity=Depends(require_permission("documents:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        rows = conn.execute(text("""SELECT key, value FROM document_metadata
            WHERE document_id=:doc AND organization_id=:org ORDER BY key"""),
            {"doc": doc_id, "org": identity["organization_id"]}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/documents/{doc_id}/metadata", status_code=201)
def set_metadata(doc_id: UUID, payload: MetadataData, response: Response,
                 identity=Depends(require_permission("documents:write"))):
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            exists = conn.execute(text("SELECT 1 FROM documents WHERE id=:id AND organization_id=:org"),
                                  {"id": doc_id, "org": identity["organization_id"]}).scalar_one_or_none()
            if exists is None:
                raise HTTPException(404, "Document not found")
            row = conn.execute(text("""INSERT INTO document_metadata(id,organization_id,document_id,key,value,created_by)
                VALUES(:id,:org,:doc,:key,:value,:actor)
                ON CONFLICT (organization_id, document_id, key) DO UPDATE SET value=EXCLUDED.value
                RETURNING key, value"""),
                {"id": uuid4(), "org": identity["organization_id"], "doc": doc_id,
                 "key": payload.key, "value": payload.value, "actor": identity["account_id"]}).mappings().one()
            audit(conn, identity, "ged.metadata.set", doc_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


# ── Search (by title / category / metadata) ──────────────────────────────────
@router.get("/search")
def search(response: Response, q: str = Query("", max_length=200),
           category: str | None = Query(None, max_length=30),
           limit: int = Query(50, ge=1, le=200),
           identity=Depends(require_permission("documents:read"))):
    cat = category or ""
    with tenant_transaction(identity["organization_id"]) as conn:
        rows = conn.execute(text("""SELECT DISTINCT d.id, d.title, d.category, d.litigation_hold,
            d.retention_until, max(v.version) AS latest_version, max(v.quarantine_status) AS quarantine_status
            FROM documents d
            LEFT JOIN document_versions v ON v.document_id=d.id AND v.organization_id=d.organization_id
            LEFT JOIN document_metadata m ON m.document_id=d.id AND m.organization_id=d.organization_id
            WHERE d.organization_id=:org
              AND (:category='' OR d.category=:category)
              AND (:q='' OR d.title ILIKE '%'||:q||'%' OR m.value ILIKE '%'||:q||'%' OR m.key ILIKE '%'||:q||'%')
            GROUP BY d.id, d.title, d.category, d.litigation_hold, d.retention_until
            ORDER BY d.title LIMIT :limit"""),
            {"org": identity["organization_id"], "category": cat, "q": q, "limit": limit}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [serialize(r) for r in rows]


# ── Presigned URL (time-limited download token) ──────────────────────────────
@router.post("/documents/{doc_id}/versions/{version}/presign")
def presign(doc_id: UUID, version: int, response: Response,
            expires_in: int = Query(900, ge=60, le=86400),
            identity=Depends(require_permission("documents:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        row = conn.execute(text("""SELECT v.quarantine_status, v.object_key
            FROM document_versions v WHERE v.document_id=:doc AND v.version=:ver AND v.organization_id=:org"""),
            {"doc": doc_id, "ver": version, "org": identity["organization_id"]}).mappings().one_or_none()
        if row is None:
            raise HTTPException(404, "Version not found")
        if row["quarantine_status"] == "quarantine":
            raise HTTPException(409, "Document in quarantine — presign refused")
        # Token encodes org|doc|version so the anonymous download can resolve the tenant
        # and confirm the token matches the requested path (no cross-doc reuse).
        key = f"{identity['organization_id']}|{doc_id}|{version}"
        token = storage.presign(key, expires_in)
        conn.execute(text("""INSERT INTO document_access_log(id,organization_id,document_id,version,action,account_id)
            VALUES(:lid,:org,:doc,:ver,'presign',:actor)"""),
            {"lid": uuid4(), "org": identity["organization_id"], "doc": doc_id, "ver": version,
             "actor": identity["account_id"]})
        audit(conn, identity, "ged.presign.issued", doc_id)
    expires_at = datetime.now(timezone.utc).timestamp() + expires_in
    response.headers["Cache-Control"] = "no-store"
    return {"url": f"/api/v1/documents/{doc_id}/versions/{version}/content?token={token}",
            "expires_at": int(expires_at), "token": token}


# ── Quarantine scan (admin records the antivirus verdict) ────────────────────
@router.post("/documents/{doc_id}/versions/{version}/scan", status_code=201)
def scan(doc_id: UUID, version: int, payload: ScanData, response: Response,
         identity=Depends(require_permission("documents:admin"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        row = conn.execute(text("""UPDATE document_versions SET quarantine_status=:verdict
            WHERE document_id=:doc AND version=:ver AND organization_id=:org
            RETURNING quarantine_status"""),
            {"doc": doc_id, "ver": version, "verdict": payload.verdict,
             "org": identity["organization_id"]}).mappings().one_or_none()
        if row is None:
            raise HTTPException(404, "Version not found")
        conn.execute(text("""INSERT INTO document_access_log(id,organization_id,document_id,version,action,account_id)
            VALUES(:lid,:org,:doc,:ver,'scan',:actor)"""),
            {"lid": uuid4(), "org": identity["organization_id"], "doc": doc_id, "ver": version,
             "actor": identity["account_id"]})
        audit(conn, identity, "ged.scan." + payload.verdict, doc_id)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


# ── Access journal ───────────────────────────────────────────────────────────
@router.get("/documents/{doc_id}/access-log")
def access_log(doc_id: UUID, response: Response, limit: int = Query(100, ge=1, le=500),
               identity=Depends(require_permission("documents:admin"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        rows = conn.execute(text("""SELECT action, version, account_id, ip_hash, occurred_at
            FROM document_access_log WHERE document_id=:doc AND organization_id=:org
            ORDER BY occurred_at DESC, id LIMIT :limit"""),
            {"doc": doc_id, "org": identity["organization_id"], "limit": limit}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [serialize(r) for r in rows]
