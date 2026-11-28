"""PHASE 3 — Advanced copyright and related rights router.

Extends the works/artists rights model with:
  * ISRC recordings, IPI/ISNI holder identifiers and holder category,
  * territorial, time-bound rights grants (collective vs direct),
  * versioned, reproducible per-category distribution rules,
  * unidentified/pending rights amounts,
  * holder claims/adjustments with an independent approval workflow.

Gated on the existing 'works' tenant module (same as rights_shares.py). RBAC:
rights:read / rights:write / rights:decide. Sensitive actions (claim approval,
claim payout) require an independent rights:decide approver (self-review
blocked, advisory lock 365) and are journalized via audit_events.

Compliance: identifiers (ISWC/IPI/ISRC/ISNI) are validated at the format level
only; official registration with the competent bodies is the institution's
responsibility. No automated legal decision is taken.
"""
from datetime import date
from typing import Literal
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.exploitation import audit, conflict
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router = APIRouter(prefix="/api/v1/rights", tags=["rights-advanced"])

HolderCategory = Literal["author", "composer", "publisher", "producer_phonographic",
                         "producer_audiovisual", "performer", "heir", "mandatary", "other"]
GrantRole = Literal["author", "composer", "publisher", "producer_phonographic",
                    "producer_audiovisual", "performer", "heir", "mandatary", "other"]
RuleCategory = Literal["mechanical", "performance", "broadcast", "synchronization",
                       "digital", "public_lending", "other"]
AllocationRole = Literal["author", "composer", "publisher", "producer_phonographic",
                         "producer_audiovisual", "performer", "heir", "mandatary", "other"]


def _check_exists(conn, table, id_val, label):
    if not conn.execute(text(f"SELECT EXISTS(SELECT 1 FROM {table} WHERE id=:id)"), {"id": id_val}).scalar_one():
        raise HTTPException(404, f"{label} not found")


# ── Holder identifiers (category / IPI / ISNI on artists) ───────────────────
class HolderIdentifiers(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    category: HolderCategory | None = None
    ipi: str | None = Field(default=None, pattern=r"^[0-9]{9,11}$")
    isni: str | None = Field(default=None, pattern=r"^[0-9]{15}[0-9X]$")


@router.patch("/holders/{artist_id}")
def set_holder_identifiers(artist_id: UUID, payload: HolderIdentifiers, response: Response,
                           identity=Depends(require_permission("rights:write"))):
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "works")
            _check_exists(conn, "artists", artist_id, "Rights holder")
            conn.execute(text("""UPDATE artists SET category=:category, ipi=:ipi, isni=:isni, updated_at=now()
                WHERE id=:id"""),
                {"id": artist_id, "category": payload.category, "ipi": payload.ipi, "isni": payload.isni})
            audit(conn, identity, "rights.holder.identifiers", artist_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(artist_id)}


# ── Recordings (ISRC) ───────────────────────────────────────────────────────
class RecordingData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    work_id: UUID
    isrc: str = Field(min_length=12, max_length=12, pattern=r"^[A-Z]{2}[0-9A-Z]{3}[0-9]{2}[0-9]{5}$")
    title: str = Field(min_length=1, max_length=250)
    duration_seconds: int | None = Field(default=None, ge=0, le=86400)


@router.get("/recordings")
def list_recordings(response: Response, work_id: UUID | None = Query(None),
                    limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=1000000),
                    identity=Depends(require_permission("rights:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "works")
        rows = conn.execute(text("""SELECT id, work_id, isrc, title, duration_seconds, created_at
            FROM recordings WHERE CAST(:work_id AS uuid) IS NULL OR work_id=:work_id
            ORDER BY created_at DESC LIMIT :limit OFFSET :offset"""),
            {"work_id": work_id, "limit": limit, "offset": offset}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/recordings", status_code=201)
def create_recording(payload: RecordingData, response: Response, identity=Depends(require_permission("rights:write"))):
    rec_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "works")
            _check_exists(conn, "works", payload.work_id, "Work")
            conn.execute(text("""INSERT INTO recordings(id,organization_id,work_id,isrc,title,duration_seconds,created_by)
                VALUES(:id,:org,:work_id,:isrc,:title,:duration_seconds,:actor)"""),
                {"id": rec_id, "org": identity["organization_id"], "actor": identity["account_id"], **payload.model_dump()})
            audit(conn, identity, "rights.recording.created", rec_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(rec_id)}


# ── Territorial rights grants ───────────────────────────────────────────────
class GrantData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    work_id: UUID
    artist_id: UUID
    role: GrantRole
    territory: str = Field(min_length=1, max_length=100)
    scope: Literal["collective", "direct"]
    basis_points: StrictInt = Field(ge=1, le=10000)
    valid_from: date
    valid_until: date | None = None

    @model_validator(mode="after")
    def _dates(self):
        if self.valid_until is not None and self.valid_until < self.valid_from:
            raise ValueError("valid_until before valid_from")
        return self


@router.get("/grants")
def list_grants(response: Response, work_id: UUID | None = Query(None),
                limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=1000000),
                identity=Depends(require_permission("rights:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "works")
        rows = conn.execute(text("""SELECT id, work_id, artist_id, role, territory, scope, basis_points,
            valid_from, valid_until, status FROM rights_grants
            WHERE CAST(:work_id AS uuid) IS NULL OR work_id=:work_id
            ORDER BY created_at DESC LIMIT :limit OFFSET :offset"""),
            {"work_id": work_id, "limit": limit, "offset": offset}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/grants", status_code=201)
def create_grant(payload: GrantData, response: Response, identity=Depends(require_permission("rights:write"))):
    grant_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "works")
            _check_exists(conn, "works", payload.work_id, "Work")
            _check_exists(conn, "artists", payload.artist_id, "Rights holder")
            conn.execute(text("""INSERT INTO rights_grants(id,organization_id,work_id,artist_id,role,territory,scope,
                basis_points,valid_from,valid_until,created_by)
                VALUES(:id,:org,:work_id,:artist_id,:role,:territory,:scope,:basis_points,:valid_from,:valid_until,:actor)"""),
                {"id": grant_id, "org": identity["organization_id"], "actor": identity["account_id"], **payload.model_dump()})
            audit(conn, identity, "rights.grant.created", grant_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(grant_id)}


@router.post("/grants/{grant_id}/terminate")
def terminate_grant(grant_id: UUID, response: Response, identity=Depends(require_permission("rights:write"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "works")
        row = conn.execute(text("SELECT status, valid_until FROM rights_grants WHERE id=:id FOR UPDATE"), {"id": grant_id}).mappings().one_or_none()
        if row is None:
            raise HTTPException(404, "Rights grant not found")
        if row["status"] == "terminated":
            raise HTTPException(409, "Grant already terminated")
        conn.execute(text("UPDATE rights_grants SET status='terminated', valid_until=LEAST(COALESCE(valid_until,CURRENT_DATE),CURRENT_DATE) WHERE id=:id"), {"id": grant_id})
        audit(conn, identity, "rights.grant.terminated", grant_id)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(grant_id), "status": "terminated"}


# ── Distribution rules (versioned, reproducible) ────────────────────────────
class RuleData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    rule_category: RuleCategory
    expected_version: StrictInt = Field(ge=0)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    allocation: dict[AllocationRole, StrictInt]

    @model_validator(mode="after")
    def _allocation(self):
        if not self.allocation:
            raise ValueError("allocation required")
        if any(v < 0 or v > 10000 for v in self.allocation.values()):
            raise ValueError("basis_points out of range")
        if sum(self.allocation.values()) != 10000:
            raise ValueError("allocation must sum to 10000")
        return self


@router.get("/rules")
def list_rules(response: Response, rule_category: RuleCategory | None = Query(None),
               identity=Depends(require_permission("rights:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "works")
        rows = conn.execute(text("""SELECT id, rule_category, version, name, description, allocation, status, created_at
            FROM distribution_rules WHERE CAST(:cat AS text) IS NULL OR rule_category=:cat
            ORDER BY rule_category, version DESC"""),
            {"cat": rule_category}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/rules", status_code=201)
def create_rule(payload: RuleData, response: Response, identity=Depends(require_permission("rights:write"))):
    rule_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "works")
            current = conn.execute(text("SELECT COALESCE(max(version),0) FROM distribution_rules WHERE organization_id=:org AND rule_category=:cat"),
                                   {"org": identity["organization_id"], "cat": payload.rule_category}).scalar_one()
            if current != payload.expected_version:
                raise HTTPException(409, "Rule version changed")
            conn.execute(text("""INSERT INTO distribution_rules(id,organization_id,rule_category,version,name,description,allocation,status,created_by)
                VALUES(:id,:org,:rule_category,:version,:name,:description,CAST(:allocation AS jsonb),'draft',:actor)"""),
                {"id": rule_id, "org": identity["organization_id"], "actor": identity["account_id"],
                 "version": current + 1, "rule_category": payload.rule_category, "name": payload.name,
                 "description": payload.description, "allocation": __import__("json").dumps(payload.allocation)})
            audit(conn, identity, "rights.rule.created", rule_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(rule_id), "version": payload.expected_version + 1, "status": "draft"}


@router.post("/rules/{rule_id}/activate")
def activate_rule(rule_id: UUID, response: Response, identity=Depends(require_permission("rights:write"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "works")
        rule = conn.execute(text("SELECT id, rule_category, version, status FROM distribution_rules WHERE id=:id FOR UPDATE"), {"id": rule_id}).mappings().one_or_none()
        if rule is None:
            raise HTTPException(404, "Rule not found")
        if rule["status"] == "active":
            raise HTTPException(409, "Rule already active")
        # Supersede any previously active version of the same category.
        conn.execute(text("UPDATE distribution_rules SET status='superseded' WHERE organization_id=:org AND rule_category=:cat AND status='active'"),
                     {"org": identity["organization_id"], "cat": rule["rule_category"]})
        conn.execute(text("UPDATE distribution_rules SET status='active' WHERE id=:id"), {"id": rule_id})
        audit(conn, identity, "rights.rule.activated", rule_id)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(rule_id), "status": "active", "version": rule["version"]}


# ── Unidentified / pending rights ───────────────────────────────────────────
class UnidentifiedData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    distribution_id: UUID | None = None
    amount_minor: StrictInt = Field(gt=0, le=10**18)
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    reason: str = Field(min_length=1, max_length=200)


class UnidentifiedStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["identified", "expired"]


@router.get("/unidentified")
def list_unidentified(response: Response, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=1000000),
                      identity=Depends(require_permission("rights:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "works")
        rows = conn.execute(text("""SELECT id, distribution_id, amount_minor, currency, reason, status, created_at
            FROM rights_unidentified ORDER BY created_at DESC LIMIT :limit OFFSET :offset"""),
            {"limit": limit, "offset": offset}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/unidentified", status_code=201)
def create_unidentified(payload: UnidentifiedData, response: Response, identity=Depends(require_permission("rights:write"))):
    uid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "works")
            if payload.distribution_id is not None:
                _check_exists(conn, "royalty_distributions", payload.distribution_id, "Distribution")
            conn.execute(text("""INSERT INTO rights_unidentified(id,organization_id,distribution_id,amount_minor,currency,reason,created_by)
                VALUES(:id,:org,:distribution_id,:amount_minor,:currency,:reason,:actor)"""),
                {"id": uid, "org": identity["organization_id"], "actor": identity["account_id"], **payload.model_dump()})
            audit(conn, identity, "rights.unidentified.created", uid)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(uid)}


@router.patch("/unidentified/{uid}")
def update_unidentified(uid: UUID, payload: UnidentifiedStatus, response: Response, identity=Depends(require_permission("rights:write"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "works")
        row = conn.execute(text("SELECT status FROM rights_unidentified WHERE id=:id FOR UPDATE"), {"id": uid}).mappings().one_or_none()
        if row is None:
            raise HTTPException(404, "Unidentified record not found")
        if row["status"] != "pending":
            raise HTTPException(409, "Unidentified record already resolved")
        conn.execute(text("UPDATE rights_unidentified SET status=:status WHERE id=:id"), {"id": uid, "status": payload.status})
        audit(conn, identity, f"rights.unidentified.{payload.status}", uid)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(uid), "status": payload.status}


# ── Claims / adjustments (approval workflow) ────────────────────────────────
class ClaimData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    claimant_artist_id: UUID
    work_id: UUID | None = None
    unidentified_id: UUID | None = None
    amount_minor: StrictInt = Field(gt=0, le=10**18)
    currency: str = Field(min_length=3, max_length=3, pattern=r"^[A-Z]{3}$")
    justification: str = Field(min_length=1, max_length=4000)


class ClaimReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "reject"]


@router.get("/claims")
def list_claims(response: Response, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=1000000),
               identity=Depends(require_permission("rights:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "works")
        rows = conn.execute(text("""SELECT id, claimant_artist_id, work_id, unidentified_id, amount_minor, currency,
            justification, status, proposed_by, proposed_at, reviewed_by, reviewed_at
            FROM rights_claims ORDER BY proposed_at DESC LIMIT :limit OFFSET :offset"""),
            {"limit": limit, "offset": offset}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/claims", status_code=201)
def create_claim(payload: ClaimData, response: Response, identity=Depends(require_permission("rights:write"))):
    claim_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "works")
            _check_exists(conn, "artists", payload.claimant_artist_id, "Rights holder")
            if payload.work_id is not None:
                _check_exists(conn, "works", payload.work_id, "Work")
            if payload.unidentified_id is not None:
                _check_exists(conn, "rights_unidentified", payload.unidentified_id, "Unidentified record")
            conn.execute(text("""INSERT INTO rights_claims(id,organization_id,claimant_artist_id,work_id,unidentified_id,
                amount_minor,currency,justification,proposed_by)
                VALUES(:id,:org,:claimant_artist_id,:work_id,:unidentified_id,:amount_minor,:currency,:justification,:actor)"""),
                {"id": claim_id, "org": identity["organization_id"], "actor": identity["account_id"], **payload.model_dump()})
            audit(conn, identity, "rights.claim.created", claim_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(claim_id), "status": "pending"}


@router.post("/claims/{claim_id}/review")
def review_claim(claim_id: UUID, payload: ClaimReview, response: Response, identity=Depends(require_permission("rights:decide"))):
    actor = identity["account_id"]
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "works")
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text),365))"), {"id": claim_id})
        claim = conn.execute(text("SELECT * FROM rights_claims WHERE id=:id"), {"id": claim_id}).mappings().one_or_none()
        if claim is None:
            raise HTTPException(404, "Claim not found")
        if claim["status"] != "pending":
            raise HTTPException(409, "Claim already reviewed")
        if str(claim["proposed_by"]) == str(actor):
            raise HTTPException(409, "Independent review required")
        new_status = "approved" if payload.decision == "approve" else "rejected"
        conn.execute(text("UPDATE rights_claims SET status=:status, reviewed_by=:actor, reviewed_at=now() WHERE id=:id"),
                     {"id": claim_id, "status": new_status, "actor": actor})
        audit(conn, identity, f"rights.claim.{new_status}", claim_id)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(claim_id), "status": new_status}


@router.post("/claims/{claim_id}/paid")
def mark_claim_paid(claim_id: UUID, response: Response, identity=Depends(require_permission("rights:decide"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "works")
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text),365))"), {"id": claim_id})
        row = conn.execute(text("SELECT status FROM rights_claims WHERE id=:id FOR UPDATE"), {"id": claim_id}).mappings().one_or_none()
        if row is None:
            raise HTTPException(404, "Claim not found")
        if row["status"] != "approved":
            raise HTTPException(409, "Claim must be approved first")
        conn.execute(text("UPDATE rights_claims SET status='paid' WHERE id=:id"), {"id": claim_id})
        audit(conn, identity, "rights.claim.paid", claim_id)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(claim_id), "status": "paid"}
