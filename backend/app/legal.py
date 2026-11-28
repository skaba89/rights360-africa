"""PHASE 2 — Legal and litigation module router.

Activable per institution via the 'legal' tenant module + entitlement. Every
route authenticates and authorizes membership, then opens a tenant_transaction
so RLS scopes all rows to the caller's organization.

Sensitive case-status transitions (amicable / judicial / resolved / closed /
withdrawn) CANNOT be set directly: they must be proposed as a legal_decisions
record and approved by a second, independent administrator (legal:decide). This
implements the mandatory human validation of sensitive decisions. Mandate
revocation and succession approval require a single legal:decide approver plus
an immutable audit event.

Compliance: this module records legal operational data; it does NOT take any
automated legal decision and MUST NOT be presented as conformant to any
jurisdiction without validation by a locally qualified legal professional.
"""
from datetime import date
from typing import Literal
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.exploitation import audit, conflict
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router = APIRouter(prefix="/api/v1/legal", tags=["legal"])

# Statuses that affect rights and therefore require a reviewed decision.
SENSITIVE_TRANSITIONS = frozenset({"amicable", "judicial", "resolved", "closed", "withdrawn"})

CaseCategory = Literal["rights_dispute", "operator_dispute", "claim", "share_challenge", "succession", "contract", "other"]
CaseStatus = Literal["open", "in_review", "amicable", "judicial", "resolved", "closed", "withdrawn"]
Priority = Literal["low", "normal", "high", "urgent"]
Counterpart = Literal["artist", "operator", "member", "external"]


class CaseData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    case_number: str = Field(min_length=1, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")
    title: str = Field(min_length=1, max_length=200)
    category: CaseCategory
    priority: Priority = "normal"
    counterpart_type: Counterpart
    counterpart_ref: str | None = Field(default=None, max_length=200)
    summary: str | None = Field(default=None, max_length=4000)
    opened_on: date


class CaseStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "in_review"]  # only non-sensitive direct transitions


class PartyData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    role: Literal["claimant", "respondent", "heir", "representative", "witness", "other"]
    account_id: UUID | None = None
    external_name: str | None = Field(default=None, max_length=200)
    external_contact: str | None = Field(default=None, max_length=200)


class EventData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    kind: Literal["claim", "notice", "amicable", "judicial", "decision", "hearing", "correspondence", "other"]
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    occurred_on: date


class DecisionProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    proposed_status: CaseStatus
    rationale: str = Field(min_length=1, max_length=4000)


class DecisionReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "reject"]


class DeadlineData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    label: str = Field(min_length=1, max_length=200)
    due_at: date  # calendar date; stored as midnight UTC timestamp
    kind: Literal["hearing", "filing", "response", "notice", "other"]


class DeadlineStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["pending", "met", "missed"]
    notified: bool | None = None


class MandateData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    case_id: UUID | None = None
    mandatee_account_id: UUID | None = None
    mandatee_external: str | None = Field(default=None, max_length=200)
    scope: str = Field(min_length=1, max_length=4000)
    territory: str = Field(min_length=1, max_length=100)
    valid_from: date
    valid_until: date | None = None


class SuccessionData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deceased_account_id: UUID
    heir_account_id: UUID
    share_basis_points: StrictInt = Field(ge=1, le=10000)
    declared_on: date


class ContractData(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    kind: Literal["reciprocity", "representation", "settlement", "other"]
    title: str = Field(min_length=1, max_length=200)
    counterpart: str = Field(min_length=1, max_length=200)
    territory: str = Field(min_length=1, max_length=100)
    valid_from: date
    valid_until: date | None = None


class CaseDocumentLink(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document_id: UUID


def case_exists(conn, case_id, lock=False):
    sql = "SELECT id FROM legal_cases WHERE id=:id" + (" FOR UPDATE" if lock else "")
    if conn.execute(text(sql), {"id": case_id}).scalar_one_or_none() is None:
        raise HTTPException(404, "Legal case not found")


# ── Cases ────────────────────────────────────────────────────────────────────
@router.get("/cases")
def list_cases(response: Response, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=1000000),
               identity=Depends(require_permission("legal:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        rows = conn.execute(text("""SELECT id, case_number, title, category, status, priority,
            counterpart_type, counterpart_ref, opened_on, closed_on, created_at
            FROM legal_cases ORDER BY opened_on DESC, created_at DESC LIMIT :limit OFFSET :offset"""),
            {"limit": limit, "offset": offset}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/cases", status_code=201)
def create_case(payload: CaseData, response: Response, identity=Depends(require_permission("legal:write"))):
    case_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "legal")
            row = conn.execute(text("""INSERT INTO legal_cases(id,organization_id,case_number,title,category,status,priority,
                counterpart_type,counterpart_ref,summary,opened_on,created_by)
                VALUES(:id,:org,:case_number,:title,:category,'open',:priority,:counterpart_type,:counterpart_ref,:summary,:opened_on,:actor)
                RETURNING id,case_number,title,category,status,priority,counterpart_type,opened_on"""),
                {"id": case_id, "org": identity["organization_id"], "actor": identity["account_id"], **payload.model_dump()}).mappings().one()
            audit(conn, identity, "legal.case.created", case_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


@router.get("/cases/{case_id}")
def get_case(case_id: UUID, response: Response, identity=Depends(require_permission("legal:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        case_exists(conn, case_id)
        row = conn.execute(text("""SELECT * FROM legal_cases WHERE id=:id"""), {"id": case_id}).mappings().one()
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


@router.patch("/cases/{case_id}/status")
def update_case_status(case_id: UUID, payload: CaseStatusUpdate, response: Response,
                       identity=Depends(require_permission("legal:write"))):
    # Only non-sensitive transitions are allowed directly; sensitive ones need a
    # reviewed decision (see propose_decision / review_decision).
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        case_exists(conn, case_id, lock=True)
        old = conn.execute(text("SELECT status FROM legal_cases WHERE id=:id"), {"id": case_id}).scalar_one()
        if old in SENSITIVE_TRANSITIONS:
            raise HTTPException(409, "Case is in a sensitive status; use a reviewed decision")
        if payload.status == old:
            raise HTTPException(409, "Case already in that status")
        conn.execute(text("UPDATE legal_cases SET status=:status, updated_at=now() WHERE id=:id"),
                     {"id": case_id, "status": payload.status})
        audit(conn, identity, "legal.case.status", case_id)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(case_id), "status": payload.status}


# ── Parties ──────────────────────────────────────────────────────────────────
@router.post("/cases/{case_id}/parties", status_code=201)
def add_party(case_id: UUID, payload: PartyData, response: Response, identity=Depends(require_permission("legal:write"))):
    party_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "legal")
            case_exists(conn, case_id, lock=True)
            if payload.account_id is None and not payload.external_name:
                raise HTTPException(422, "Party identity required")
            conn.execute(text("""INSERT INTO legal_case_parties(id,organization_id,case_id,role,account_id,external_name,external_contact,added_by)
                VALUES(:id,:org,:cid,:role,:account_id,:external_name,:external_contact,:actor)"""),
                {"id": party_id, "org": identity["organization_id"], "cid": case_id, "actor": identity["account_id"], **payload.model_dump()})
            audit(conn, identity, "legal.party.added", party_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(party_id)}


# ── Events / history (immutable) ─────────────────────────────────────────────
@router.get("/cases/{case_id}/events")
def list_events(case_id: UUID, response: Response, identity=Depends(require_permission("legal:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        case_exists(conn, case_id)
        rows = conn.execute(text("""SELECT kind,title,description,occurred_on,created_by,created_at
            FROM legal_case_events WHERE case_id=:id ORDER BY occurred_on DESC, created_at DESC LIMIT 200"""),
            {"id": case_id}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/cases/{case_id}/events", status_code=201)
def add_event(case_id: UUID, payload: EventData, response: Response, identity=Depends(require_permission("legal:write"))):
    event_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "legal")
            case_exists(conn, case_id, lock=True)
            conn.execute(text("""INSERT INTO legal_case_events(id,organization_id,case_id,kind,title,description,occurred_on,created_by)
                VALUES(:id,:org,:cid,:kind,:title,:description,:occurred_on,:actor)"""),
                {"id": event_id, "org": identity["organization_id"], "cid": case_id, "actor": identity["account_id"], **payload.model_dump()})
            audit(conn, identity, "legal.event.added", event_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(event_id)}


# ── Sensitive decisions (double review) ──────────────────────────────────────
@router.post("/cases/{case_id}/decisions", status_code=201)
def propose_decision(case_id: UUID, payload: DecisionProposal, response: Response,
                     identity=Depends(require_permission("legal:write"))):
    if payload.proposed_status not in SENSITIVE_TRANSITIONS:
        raise HTTPException(422, "Proposed status is not a sensitive transition")
    decision_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "legal")
            case_exists(conn, case_id, lock=True)
            current = conn.execute(text("SELECT status FROM legal_cases WHERE id=:id"), {"id": case_id}).scalar_one()
            if payload.proposed_status == current:
                raise HTTPException(409, "Case already in that status")
            conn.execute(text("""INSERT INTO legal_decisions(id,organization_id,case_id,proposed_action,proposed_status,rationale,proposed_by)
                VALUES(:id,:org,:cid,'transition',:status,:rationale,:actor)"""),
                {"id": decision_id, "org": identity["organization_id"], "cid": case_id,
                 "status": payload.proposed_status, "rationale": payload.rationale, "actor": identity["account_id"]})
            audit(conn, identity, "legal.decision.proposed", decision_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(decision_id), "status": "pending"}


@router.get("/cases/{case_id}/decisions")
def list_decisions(case_id: UUID, response: Response, identity=Depends(require_permission("legal:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        case_exists(conn, case_id)
        rows = conn.execute(text("""SELECT id,proposed_action,proposed_status,rationale,status,proposed_by,proposed_at,reviewed_by,reviewed_at
            FROM legal_decisions WHERE case_id=:id ORDER BY proposed_at DESC LIMIT 200"""), {"id": case_id}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/decisions/{decision_id}/review")
def review_decision(decision_id: UUID, payload: DecisionReview, response: Response,
                     identity=Depends(require_permission("legal:decide"))):
    actor = identity["account_id"]
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text),364))"), {"id": decision_id})
        decision = conn.execute(text("SELECT * FROM legal_decisions WHERE id=:id"), {"id": decision_id}).mappings().one_or_none()
        if decision is None:
            raise HTTPException(404, "Decision not found")
        if decision["status"] != "pending":
            raise HTTPException(409, "Decision already reviewed")
        if str(decision["proposed_by"]) == str(actor):
            raise HTTPException(409, "Independent review required")
        new_status = "approved" if payload.decision == "approve" else "rejected"
        conn.execute(text("UPDATE legal_decisions SET status=:status, reviewed_by=:actor, reviewed_at=now() WHERE id=:id"),
                     {"id": decision_id, "status": new_status, "actor": actor})
        if payload.decision == "approve" and decision["proposed_action"] == "transition":
            target = decision["proposed_status"]
            if target in ("resolved", "closed"):
                conn.execute(text("UPDATE legal_cases SET status=:status, closed_on=CURRENT_DATE, updated_at=now() WHERE id=:cid"),
                             {"status": target, "cid": decision["case_id"]})
            else:
                conn.execute(text("UPDATE legal_cases SET status=:status, updated_at=now() WHERE id=:cid"),
                             {"status": target, "cid": decision["case_id"]})
            conn.execute(text("""INSERT INTO legal_case_events(id,organization_id,case_id,kind,title,description,occurred_on,created_by)
                VALUES(:id,:org,:cid,'decision',:title,:desc,CURRENT_DATE,:actor)"""),
                {"id": uuid4(), "org": identity["organization_id"], "cid": decision["case_id"],
                 "title": f"Statut validé → {target}", "desc": decision["rationale"] or "", "actor": actor})
        audit(conn, identity, f"legal.decision.{new_status}", decision_id)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(decision_id), "status": new_status,
            "applied": decision["proposed_action"] if payload.decision == "approve" else None}


# ── Deadlines ────────────────────────────────────────────────────────────────
@router.get("/cases/{case_id}/deadlines")
def list_deadlines(case_id: UUID, response: Response, identity=Depends(require_permission("legal:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        case_exists(conn, case_id)
        rows = conn.execute(text("""SELECT id,label,due_at,kind,status,notified FROM legal_deadlines
            WHERE case_id=:id ORDER BY due_at ASC LIMIT 200"""), {"id": case_id}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/cases/{case_id}/deadlines", status_code=201)
def add_deadline(case_id: UUID, payload: DeadlineData, response: Response, identity=Depends(require_permission("legal:write"))):
    deadline_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "legal")
            case_exists(conn, case_id, lock=True)
            conn.execute(text("""INSERT INTO legal_deadlines(id,organization_id,case_id,label,due_at,kind,created_by)
                VALUES(:id,:org,:cid,:label,CAST(:due_at AS timestamptz),:kind,:actor)"""),
                {"id": deadline_id, "org": identity["organization_id"], "cid": case_id, "actor": identity["account_id"], **payload.model_dump()})
            audit(conn, identity, "legal.deadline.added", deadline_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(deadline_id)}


@router.patch("/deadlines/{deadline_id}")
def update_deadline(deadline_id: UUID, payload: DeadlineStatus, response: Response, identity=Depends(require_permission("legal:write"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        row = conn.execute(text("SELECT id FROM legal_deadlines WHERE id=:id FOR UPDATE"), {"id": deadline_id}).mappings().one_or_none()
        if row is None:
            raise HTTPException(404, "Deadline not found")
        conn.execute(text("UPDATE legal_deadlines SET status=:status, notified=COALESCE(:notified, notified) WHERE id=:id"),
                     {"id": deadline_id, "status": payload.status, "notified": payload.notified})
        audit(conn, identity, "legal.deadline.updated", deadline_id)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(deadline_id), "status": payload.status}


# ── Case documents (link to existing GED) ────────────────────────────────────
@router.post("/cases/{case_id}/documents", status_code=201)
def link_document(case_id: UUID, payload: CaseDocumentLink, response: Response, identity=Depends(require_permission("legal:write"))):
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "legal")
            case_exists(conn, case_id, lock=True)
            # Document must exist in the same tenant (RLS scopes the check).
            if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM documents WHERE id=:id)"), {"id": payload.document_id}).scalar_one():
                raise HTTPException(404, "Document not found")
            conn.execute(text("""INSERT INTO legal_case_documents(organization_id,case_id,document_id,linked_by)
                VALUES(:org,:cid,:doc,:actor) ON CONFLICT DO NOTHING"""),
                {"org": identity["organization_id"], "cid": case_id, "doc": payload.document_id, "actor": identity["account_id"]})
            audit(conn, identity, "legal.document.linked", payload.document_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"case_id": str(case_id), "document_id": str(payload.document_id)}


@router.get("/cases/{case_id}/documents")
def list_documents(case_id: UUID, response: Response, identity=Depends(require_permission("legal:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        case_exists(conn, case_id)
        rows = conn.execute(text("""SELECT d.id, d.title, d.category, lcd.linked_at
            FROM legal_case_documents lcd JOIN documents d ON d.organization_id=lcd.organization_id AND d.id=lcd.document_id
            WHERE lcd.case_id=:id ORDER BY lcd.linked_at DESC"""), {"id": case_id}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


# ── Mandates ─────────────────────────────────────────────────────────────────
@router.get("/mandates")
def list_mandates(response: Response, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=1000000),
                 identity=Depends(require_permission("legal:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        rows = conn.execute(text("""SELECT id, case_id, mandatee_account_id, mandatee_external, scope, territory,
            valid_from, valid_until, revoked_at FROM legal_mandates
            ORDER BY created_at DESC LIMIT :limit OFFSET :offset"""), {"limit": limit, "offset": offset}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/mandates", status_code=201)
def create_mandate(payload: MandateData, response: Response, identity=Depends(require_permission("legal:write"))):
    if payload.mandatee_account_id is None and not payload.mandatee_external:
        raise HTTPException(422, "Mandatee identity required")
    if payload.valid_until is not None and payload.valid_until < payload.valid_from:
        raise HTTPException(422, "Invalid mandate dates")
    mandate_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "legal")
            if payload.case_id is not None:
                case_exists(conn, payload.case_id, lock=True)
            conn.execute(text("""INSERT INTO legal_mandates(id,organization_id,case_id,mandatee_account_id,mandatee_external,scope,territory,valid_from,valid_until,created_by)
                VALUES(:id,:org,:case_id,:mandatee_account_id,:mandatee_external,:scope,:territory,:valid_from,:valid_until,:actor)"""),
                {"id": mandate_id, "org": identity["organization_id"], "actor": identity["account_id"], **payload.model_dump()})
            audit(conn, identity, "legal.mandate.created", mandate_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(mandate_id)}


@router.post("/mandates/{mandate_id}/revoke")
def revoke_mandate(mandate_id: UUID, response: Response, identity=Depends(require_permission("legal:decide"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        row = conn.execute(text("SELECT revoked_at FROM legal_mandates WHERE id=:id FOR UPDATE"), {"id": mandate_id}).mappings().one_or_none()
        if row is None:
            raise HTTPException(404, "Mandate not found")
        if row["revoked_at"] is not None:
            raise HTTPException(409, "Mandate already revoked")
        conn.execute(text("UPDATE legal_mandates SET revoked_at=now() WHERE id=:id"), {"id": mandate_id})
        audit(conn, identity, "legal.mandate.revoked", mandate_id)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(mandate_id), "revoked": True}


# ── Successions ──────────────────────────────────────────────────────────────
@router.get("/successions")
def list_successions(response: Response, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=1000000),
                    identity=Depends(require_permission("legal:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        rows = conn.execute(text("""SELECT id, deceased_account_id, heir_account_id, share_basis_points, declared_on, status, approved_at
            FROM legal_successions ORDER BY declared_on DESC LIMIT :limit OFFSET :offset"""), {"limit": limit, "offset": offset}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/successions", status_code=201)
def create_succession(payload: SuccessionData, response: Response, identity=Depends(require_permission("legal:write"))):
    succession_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "legal")
            conn.execute(text("""INSERT INTO legal_successions(id,organization_id,deceased_account_id,heir_account_id,share_basis_points,declared_on,created_by)
                VALUES(:id,:org,:deceased_account_id,:heir_account_id,:share_basis_points,:declared_on,:actor)"""),
                {"id": succession_id, "org": identity["organization_id"], "actor": identity["account_id"], **payload.model_dump()})
            audit(conn, identity, "legal.succession.created", succession_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(succession_id)}


@router.post("/successions/{succession_id}/approve")
def approve_succession(succession_id: UUID, payload: DecisionReview, response: Response,
                       identity=Depends(require_permission("legal:decide"))):
    actor = identity["account_id"]
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text),364))"), {"id": succession_id})
        row = conn.execute(text("SELECT status, created_by FROM legal_successions WHERE id=:id FOR UPDATE"), {"id": succession_id}).mappings().one_or_none()
        if row is None:
            raise HTTPException(404, "Succession not found")
        if row["status"] != "pending":
            raise HTTPException(409, "Succession already reviewed")
        new_status = "approved" if payload.decision == "approve" else "rejected"
        if str(row["created_by"]) == str(actor) and payload.decision == "approve":
            raise HTTPException(409, "Independent approval required")
        conn.execute(text("""UPDATE legal_successions SET status=:status, approved_by=:actor, approved_at=now() WHERE id=:id"""),
                     {"id": succession_id, "status": new_status, "actor": actor})
        audit(conn, identity, f"legal.succession.{new_status}", succession_id)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(succession_id), "status": new_status}


# ── Contracts ────────────────────────────────────────────────────────────────
@router.get("/contracts")
def list_contracts(response: Response, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=1000000),
                  identity=Depends(require_permission("legal:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "legal")
        rows = conn.execute(text("""SELECT id, kind, title, counterpart, territory, valid_from, valid_until, status
            FROM legal_contracts ORDER BY created_at DESC LIMIT :limit OFFSET :offset"""), {"limit": limit, "offset": offset}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/contracts", status_code=201)
def create_contract(payload: ContractData, response: Response, identity=Depends(require_permission("legal:write"))):
    if payload.valid_until is not None and payload.valid_until < payload.valid_from:
        raise HTTPException(422, "Invalid contract dates")
    contract_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "legal")
            conn.execute(text("""INSERT INTO legal_contracts(id,organization_id,kind,title,counterpart,territory,valid_from,valid_until,created_by)
                VALUES(:id,:org,:kind,:title,:counterpart,:territory,:valid_from,:valid_until,:actor)"""),
                {"id": contract_id, "org": identity["organization_id"], "actor": identity["account_id"], **payload.model_dump()})
            audit(conn, identity, "legal.contract.created", contract_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(contract_id)}
