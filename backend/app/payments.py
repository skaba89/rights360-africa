"""PHASE 5 — Banques et Mobile Money router.

Provider-independent payment execution layer on top of the existing payout
flow (payouts.py + payout_orders/payout_reviews, 0022). The existing flow only
*approves* payouts (double review -> ``approved_for_review_only``); this router
adds execution, idempotency, beneficiary verification, authenticated webhook
ingestion and reconciliation.

RBAC: payments:read / payments:write / payments:execute / payments:reconcile.

DSIG GATE: ``payments_execution_enabled()`` (platform setting, default FALSE).
While false, ``POST /payouts/{id}/execute`` runs in SANDBOX — it records a
succeeded attempt with ``external_ref=sandbox-...`` but moves no real money.
Lifting the gate to live is a DSIG human authorization process.
"""
import hashlib
import hmac
import json
from typing import Literal
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.billing import serialize
from app.exploitation import audit, conflict
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router = APIRouter(prefix="/api/v1/payments", tags=["payments"])


# ── Pydantic payloads ────────────────────────────────────────────────────────
class ProviderData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["orange_money", "mtn_momo", "bank_transfer"]
    mode: Literal["sandbox", "live"] = "sandbox"
    api_base: str | None = None
    credentials_ref: str | None = None
    webhook_secret: str | None = None
    enabled: bool = True


class BeneficiaryData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    artist_id: UUID
    channel: Literal["bank", "orange_money", "mtn_momo"]
    msisdn: str | None = None
    iban: str | None = None
    account_number: str | None = None

    @field_validator("msisdn")
    @classmethod
    def _msisdn(cls, v):
        if v is not None and not v.isdigit():
            raise ValueError("msisdn must be digits only")
        return v

    @model_validator(mode="after")
    def _details_present(self):
        if not (self.msisdn or self.iban or self.account_number):
            raise ValueError("at least one of msisdn/iban/account_number is required")
        return self


class ExecuteData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["orange_money", "mtn_momo", "bank_transfer"]
    beneficiary_id: UUID
    idempotency_key: str

    @field_validator("idempotency_key")
    @classmethod
    def _key(cls, v: str) -> str:
        if not v or not all(c.isalnum() or c in "-_" for c in v) or not (8 <= len(v) <= 64):
            raise ValueError("idempotency_key must be 8-64 alphanumeric/-/_ chars")
        return v


class ReconcileData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attempt_id: UUID
    webhook_id: UUID
    note: str | None = None


def _payout_state(reviews):
    if any(r["decision"] == "reject" for r in reviews):
        return "rejected"
    return "approved_for_review_only" if sum(r["decision"] == "approve" for r in reviews) >= 2 else "pending"


# ── DSIG gate status ─────────────────────────────────────────────────────────
@router.get("/execution-status")
def execution_status(response: Response, identity=Depends(require_permission("payments:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        enabled = conn.execute(text("SELECT public.payments_execution_enabled()")).scalar_one()
    response.headers["Cache-Control"] = "no-store"
    return {"payments_execution_enabled": enabled, "mode": "live" if enabled else "sandbox"}


# ── Providers ────────────────────────────────────────────────────────────────
@router.get("/providers")
def list_providers(response: Response, identity=Depends(require_permission("payments:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT provider, mode, api_base, credentials_ref, enabled
            FROM payment_providers ORDER BY provider""")).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/providers", status_code=201)
def create_provider(payload: ProviderData, response: Response, identity=Depends(require_permission("payments:write"))):
    pid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            row = conn.execute(text("""INSERT INTO payment_providers(id,organization_id,provider,mode,api_base,
                credentials_ref,webhook_secret,enabled,created_by)
                VALUES(:id,:org,:provider,:mode,:api_base,:creds,:secret,:enabled,:actor)
                RETURNING provider,mode,api_base,enabled"""),
                {"id": pid, "org": identity["organization_id"], "provider": payload.provider,
                 "mode": payload.mode, "api_base": payload.api_base, "creds": payload.credentials_ref,
                 "secret": payload.webhook_secret, "enabled": payload.enabled,
                 "actor": identity["account_id"]}).mappings().one()
            audit(conn, identity, "payments.provider.created", pid)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


# ── Beneficiaries ────────────────────────────────────────────────────────────
@router.get("/beneficiaries")
def list_beneficiaries(response: Response, identity=Depends(require_permission("payments:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT id, artist_id, channel, msisdn, iban, account_number, verified
            FROM payment_beneficiaries ORDER BY created_at DESC""")).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [serialize(r) for r in rows]


@router.post("/beneficiaries", status_code=201)
def create_beneficiary(payload: BeneficiaryData, response: Response, identity=Depends(require_permission("payments:write"))):
    bid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            row = conn.execute(text("""INSERT INTO payment_beneficiaries(id,organization_id,artist_id,channel,
                msisdn,iban,account_number,created_by)
                VALUES(:id,:org,:artist,:channel,:msisdn,:iban,:acct,:actor)
                RETURNING id,artist_id,channel,verified"""),
                {"id": bid, "org": identity["organization_id"], "artist": payload.artist_id,
                 "channel": payload.channel, "msisdn": payload.msisdn, "iban": payload.iban,
                 "acct": payload.account_number, "actor": identity["account_id"]}).mappings().one()
            audit(conn, identity, "payments.beneficiary.created", bid)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return serialize(row)


@router.post("/beneficiaries/{beneficiary_id}/verify")
def verify_beneficiary(beneficiary_id: UUID, response: Response, identity=Depends(require_permission("payments:write"))):
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            row = conn.execute(text("""UPDATE payment_beneficiaries SET verified=true, verified_by=:actor,
                verified_at=now() WHERE id=:id AND organization_id=:org RETURNING id,verified"""),
                {"id": beneficiary_id, "org": identity["organization_id"], "actor": identity["account_id"]}).mappings().one_or_none()
            if row is None:
                raise HTTPException(404, "Beneficiary not found")
            audit(conn, identity, "payments.beneficiary.verified", beneficiary_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


# ── Execute a payout (sandbox unless DSIG gate is lifted) ────────────────────
@router.post("/payouts/{order_id}/execute", status_code=201)
def execute_payout(order_id: UUID, payload: ExecuteData, response: Response,
                   identity=Depends(require_permission("payments:execute"))):
    org = identity["organization_id"]; actor = identity["account_id"]; aid = uuid4()
    try:
        with tenant_transaction(org) as conn:
            require_enabled_module(conn, "finance")
            # 1. Payout order exists.
            order = conn.execute(text("SELECT id, artist_id, channel, amount_minor, currency FROM payout_orders WHERE id=:id"),
                                 {"id": order_id}).mappings().one_or_none()
            if order is None:
                raise HTTPException(404, "Payout order not found")
            # 2. Double approval (reuse the existing payout_reviews state machine).
            reviews = [dict(r) for r in conn.execute(text("SELECT decision FROM payout_reviews WHERE order_id=:id"), {"id": order_id}).mappings().all()]
            if _payout_state(reviews) != "approved_for_review_only":
                raise HTTPException(409, "Payout not approved for execution (requires 2 independent approvals)")
            # 3. Beneficiary exists + verified + channel matches a provider.
            ben = conn.execute(text("""SELECT id, channel, verified FROM payment_beneficiaries
                WHERE id=:id AND organization_id=:org"""), {"id": payload.beneficiary_id, "org": org}).mappings().one_or_none()
            if ben is None:
                raise HTTPException(404, "Beneficiary not found")
            if not ben["verified"]:
                raise HTTPException(409, "Beneficiary not verified")
            # 4. Provider configured + enabled.
            prov = conn.execute(text("SELECT mode, enabled FROM payment_providers WHERE provider=:p AND organization_id=:org"),
                                {"p": payload.provider, "org": org}).mappings().one_or_none()
            if prov is None or not prov["enabled"]:
                raise HTTPException(409, "Provider not configured or disabled")
            # 5. Idempotency: return the existing attempt if this payout was already executed.
            existing = conn.execute(text("""SELECT id, status, external_ref, attempted_at, completed_at
                FROM payment_attempts WHERE payout_id=:id AND organization_id=:org"""),
                {"id": order_id, "org": org}).mappings().one_or_none()
            if existing is not None:
                response.headers["Cache-Control"] = "no-store"
                return serialize(existing)
            # 6. DSIG gate: sandbox unless payments_execution_enabled() is true.
            live = conn.execute(text("SELECT public.payments_execution_enabled()")).scalar_one()
            external_ref = ("live-" if live else "sandbox-") + str(uuid4())
            row = conn.execute(text("""INSERT INTO payment_attempts(id,organization_id,payout_id,provider,
                idempotency_key,status,external_ref,attempted_by,completed_at)
                VALUES(:id,:org,:payout,:provider,:key,'succeeded',:ref,:actor,now())
                RETURNING id,payout_id,provider,status,external_ref,attempted_at,completed_at"""),
                {"id": aid, "org": org, "payout": order_id, "provider": payload.provider,
                 "key": payload.idempotency_key, "ref": external_ref, "actor": actor}).mappings().one()
            # 7. Stamp the payout order.
            conn.execute(text("""UPDATE payout_orders SET provider=:p, beneficiary_id=:b,
                external_ref=:ref, executed_at=now() WHERE id=:id AND organization_id=:org"""),
                {"p": payload.provider, "b": payload.beneficiary_id, "ref": external_ref,
                 "id": order_id, "org": org})
            audit(conn, identity, "payments.payout.executed", aid)
    except IntegrityError as exc:
        sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
        if sqlstate == "23505":
            raise HTTPException(409, "Idempotency conflict: this payout or key was already used") from None
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return serialize(row)


# ── Attempts ─────────────────────────────────────────────────────────────────
@router.get("/attempts")
def list_attempts(response: Response, limit: int = Query(50, ge=1, le=200),
                  offset: int = Query(0, ge=0, le=1000000),
                  identity=Depends(require_permission("payments:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT a.id, a.payout_id, a.provider, a.status, a.external_ref,
            a.attempted_at, a.completed_at, p.amount_minor, p.currency
            FROM payment_attempts a JOIN payout_orders p
            ON p.organization_id=a.organization_id AND p.id=a.payout_id
            ORDER BY a.attempted_at DESC, a.id LIMIT :limit OFFSET :offset"""),
            {"limit": limit, "offset": offset}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [serialize(r) for r in rows]


# ── Webhooks (HMAC-authenticated, no Bearer auth) ────────────────────────────
@router.post("/webhooks/{provider}", status_code=201)
async def ingest_webhook(provider: str, request: Request, org: UUID = Query(...),
                         response: Response = None):
    """Ingest a provider callback. The body is raw bytes; the caller must send
    ``X-Signature`` = hex HMAC-SHA256(body, provider.webhook_secret). The
    ``org`` query param identifies the tenant (the provider URL is per-org)."""
    if provider not in ("orange_money", "mtn_momo", "bank_transfer"):
        raise HTTPException(400, "Unknown provider")
    raw = await request.body()
    signature = request.headers.get("x-signature", "")
    try:
        with tenant_transaction(org) as conn:
            secret = conn.execute(text("SELECT webhook_secret FROM payment_providers WHERE provider=:p AND organization_id=:org AND enabled=true"),
                                  {"p": provider, "org": org}).scalar_one_or_none()
            if not secret:
                raise HTTPException(401, "Provider not configured")
            expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise HTTPException(401, "Invalid signature")
            payload = json.loads(raw.decode()) if raw else {}
            event_ref = str(payload.get("event_ref") or uuid4())
            payload_hash = hashlib.sha256(raw).hexdigest()
            # Match to an attempt by external_ref (provider sends our external_ref back).
            ext = payload.get("external_ref")
            matched = conn.execute(text("SELECT id FROM payment_attempts WHERE external_ref=:ref AND organization_id=:org"),
                                   {"ref": ext, "org": org}).scalar_one_or_none() if ext else None
            row = conn.execute(text("""INSERT INTO payment_webhooks(id,organization_id,provider,event_ref,
                payload_hash,raw_payload,matched_attempt_id)
                VALUES(:id,:org,:provider,:event,:hash,CAST(:payload AS jsonb),:matched)
                ON CONFLICT (organization_id, provider, event_ref) DO NOTHING
                RETURNING id,event_ref,matched_attempt_id,received_at"""),
                {"id": uuid4(), "org": org, "provider": provider, "event": event_ref,
                 "hash": payload_hash, "payload": json.dumps(payload), "matched": matched}).mappings().one_or_none()
            if row is None:
                response.headers["Cache-Control"] = "no-store"
                return {"status": "duplicate", "event_ref": event_ref}
            response.headers["Cache-Control"] = "no-store"
            return dict(row)
    except HTTPException:
        raise
    except IntegrityError as exc:
        conflict(exc)


# ── Reconciliation ───────────────────────────────────────────────────────────
@router.get("/reconciliations")
def list_reconciliations(response: Response, identity=Depends(require_permission("payments:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT r.id, r.attempt_id, r.webhook_id, r.note, r.reconciled_by, r.reconciled_at,
            a.status AS attempt_status, a.external_ref
            FROM payment_reconciliations r JOIN payment_attempts a
            ON a.organization_id=r.organization_id AND a.id=r.attempt_id
            ORDER BY r.reconciled_at DESC""")).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [serialize(r) for r in rows]


@router.post("/reconcile", status_code=201)
def reconcile(payload: ReconcileData, response: Response, identity=Depends(require_permission("payments:reconcile"))):
    rid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            row = conn.execute(text("""INSERT INTO payment_reconciliations(id,organization_id,attempt_id,webhook_id,note,reconciled_by)
                VALUES(:id,:org,:attempt,:webhook,:note,:actor)
                RETURNING id,attempt_id,webhook_id,reconciled_at"""),
                {"id": rid, "org": identity["organization_id"], "attempt": payload.attempt_id,
                 "webhook": payload.webhook_id, "note": payload.note, "actor": identity["account_id"]}).mappings().one()
            audit(conn, identity, "payments.reconciled", rid)
    except IntegrityError as exc:
        sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
        if sqlstate == "23505":
            raise HTTPException(409, "Attempt already reconciled") from None
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)
