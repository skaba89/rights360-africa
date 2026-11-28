"""PHASE 4 — Finance et comptabilité SYSCOHADA router.

Builds the configurable SYSCOHADA layer on top of the existing double-entry
accounting engine (accounting_entries/accounting_lines, migration 0021):

  * chart_of_accounts  — configurable plan comptable (SYSCOHADA classes 1-8)
  * account_mappings   — bridge the five hardcoded accounting.py generic keys
    (receivable, royalties_unallocated, cash_unverified, management_commission,
    beneficiary_payable) to SYSCOHADA account codes, so the existing engine can
    produce a SYSCOHADA trial balance without rewriting accounting_lines.
  * journals           — journaux (sales / receipts / general / payouts)
  * fiscal_periods     — exercices + périodes, with a 2-approval close workflow
  * accounting_reversals — contrepassations (a mirrored, balanced reversal entry
    that nets out the original in the trial balance)
  * tax_rules          — retenues à la source (withholding), per category/country

RBAC: finance:read / finance:write / finance:close / finance:reconcile.
All endpoints gate on the 'finance' module entitlement.

NOTE — the default OHADA chart seeded by POST /chart-of-accounts/seed is a
sensible default for an IP-rights collective-management organisation; per
ROADMAP_99.md it MUST be qualified by a SYSCOHADA professional before production.
"""
from typing import Literal
from uuid import UUID, uuid4
from datetime import date
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.billing import serialize
from app.exploitation import audit, conflict
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router = APIRouter(prefix="/api/v1/finance", tags=["finance"])

# Default OHADA/SYSCOHADA chart for an IP-rights collective-management org.
# (account_code, name, class, type)
DEFAULT_CHART = [
    ("101000", "Capital social", "1", "equity"),
    ("411000", "Clients (ayants droit redevables)", "4", "asset"),
    ("422000", "Ayants droit à payer", "4", "liability"),
    ("471000", "Compte d'attente (fonds non répartis)", "4", "liability"),
    ("521000", "Banque", "5", "asset"),
    ("641000", "Rémunérations du personnel", "6", "expense"),
    ("706000", "Prestations de services (commissions)", "7", "revenue"),
]
DEFAULT_MAPPINGS = {
    "receivable": "411000",
    "royalties_unallocated": "471000",
    "cash_unverified": "521000",
    "management_commission": "706000",
    "beneficiary_payable": "422000",
}


# ── Pydantic payloads ────────────────────────────────────────────────────────
class ChartAccountData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_code: str
    name: str
    syscohada_class: Literal["1", "2", "3", "4", "5", "6", "7", "8"]
    account_type: Literal["asset", "liability", "equity", "revenue", "expense"]
    parent_account_code: str | None = None
    is_postable: bool = True

    @field_validator("account_code")
    @classmethod
    def _code(cls, v: str) -> str:
        if not v.isdigit() or not (1 <= len(v) <= 8):
            raise ValueError("account_code must be 1-8 digits")
        return v


class AccountMappingData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    generic_key: Literal["receivable", "royalties_unallocated", "cash_unverified",
                         "management_commission", "beneficiary_payable"]
    account_code: str


class JournalData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str
    name: str
    kind: Literal["sales", "receipts", "general", "payouts"]

    @field_validator("code")
    @classmethod
    def _code(cls, v: str) -> str:
        if not v or not v.replace("", "").isupper() or not all(c.isalnum() for c in v) or not (1 <= len(v) <= 10):
            raise ValueError("code must be 1-10 upper alphanumeric chars")
        return v


class FiscalPeriodData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fiscal_year: int
    period_index: int
    starts_on: date
    ends_on: date

    @field_validator("period_index")
    @classmethod
    def _idx(cls, v: int) -> int:
        if not (0 <= v <= 12):
            raise ValueError("period_index must be 0-12 (0 = annual)")
        return v

    @field_validator("ends_on")
    @classmethod
    def _dates(cls, v: date, info) -> date:
        starts = info.data.get("starts_on")
        if starts and v < starts:
            raise ValueError("ends_on must be >= starts_on")
        return v


class FiscalReviewData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "reject"]
    rationale: str | None = None


class ReversalData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str


class TaxRuleData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str
    country: str
    rate_bps: int
    account_code: str | None = None

    @field_validator("country")
    @classmethod
    def _country(cls, v: str) -> str:
        if len(v) != 2 or not v.isupper():
            raise ValueError("country must be a 2-letter ISO code")
        return v

    @field_validator("rate_bps")
    @classmethod
    def _rate(cls, v: int) -> int:
        if not (0 <= v <= 10000):
            raise ValueError("rate_bps must be 0-10000 (0-100%)")
        return v


# ── Chart of accounts ────────────────────────────────────────────────────────
@router.get("/chart-of-accounts")
def list_chart(response: Response, identity=Depends(require_permission("finance:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT account_code, name, syscohada_class, account_type,
            parent_account_code, is_postable FROM chart_of_accounts
            ORDER BY syscohada_class, account_code""")).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/chart-of-accounts", status_code=201)
def create_chart(payload: ChartAccountData, response: Response, identity=Depends(require_permission("finance:write"))):
    acct_id = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            row = conn.execute(text("""INSERT INTO chart_of_accounts(id,organization_id,account_code,name,
                syscohada_class,account_type,parent_account_code,is_postable,created_by)
                VALUES(:id,:org,:code,:name,:class,:type,:parent,:postable,:actor)
                RETURNING account_code,name,syscohada_class,account_type,parent_account_code,is_postable"""),
                {"id": acct_id, "org": identity["organization_id"], "code": payload.account_code,
                 "name": payload.name, "class": payload.syscohada_class, "type": payload.account_type,
                 "parent": payload.parent_account_code, "postable": payload.is_postable,
                 "actor": identity["account_id"]}).mappings().one()
            audit(conn, identity, "finance.chart.created", acct_id)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


@router.post("/chart-of-accounts/seed", status_code=201)
def seed_chart(response: Response, identity=Depends(require_permission("finance:write"))):
    """Seed the default OHADA/SYSCOHADA chart + the five generic-key mappings.

    Idempotent: existing accounts/mappings are kept (ON CONFLICT DO NOTHING).
    Returns the counts actually inserted.
    """
    org = identity["organization_id"]; actor = identity["account_id"]
    inserted_accounts = 0; inserted_mappings = 0
    try:
        with tenant_transaction(org) as conn:
            require_enabled_module(conn, "finance")
            for code, name, cls, atype in DEFAULT_CHART:
                res = conn.execute(text("""INSERT INTO chart_of_accounts(id,organization_id,account_code,name,
                    syscohada_class,account_type,is_postable,created_by)
                    VALUES(:id,:org,:code,:name,:class,:type,TRUE,:actor)
                    ON CONFLICT (organization_id, account_code) DO NOTHING"""),
                    {"id": uuid4(), "org": org, "code": code, "name": name,
                     "class": cls, "type": atype, "actor": actor})
                inserted_accounts += res.rowcount
            for generic_key, account_code in DEFAULT_MAPPINGS.items():
                res = conn.execute(text("""INSERT INTO account_mappings(id,organization_id,generic_key,account_code)
                    VALUES(:id,:org,:key,:code)
                    ON CONFLICT (organization_id, generic_key) DO NOTHING"""),
                    {"id": uuid4(), "org": org, "key": generic_key, "code": account_code})
                inserted_mappings += res.rowcount
            audit(conn, identity, "finance.chart.seeded", uuid4())
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return {"seeded_accounts": inserted_accounts, "seeded_mappings": inserted_mappings}


# ── Account mappings ─────────────────────────────────────────────────────────
@router.get("/account-mappings")
def list_mappings(response: Response, identity=Depends(require_permission("finance:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT m.generic_key, m.account_code, c.name AS account_name, c.syscohada_class
            FROM account_mappings m JOIN chart_of_accounts c
            ON c.organization_id=m.organization_id AND c.account_code=m.account_code
            ORDER BY m.generic_key""")).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/account-mappings", status_code=201)
def create_mapping(payload: AccountMappingData, response: Response, identity=Depends(require_permission("finance:write"))):
    mid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            row = conn.execute(text("""INSERT INTO account_mappings(id,organization_id,generic_key,account_code)
                VALUES(:id,:org,:key,:code) RETURNING generic_key,account_code"""),
                {"id": mid, "org": identity["organization_id"], "key": payload.generic_key,
                 "code": payload.account_code}).mappings().one()
            audit(conn, identity, "finance.mapping.created", mid)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


# ── Journaux ─────────────────────────────────────────────────────────────────
@router.get("/journals")
def list_journals(response: Response, identity=Depends(require_permission("finance:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT code, name, kind FROM journals ORDER BY code""")).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/journals", status_code=201)
def create_journal(payload: JournalData, response: Response, identity=Depends(require_permission("finance:write"))):
    jid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            row = conn.execute(text("""INSERT INTO journals(id,organization_id,code,name,kind,created_by)
                VALUES(:id,:org,:code,:name,:kind,:actor) RETURNING code,name,kind"""),
                {"id": jid, "org": identity["organization_id"], "code": payload.code,
                 "name": payload.name, "kind": payload.kind, "actor": identity["account_id"]}).mappings().one()
            audit(conn, identity, "finance.journal.created", jid)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


# ── Exercices / périodes + multi-level close ─────────────────────────────────
@router.get("/fiscal-periods")
def list_periods(response: Response, identity=Depends(require_permission("finance:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT id, fiscal_year, period_index, starts_on, ends_on, status, closed_at
            FROM fiscal_periods ORDER BY fiscal_year DESC, period_index""")).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/fiscal-periods", status_code=201)
def create_period(payload: FiscalPeriodData, response: Response, identity=Depends(require_permission("finance:write"))):
    pid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            row = conn.execute(text("""INSERT INTO fiscal_periods(id,organization_id,fiscal_year,period_index,
                starts_on,ends_on,created_by)
                VALUES(:id,:org,:year,:idx,:start,:end,:actor)
                RETURNING id,fiscal_year,period_index,starts_on,ends_on,status"""),
                {"id": pid, "org": identity["organization_id"], "year": payload.fiscal_year,
                 "idx": payload.period_index, "start": payload.starts_on, "end": payload.ends_on,
                 "actor": identity["account_id"]}).mappings().one()
            audit(conn, identity, "finance.period.created", pid)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


@router.post("/fiscal-periods/{period_id}/reviews", status_code=201)
def review_period(period_id: UUID, payload: FiscalReviewData, response: Response,
                  identity=Depends(require_permission("finance:close"))):
    rid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            row = conn.execute(text("""INSERT INTO fiscal_period_reviews(id,organization_id,period_id,reviewer_id,
                decision,rationale) VALUES(:id,:org,:pid,:reviewer,:decision,:rationale)
                RETURNING id,decision,reviewed_at"""),
                {"id": rid, "org": identity["organization_id"], "pid": period_id,
                 "reviewer": identity["account_id"], "decision": payload.decision,
                 "rationale": payload.rationale}).mappings().one()
            audit(conn, identity, f"finance.period.{payload.decision}", period_id)
    except IntegrityError as exc:
        # check_violation (23514) from the review/close guards, 23505 duplicate,
        # 23503 missing period -> map to a clear 409/404.
        sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
        if sqlstate == "23514":
            raise HTTPException(409, "Review rejected by period state (closed, already 2 approvals, or prior reject)")
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


@router.post("/fiscal-periods/{period_id}/close")
def close_period(period_id: UUID, response: Response, identity=Depends(require_permission("finance:close"))):
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            existing = conn.execute(text("SELECT status FROM fiscal_periods WHERE id=:id"),
                                    {"id": period_id}).mappings().one_or_none()
            if existing is None:
                raise HTTPException(404, "Fiscal period not found")
            if existing["status"] != "open":
                raise HTTPException(409, f"Period is {existing['status']}, not open")
            conn.execute(text("""UPDATE fiscal_periods SET status='closed', closed_at=now() WHERE id=:id"""),
                         {"id": period_id})
            audit(conn, identity, "finance.period.closed", period_id)
    except IntegrityError as exc:
        # The deferred check_fiscal_period_close trigger raises check_violation
        # if <2 approvals or a rejection exists.
        if getattr(getattr(exc, "orig", None), "sqlstate", None) == "23514":
            raise HTTPException(409, "Period requires at least 2 independent approvals and no rejections before closing")
        raise
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(period_id), "status": "closed"}


# ── Balance générale / grand livre ───────────────────────────────────────────
@router.get("/trial-balance")
def trial_balance(response: Response, identity=Depends(require_permission("finance:read"))):
    """Balance générale: per SYSCOHADA account_code (via the generic->SYSCOHADA
    mapping), summed debit/credit/balance across all currencies + entries.
    Reversal entries net out automatically (their lines are mirrored)."""
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT c.account_code, c.name, c.syscohada_class, c.account_type,
            e.currency,
            COALESCE(sum(l.debit_minor),0) AS debit_minor,
            COALESCE(sum(l.credit_minor),0) AS credit_minor,
            COALESCE(sum(l.debit_minor),0)-COALESCE(sum(l.credit_minor),0) AS balance_minor
            FROM accounting_lines l
            JOIN accounting_entries e ON e.organization_id=l.organization_id AND e.id=l.entry_id
            JOIN account_mappings m ON m.organization_id=l.organization_id AND m.generic_key=l.account_key
            JOIN chart_of_accounts c ON c.organization_id=m.organization_id AND c.account_code=m.account_code
            GROUP BY c.account_code, c.name, c.syscohada_class, c.account_type, e.currency
            ORDER BY c.syscohada_class, c.account_code, e.currency""")).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [serialize(r) for r in rows]


@router.get("/general-ledger")
def general_ledger(response: Response, limit: int = Query(100, ge=1, le=500),
                  offset: int = Query(0, ge=0, le=1000000),
                  identity=Depends(require_permission("finance:read"))):
    """Grand livre: posted entries + their lines, SYSCOHADA-mapped, chronological."""
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT e.id AS entry_id, e.source_type, e.currency, e.posted_at,
            l.line_no, l.account_key, m.account_code, c.name AS account_name,
            l.artist_id, l.debit_minor, l.credit_minor
            FROM accounting_entries e
            JOIN accounting_lines l ON l.organization_id=e.organization_id AND l.entry_id=e.id
            LEFT JOIN account_mappings m ON m.organization_id=l.organization_id AND m.generic_key=l.account_key
            LEFT JOIN chart_of_accounts c ON c.organization_id=m.organization_id AND c.account_code=m.account_code
            ORDER BY e.posted_at DESC, e.id, l.line_no
            LIMIT :limit OFFSET :offset"""), {"limit": limit, "offset": offset}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [serialize(r) for r in rows]


# ── Contrepassation (reversal) ───────────────────────────────────────────────
@router.post("/accounting/entries/{entry_id}/reverse", status_code=201)
def reverse_entry(entry_id: UUID, payload: ReversalData, response: Response,
                  identity=Depends(require_permission("finance:write"))):
    """Post a contrepassation: a mirrored, balanced reversal entry that nets
    out the original in the trial balance. One reversal per entry (enforced by
    entry_source_unique on source_type='reversal')."""
    org = identity["organization_id"]; actor = identity["account_id"]
    rev_id = uuid4()
    try:
        with tenant_transaction(org) as conn:
            require_enabled_module(conn, "finance")
            orig = conn.execute(text("""SELECT id, currency, journal_id, fiscal_period_id FROM accounting_entries
                WHERE id=:id"""), {"id": entry_id}).mappings().one_or_none()
            if orig is None:
                raise HTTPException(404, "Entry not found")
            lines = conn.execute(text("""SELECT account_key, artist_id, debit_minor, credit_minor
                FROM accounting_lines WHERE entry_id=:id ORDER BY line_no"""), {"id": entry_id}).mappings().all()
            if not lines:
                raise HTTPException(409, "Entry has no lines to reverse")
            # Create the mirrored reversal entry (source_type='reversal').
            conn.execute(text("""INSERT INTO accounting_entries(id,organization_id,source_type,source_id,
                currency,journal_id,fiscal_period_id,posted_by)
                VALUES(:id,:org,'reversal',:source,:currency,:journal,:period,:actor)"""),
                {"id": rev_id, "org": org, "source": entry_id, "currency": orig["currency"],
                 "journal": orig["journal_id"], "period": orig["fiscal_period_id"], "actor": actor})
            # Mirror each line with debit/credit swapped (so the reversal nets out).
            conn.execute(text("""INSERT INTO accounting_lines(organization_id,entry_id,line_no,account_key,artist_id,debit_minor,credit_minor)
                VALUES(:org,:entry,:no,:account_key,:artist_id,:debit,:credit)"""),
                [{"org": org, "entry": rev_id, "no": i + 1,
                  "account_key": ln["account_key"], "artist_id": ln["artist_id"],
                  "debit": ln["credit_minor"], "credit": ln["debit_minor"]}  # swapped
                 for i, ln in enumerate(lines)])
            conn.execute(text("""INSERT INTO accounting_reversals(id,organization_id,original_entry_id,reversal_entry_id,reason,reversed_by)
                VALUES(:id,:org,:orig,:rev,:reason,:actor)"""),
                {"id": uuid4(), "org": org, "orig": entry_id, "rev": rev_id,
                 "reason": payload.reason, "actor": actor})
            audit(conn, identity, "finance.entry.reversed", rev_id)
    except IntegrityError as exc:
        sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
        if sqlstate == "23505":
            raise HTTPException(409, "Entry already reversed") from None
        if sqlstate == "23514":
            raise HTTPException(409, "Reversal would produce an unbalanced entry") from None
        raise
    response.headers["Cache-Control"] = "no-store"
    return {"id": str(rev_id), "reversal_of": str(entry_id), "reason": payload.reason}


# ── Retenues à la source (withholding tax rules) ─────────────────────────────
@router.get("/tax-rules")
def list_tax_rules(response: Response, identity=Depends(require_permission("finance:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        rows = conn.execute(text("""SELECT category, country, rate_bps, account_code
            FROM tax_rules ORDER BY country, category""")).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return [dict(r) for r in rows]


@router.post("/tax-rules", status_code=201)
def create_tax_rule(payload: TaxRuleData, response: Response, identity=Depends(require_permission("finance:write"))):
    tid = uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn, "finance")
            row = conn.execute(text("""INSERT INTO tax_rules(id,organization_id,category,country,rate_bps,account_code)
                VALUES(:id,:org,:cat,:country,:rate,:code) RETURNING category,country,rate_bps,account_code"""),
                {"id": tid, "org": identity["organization_id"], "cat": payload.category,
                 "country": payload.country, "rate": payload.rate_bps,
                 "code": payload.account_code}).mappings().one()
            audit(conn, identity, "finance.taxrule.created", tid)
    except IntegrityError as exc:
        conflict(exc)
    response.headers["Cache-Control"] = "no-store"
    return dict(row)


# ── Relevé ayant droit (beneficiary statement) ───────────────────────────────
@router.get("/beneficiaries/{artist_id}/statement")
def beneficiary_statement(artist_id: UUID, response: Response,
                          identity=Depends(require_permission("finance:read"))):
    """Relevé having-droit: per-account balances (debit owed / credit paid) +
    payout totals for one artist, across currencies."""
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn, "finance")
        balances = conn.execute(text("""SELECT e.currency, l.account_key,
            COALESCE(sum(l.debit_minor),0) AS debit_minor,
            COALESCE(sum(l.credit_minor),0) AS credit_minor,
            COALESCE(sum(l.debit_minor),0)-COALESCE(sum(l.credit_minor),0) AS balance_minor
            FROM accounting_lines l JOIN accounting_entries e
            ON e.organization_id=l.organization_id AND e.id=l.entry_id
            WHERE l.artist_id=:artist
            GROUP BY e.currency, l.account_key ORDER BY e.currency, l.account_key"""),
            {"artist": artist_id}).mappings().all()
        payouts = conn.execute(text("""SELECT currency, COALESCE(sum(amount_minor),0) AS amount_minor
            FROM payout_orders WHERE artist_id=:artist GROUP BY currency ORDER BY currency"""),
            {"artist": artist_id}).mappings().all()
    response.headers["Cache-Control"] = "no-store"
    return {"artist_id": str(artist_id), "balances": [serialize(r) for r in balances],
            "payouts": [serialize(r) for r in payouts]}
