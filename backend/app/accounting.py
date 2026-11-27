from typing import Literal
from uuid import UUID,uuid4
from fastapi import APIRouter,Depends,HTTPException,Query,Response
from pydantic import BaseModel,ConfigDict
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.billing import serialize
from app.exploitation import audit
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router=APIRouter(prefix="/api/v1/accounting",tags=["accounting"])
class Posting(BaseModel):
    model_config=ConfigDict(extra="forbid")
    source_type: Literal["invoice","receipt","distribution"]
    source_id: UUID

def line(account,debit=0,credit=0,artist_id=None):
    return dict(account_key=account,debit_minor=debit,credit_minor=credit,artist_id=artist_id)

def build_lines(kind,source,shares=()):
    if kind=="invoice":
        amount=source["amount_minor"]
        return [line("receivable",debit=amount),line("royalties_unallocated",credit=amount)]
    if kind=="receipt":
        amount=source["amount_minor"]
        return [line("cash_unverified",debit=amount),line("receivable",credit=amount)]
    if kind=="distribution":
        rows=[line("royalties_unallocated",debit=source["gross_minor"])]
        if source["commission_minor"]: rows.append(line("management_commission",credit=source["commission_minor"]))
        rows.extend(line("beneficiary_payable",credit=s["amount_minor"],artist_id=s["artist_id"]) for s in shares if s["amount_minor"])
        return rows
    raise ValueError("Unknown source type")

def require_posted(conn,kind,source_id):
    if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM accounting_entries WHERE source_type=:kind AND source_id=:id)"),{"kind":kind,"id":source_id}).scalar_one():
        raise HTTPException(409,"Preceding event must be posted first")

@router.post("/entries",status_code=201)
def post_entry(payload:Posting,response:Response,identity=Depends(require_permission("billing:write"))):
    org=identity["organization_id"]; entry_id=uuid4()
    try:
        with tenant_transaction(org) as conn:
            require_enabled_module(conn,"finance")
            kind=payload.source_type; params={"id":payload.source_id}; shares=[]
            if kind=="invoice":
                source=conn.execute(text("SELECT amount_minor,currency FROM royalty_invoices WHERE id=:id"),params).mappings().one_or_none()
            elif kind=="receipt":
                source=conn.execute(text("""SELECT r.amount_minor,r.invoice_id,i.currency FROM royalty_receipts r JOIN royalty_invoices i ON i.organization_id=r.organization_id AND i.id=r.invoice_id WHERE r.id=:id"""),params).mappings().one_or_none()
                if source: require_posted(conn,"invoice",source["invoice_id"])
            else:
                source=conn.execute(text("SELECT gross_minor,commission_minor,net_minor,currency,receipt_id FROM royalty_distributions WHERE id=:id"),params).mappings().one_or_none()
                if source:
                    require_posted(conn,"receipt",source["receipt_id"])
                    shares=conn.execute(text("SELECT artist_id,amount_minor FROM royalty_distribution_lines WHERE distribution_id=:id ORDER BY artist_id,role"),params).mappings().all()
            if source is None: raise HTTPException(404,"Source not found")
            rows=build_lines(kind,source,shares)
            if sum(x["debit_minor"] for x in rows)!=sum(x["credit_minor"] for x in rows): raise HTTPException(409,"Source not balanced")
            entry=conn.execute(text("""INSERT INTO accounting_entries(id,organization_id,source_type,source_id,currency,posted_by)
            VALUES(:id,:org,:kind,:source,:currency,:actor) RETURNING *"""),{"id":entry_id,"org":org,"kind":kind,"source":payload.source_id,"currency":source["currency"],"actor":identity["account_id"]}).mappings().one()
            conn.execute(text("""INSERT INTO accounting_lines(organization_id,entry_id,line_no,account_key,artist_id,debit_minor,credit_minor)
            VALUES(:org,:entry,:no,:account_key,:artist_id,:debit_minor,:credit_minor)"""),[{"org":org,"entry":entry_id,"no":i+1,**row} for i,row in enumerate(rows)])
            audit(conn,identity,"accounting.posted",entry_id)
    except IntegrityError as exc:
        if getattr(exc.orig,"sqlstate",None)=="23505": raise HTTPException(409,"Source already posted") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return {**dict(entry),"lines":[serialize(row) for row in rows]}

@router.get("/entries")
def entries(response:Response,limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("billing:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"finance")
        rows=conn.execute(text("SELECT * FROM accounting_entries ORDER BY posted_at DESC,id LIMIT :limit OFFSET :offset"),{"limit":limit,"offset":offset}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [dict(row) for row in rows]

@router.get("/entries/{entry_id}/lines")
def entry_lines(entry_id:UUID,response:Response,identity=Depends(require_permission("billing:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"finance")
        if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM accounting_entries WHERE id=:id)"),{"id":entry_id}).scalar_one(): raise HTTPException(404,"Entry not found")
        rows=conn.execute(text("SELECT line_no,account_key,artist_id,debit_minor,credit_minor FROM accounting_lines WHERE entry_id=:id ORDER BY line_no"),{"id":entry_id}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [serialize(row) for row in rows]

@router.get("/balances")
def balances(response:Response,identity=Depends(require_permission("billing:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"finance")
        rows=conn.execute(text("""SELECT e.currency,l.account_key,sum(l.debit_minor) AS debit_minor,sum(l.credit_minor) AS credit_minor,sum(l.debit_minor)-sum(l.credit_minor) AS balance_minor
        FROM accounting_lines l JOIN accounting_entries e ON e.organization_id=l.organization_id AND e.id=l.entry_id
        GROUP BY e.currency,l.account_key ORDER BY e.currency,l.account_key""")).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [serialize(row) for row in rows]
