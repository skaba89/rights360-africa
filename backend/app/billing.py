from datetime import date
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import Field, StrictInt
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.exploitation import Record,audit,conflict
from app.tariffs import QuoteData,calculate
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router=APIRouter(prefix="/api/v1/invoices",tags=["royalty billing"])

class InvoiceData(QuoteData,Record):
    tariff_id: UUID
    due_on: date

class ReceiptData(Record):
    amount_minor: StrictInt=Field(gt=0,le=1000000000000000000)
    received_on: date

def serialize(row):
    return {k:str(v) if k.endswith("_minor") and v is not None else v for k,v in row.items()}

@router.get("")
def invoices(response: Response,limit: int=Query(50,ge=1,le=100),offset: int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("billing:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"finance")
        rows=conn.execute(text("""SELECT i.*,p.paid_minor,i.amount_minor-p.paid_minor AS balance_minor,
        CASE WHEN p.paid_minor=i.amount_minor THEN 'paid' WHEN i.due_on<CURRENT_DATE THEN 'overdue'
        WHEN p.paid_minor>0 THEN 'partial' ELSE 'unpaid' END AS status
        FROM royalty_invoices i CROSS JOIN LATERAL
        (SELECT COALESCE(sum(r.amount_minor),0)::bigint AS paid_minor FROM royalty_receipts r WHERE r.invoice_id=i.id AND r.organization_id=i.organization_id) p
        ORDER BY i.created_at DESC,i.id LIMIT :limit OFFSET :offset"""),{"limit":limit,"offset":offset}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [serialize(row) for row in rows]

@router.post("",status_code=201)
def issue(payload: InvoiceData,response: Response,identity=Depends(require_permission("billing:write"))):
    if payload.due_on<payload.usage_date or payload.usage_date>date.today():
        raise HTTPException(422,"Invalid invoice dates")
    org=identity["organization_id"]
    record_id=uuid4()
    try:
        with tenant_transaction(org) as conn:
            require_enabled_module(conn,"finance")
            require_enabled_module(conn,"licenses")
            tariff=conn.execute(text("SELECT * FROM tariffs WHERE id=:id"),{"id":payload.tariff_id}).mappings().one_or_none()
            lic=conn.execute(text("""SELECT l.*,o.category FROM exploitation_licenses l JOIN operators o
            ON o.organization_id=l.organization_id AND o.id=l.operator_id WHERE l.id=:id FOR SHARE OF l"""),{"id":payload.license_id}).mappings().one_or_none()
            if tariff is None or lic is None: raise HTTPException(404,"Tariff or license not found")
            if lic["status"]!="active" or not lic["starts_on"]<=payload.usage_date<=lic["ends_on"] or not tariff["starts_on"]<=payload.usage_date<=tariff["ends_on"] or tariff["category"]!=lic["category"] or tariff["usage_type"]!=lic["usage_type"]:
                raise HTTPException(409,"Tariff not applicable")
            amount=calculate(tariff["method"],tariff["rate"],payload)
            if amount<=0: raise HTTPException(422,"Invoice amount must be positive")
            row=conn.execute(text("""INSERT INTO royalty_invoices(id,organization_id,reference,license_id,tariff_id,usage_date,due_on,quantity,revenue_minor,amount_minor,currency)
            VALUES(:id,:org,:reference,:license_id,:tariff_id,:usage_date,:due_on,:quantity,:revenue_minor,:amount,:currency) RETURNING *"""),
            {"id":record_id,"org":org,"amount":amount,"currency":tariff["currency"],**payload.model_dump()}).mappings().one()
            audit(conn,identity,"invoice.issued",record_id)
    except IntegrityError as exc: conflict(exc)
    response.headers["Cache-Control"]="no-store"
    return serialize(row)

@router.get("/{invoice_id}/receipts")
def receipts(invoice_id: UUID,response: Response,identity=Depends(require_permission("billing:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"finance")
        if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM royalty_invoices WHERE id=:id)"),{"id":invoice_id}).scalar_one(): raise HTTPException(404,"Invoice not found")
        rows=conn.execute(text("SELECT * FROM royalty_receipts WHERE invoice_id=:id ORDER BY created_at,id"),{"id":invoice_id}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [serialize(row) for row in rows]

@router.post("/{invoice_id}/receipts",status_code=201)
def receive(invoice_id: UUID,payload: ReceiptData,response: Response,identity=Depends(require_permission("billing:write"))):
    if payload.received_on>date.today(): raise HTTPException(422,"Future receipt date")
    record_id=uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn,"finance")
            conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text),362))"),{"id":invoice_id})
            invoice=conn.execute(text("SELECT amount_minor,usage_date FROM royalty_invoices WHERE id=:id"),{"id":invoice_id}).mappings().one_or_none()
            if invoice is None: raise HTTPException(404,"Invoice not found")
            if payload.received_on<invoice["usage_date"]: raise HTTPException(422,"Receipt before usage")
            paid=conn.execute(text("SELECT COALESCE(sum(amount_minor),0) FROM royalty_receipts WHERE invoice_id=:id"),{"id":invoice_id}).scalar_one()
            if paid+payload.amount_minor>invoice["amount_minor"]: raise HTTPException(409,"Receipt exceeds balance")
            row=conn.execute(text("""INSERT INTO royalty_receipts(id,organization_id,invoice_id,reference,amount_minor,received_on)
            VALUES(:id,:org,:invoice,:reference,:amount_minor,:received_on) RETURNING *"""),
            {"id":record_id,"org":identity["organization_id"],"invoice":invoice_id,**payload.model_dump()}).mappings().one()
            audit(conn,identity,"receipt.recorded",record_id)
    except IntegrityError as exc:
        if getattr(exc.orig,"sqlstate",None)=="23514": raise HTTPException(409,"Receipt exceeds balance") from None
        conflict(exc)
    response.headers["Cache-Control"]="no-store"
    return serialize(row)
