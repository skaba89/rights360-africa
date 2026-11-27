from uuid import UUID,uuid4
from fastapi import APIRouter,Depends,HTTPException,Query,Response
from pydantic import BaseModel,ConfigDict,Field,StrictInt
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.billing import serialize
from app.exploitation import audit
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router=APIRouter(prefix="/api/v1/distributions",tags=["royalty distribution"])

class DistributionData(BaseModel):
    model_config=ConfigDict(extra="forbid")
    receipt_id: UUID
    declaration_id: UUID
    commission_bps: StrictInt=Field(ge=0,le=10000)

def allocate(gross,commission_bps,shares):
    if gross<=0 or not 0<=commission_bps<=10000 or not shares or any(not 1<=s["basis_points"]<=10000 for s in shares) or sum(s["basis_points"] for s in shares)!=10000:
        raise HTTPException(409,"Invalid distribution basis")
    commission=(gross*commission_bps+5000)//10000
    net=gross-commission
    lines=[]
    for s in shares:
        amount,remainder=divmod(net*s["basis_points"],10000)
        lines.append({**s,"amount_minor":amount,"remainder":remainder})
    missing=net-sum(s["amount_minor"] for s in lines)
    lines.sort(key=lambda s:(-s["remainder"],str(s["artist_id"]),s["role"]))
    for s in lines[:missing]: s["amount_minor"]+=1
    for s in lines: del s["remainder"]
    return commission,net,lines

@router.get("")
def distributions(response: Response,limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("distribution:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"royalties")
        rows=conn.execute(text("SELECT * FROM royalty_distributions ORDER BY created_at DESC,id LIMIT :limit OFFSET :offset"),{"limit":limit,"offset":offset}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [serialize(r) for r in rows]

@router.get("/{distribution_id}/lines")
def lines(distribution_id:UUID,response:Response,identity=Depends(require_permission("distribution:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"royalties")
        if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM royalty_distributions WHERE id=:id)"),{"id":distribution_id}).scalar_one(): raise HTTPException(404,"Distribution not found")
        rows=conn.execute(text("SELECT artist_id,role,basis_points,amount_minor FROM royalty_distribution_lines WHERE distribution_id=:id ORDER BY artist_id,role"),{"id":distribution_id}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [serialize(r) for r in rows]

@router.post("",status_code=201)
def distribute(payload:DistributionData,response:Response,identity=Depends(require_permission("distribution:write"))):
    org=identity["organization_id"]
    record_id=uuid4()
    try:
        with tenant_transaction(org) as conn:
            for key in ("royalties","finance","works"): require_enabled_module(conn,key)
            receipt=conn.execute(text("""SELECT r.amount_minor,i.currency,l.work_id FROM royalty_receipts r
            JOIN royalty_invoices i ON i.organization_id=r.organization_id AND i.id=r.invoice_id
            JOIN exploitation_licenses l ON l.organization_id=i.organization_id AND l.id=i.license_id
            WHERE r.id=:id"""),{"id":payload.receipt_id}).mappings().one_or_none()
            declaration=conn.execute(text("SELECT work_id,status FROM work_rights_declarations WHERE id=:id"),{"id":payload.declaration_id}).mappings().one_or_none()
            if receipt is None or declaration is None: raise HTTPException(404,"Receipt or declaration not found")
            if receipt["work_id"] is None or receipt["work_id"]!=declaration["work_id"] or declaration["status"]!="complete": raise HTTPException(409,"Ineligible declaration")
            shares=conn.execute(text("SELECT artist_id,role,basis_points FROM work_rights_shares WHERE declaration_id=:id"),{"id":payload.declaration_id}).mappings().all()
            commission,net,allocations=allocate(receipt["amount_minor"],payload.commission_bps,[dict(s) for s in shares])
            row=conn.execute(text("""INSERT INTO royalty_distributions(id,organization_id,receipt_id,declaration_id,currency,gross_minor,commission_bps,commission_minor,net_minor,created_by)
            VALUES(:id,:org,:receipt,:declaration,:currency,:gross,:bps,:commission,:net,:actor) RETURNING *"""),
            {"id":record_id,"org":org,"receipt":payload.receipt_id,"declaration":payload.declaration_id,"currency":receipt["currency"],"gross":receipt["amount_minor"],"bps":payload.commission_bps,"commission":commission,"net":net,"actor":identity["account_id"]}).mappings().one()
            conn.execute(text("""INSERT INTO royalty_distribution_lines(organization_id,distribution_id,artist_id,role,basis_points,amount_minor)
            VALUES(:org,:distribution,:artist_id,:role,:basis_points,:amount_minor)"""),[{"org":org,"distribution":record_id,**s} for s in allocations])
            audit(conn,identity,"distribution.calculated",record_id)
    except IntegrityError as exc:
        if getattr(exc.orig,"sqlstate",None)=="23505": raise HTTPException(409,"Receipt already distributed") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return {**serialize(row),"lines":[serialize(s) for s in allocations]}
