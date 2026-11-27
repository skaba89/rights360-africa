from typing import Literal
from uuid import UUID,uuid4
from fastapi import APIRouter,Depends,HTTPException,Query,Response
from pydantic import BaseModel,ConfigDict
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.accounting import require_posted
from app.billing import serialize
from app.exploitation import audit
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router=APIRouter(prefix="/api/v1/payouts",tags=["payout orders"])
class Order(BaseModel):
    model_config=ConfigDict(extra="forbid")
    distribution_id: UUID
    artist_id: UUID
    channel: Literal["bank","orange_money","mtn_momo","other"]

class Review(BaseModel):
    model_config=ConfigDict(extra="forbid")
    decision: Literal["approve","reject"]

def state(reviews):
    if any(r["decision"]=="reject" for r in reviews): return "rejected"
    return "approved_for_review_only" if sum(r["decision"]=="approve" for r in reviews)>=2 else "pending"

def review_rows(conn,order_id):
    return [dict(r) for r in conn.execute(text("SELECT reviewer_id,decision,created_at FROM payout_reviews WHERE order_id=:id ORDER BY created_at,reviewer_id"),{"id":order_id}).mappings().all()]

@router.get("")
def orders(response:Response,limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("billing:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"finance")
        rows=conn.execute(text("SELECT * FROM payout_orders ORDER BY created_at DESC,id LIMIT :limit OFFSET :offset"),{"limit":limit,"offset":offset}).mappings().all()
        result=[]
        for row in rows:
            reviews=review_rows(conn,row["id"])
            result.append({**serialize(row),"status":state(reviews),"reviews":reviews,"execution_enabled":False})
    response.headers["Cache-Control"]="no-store"
    return result

@router.post("",status_code=201)
def create(payload:Order,response:Response,identity=Depends(require_permission("payout:create"))):
    org=identity["organization_id"]; order_id=uuid4()
    try:
        with tenant_transaction(org) as conn:
            require_enabled_module(conn,"finance")
            require_enabled_module(conn,"royalties")
            source=conn.execute(text("""SELECT d.currency,sum(l.amount_minor)::bigint AS amount_minor
            FROM royalty_distributions d JOIN royalty_distribution_lines l ON l.organization_id=d.organization_id AND l.distribution_id=d.id
            JOIN artists a ON a.organization_id=l.organization_id AND a.id=l.artist_id
            WHERE d.id=:distribution_id AND l.artist_id=:artist_id AND a.status='active' GROUP BY d.currency"""),payload.model_dump()).mappings().one_or_none()
            if source is None or source["amount_minor"]<=0: raise HTTPException(404,"Eligible beneficiary not found")
            require_posted(conn,"distribution",payload.distribution_id)
            row=conn.execute(text("""INSERT INTO payout_orders(id,organization_id,distribution_id,artist_id,channel,amount_minor,currency,created_by)
            VALUES(:id,:org,:distribution_id,:artist_id,:channel,:amount,:currency,:actor) RETURNING *"""),
            {"id":order_id,"org":org,"amount":source["amount_minor"],"currency":source["currency"],"actor":identity["account_id"],**payload.model_dump()}).mappings().one()
            audit(conn,identity,"payout.prepared",order_id)
    except IntegrityError as exc:
        if getattr(exc.orig,"sqlstate",None)=="23505": raise HTTPException(409,"Payout already prepared") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return {**serialize(row),"status":"pending","execution_enabled":False}

@router.post("/{order_id}/reviews",status_code=201)
def review(order_id:UUID,payload:Review,response:Response,identity=Depends(require_permission("payout:review"))):
    actor=identity["account_id"]
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn,"finance")
            require_enabled_module(conn,"royalties")
            conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text),363))"),{"id":order_id})
            order=conn.execute(text("SELECT created_by FROM payout_orders WHERE id=:id"),{"id":order_id}).mappings().one_or_none()
            if order is None: raise HTTPException(404,"Payout not found")
            reviews=review_rows(conn,order_id)
            if str(order["created_by"])==str(actor) or state(reviews)!="pending" or any(str(r["reviewer_id"])==str(actor) for r in reviews):
                raise HTTPException(409,"Independent review required")
            conn.execute(text("""INSERT INTO payout_reviews(organization_id,order_id,reviewer_id,decision)
            VALUES(:org,:id,:actor,:decision)"""),{"org":identity["organization_id"],"id":order_id,"actor":actor,"decision":payload.decision})
            audit(conn,identity,"payout."+payload.decision,order_id)
            result=state(review_rows(conn,order_id))
    except IntegrityError as exc:
        if getattr(exc.orig,"sqlstate",None) in ("23505","23514"): raise HTTPException(409,"Invalid review") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return {"id":order_id,"status":result,"execution_enabled":False}
