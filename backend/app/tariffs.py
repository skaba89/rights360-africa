from datetime import date
from typing import Literal
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator
from sqlalchemy import text
from app.exploitation import Record, audit
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router=APIRouter(prefix="/api/v1/tariffs",tags=["tariffs"])
FIELDS="id,reference,version,category,usage_type,method,currency,rate,starts_on,ends_on,created_at"

class TariffData(Record):
    expected_version: StrictInt=Field(ge=0,le=2147483646)
    category: Literal["radio","television","hotel","restaurant","event","digital","other"]
    usage_type: str=Field(min_length=1,max_length=100)
    method: Literal["flat","revenue","capacity","frequency"]
    currency: Literal["GNF","XOF","EUR","USD"]
    rate: StrictInt=Field(gt=0,le=1000000000000)
    starts_on: date
    ends_on: date

    @model_validator(mode="after")
    def valid(self):
        if self.ends_on<self.starts_on or (self.method=="revenue" and self.rate>10000):
            raise ValueError("Invalid dates or rate")
        return self

class QuoteData(BaseModel):
    model_config=ConfigDict(extra="forbid")
    license_id: UUID
    usage_date: date
    quantity: StrictInt | None=Field(default=None,ge=1,le=1000000)
    revenue_minor: StrictInt | None=Field(default=None,ge=0,le=1000000000000000)

def calculate(method,rate,payload):
    if method=="flat" and payload.quantity is None and payload.revenue_minor is None:
        return rate
    if method in ("capacity","frequency") and payload.quantity is not None and payload.revenue_minor is None:
        return rate*payload.quantity
    if method=="revenue" and payload.revenue_minor is not None and payload.quantity is None:
        return (payload.revenue_minor*rate+5000)//10000
    raise HTTPException(422,"Incorrect calculation inputs")

@router.get("")
def list_tariffs(response: Response,limit: int=Query(50,ge=1,le=100),offset: int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("licenses:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"licenses")
        rows=conn.execute(text(f"SELECT {FIELDS} FROM tariffs ORDER BY reference,version DESC LIMIT :limit OFFSET :offset"),{"limit":limit,"offset":offset}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [dict(row) for row in rows]

@router.post("",status_code=201)
def create_tariff(payload: TariffData,response: Response,identity=Depends(require_permission("licenses:approve"))):
    org=identity["organization_id"]
    record_id=uuid4()
    with tenant_transaction(org) as conn:
        require_enabled_module(conn,"licenses")
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,361))"),{"key":str(org)+":"+payload.reference})
        current=conn.execute(text("SELECT COALESCE(max(version),0) FROM tariffs WHERE reference=:ref"),{"ref":payload.reference}).scalar_one()
        if current!=payload.expected_version:
            raise HTTPException(409,"Tariff version changed")
        row=conn.execute(text(f"""INSERT INTO tariffs(id,organization_id,reference,version,category,usage_type,method,currency,rate,starts_on,ends_on)
            VALUES(:id,:org,:reference,:version,:category,:usage_type,:method,:currency,:rate,:starts_on,:ends_on) RETURNING {FIELDS}"""),
            {"id":record_id,"org":org,"version":current+1,**payload.model_dump(exclude={"expected_version"})}).mappings().one()
        audit(conn,identity,"tariff.created",record_id)
    response.headers["Cache-Control"]="no-store"
    return dict(row)

@router.post("/{tariff_id}/quote")
def quote(tariff_id: UUID,payload: QuoteData,response: Response,identity=Depends(require_permission("licenses:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"licenses")
        tariff=conn.execute(text(f"SELECT {FIELDS} FROM tariffs WHERE id=:id"),{"id":tariff_id}).mappings().one_or_none()
        license=conn.execute(text("""SELECT l.status,l.starts_on,l.ends_on,l.usage_type,o.category FROM exploitation_licenses l
            JOIN operators o ON o.organization_id=l.organization_id AND o.id=l.operator_id WHERE l.id=:id"""),{"id":payload.license_id}).mappings().one_or_none()
        if tariff is None or license is None:
            raise HTTPException(404,"Tariff or license not found")
        if license["status"]!="active" or not license["starts_on"]<=payload.usage_date<=license["ends_on"] or not tariff["starts_on"]<=payload.usage_date<=tariff["ends_on"] or tariff["category"]!=license["category"] or tariff["usage_type"]!=license["usage_type"]:
            raise HTTPException(409,"Tariff not applicable")
        amount=calculate(tariff["method"],tariff["rate"],payload)
    response.headers["Cache-Control"]="no-store"
    return {"tariff_id":tariff_id,"tariff_version":tariff["version"],"license_id":payload.license_id,"currency":tariff["currency"],"amount_minor":str(amount),"usage_date":payload.usage_date,"estimate":True}
