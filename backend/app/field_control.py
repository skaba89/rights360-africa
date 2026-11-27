import hashlib
import json
from datetime import datetime,timezone,timedelta
from typing import Literal
from uuid import UUID
from fastapi import APIRouter,Depends,HTTPException,Query,Response
from pydantic import BaseModel,ConfigDict,Field,StrictInt,AwareDatetime,model_validator
from sqlalchemy import text
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module
from app.exploitation import audit

router=APIRouter(prefix="/api/v1/field-visits",tags=["field control"])
class Visit(BaseModel):
    model_config=ConfigDict(extra="forbid",str_strip_whitespace=True)
    id: UUID
    operator_id: UUID
    visited_at: AwareDatetime
    latitude_e6: StrictInt | None=Field(default=None,ge=-90000000,le=90000000)
    longitude_e6: StrictInt | None=Field(default=None,ge=-180000000,le=180000000)
    finding: Literal["observed","suspected_noncompliance","followup"]
    notes: str=Field(max_length=2000)

    @model_validator(mode="after")
    def validate_visit(self):
        if (self.latitude_e6 is None)!=(self.longitude_e6 is None):
            raise ValueError("Coordinates must be paired")
        if self.visited_at>datetime.now(timezone.utc)+timedelta(minutes=5):
            raise ValueError("Future visit")
        self.visited_at=self.visited_at.astimezone(timezone.utc)
        return self

FIELDS="id,operator_id,agent_id,visited_at,latitude_e6,longitude_e6,finding,notes,license_snapshot,received_at"

@router.get("")
def visits(response:Response,limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("field:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"field_control")
        rows=conn.execute(text(f"SELECT {FIELDS} FROM field_visits ORDER BY visited_at DESC,id LIMIT :limit OFFSET :offset"),{"limit":limit,"offset":offset}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [dict(r) for r in rows]

@router.get("/operators")
def operators(response:Response,q:str=Query("",max_length=200),limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("field:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"field_control")
        rows=conn.execute(text("SELECT id,reference,name,category FROM operators WHERE strpos(lower(name),lower(:q))>0 OR strpos(lower(reference),lower(:q))>0 ORDER BY name,id LIMIT :limit OFFSET :offset"),{"q":q,"limit":limit,"offset":offset}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [dict(r) for r in rows]

@router.post("",status_code=201)
def submit(payload:Visit,response:Response,identity=Depends(require_permission("field:write"))):
    org=identity["organization_id"]
    digest=hashlib.sha256(json.dumps(payload.model_dump(mode="json"),sort_keys=True,separators=(",",":")).encode()).hexdigest()
    with tenant_transaction(org) as conn:
        require_enabled_module(conn,"field_control")
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text),364))"),{"id":payload.id})
        old=conn.execute(text(f"SELECT {FIELDS},payload_hash FROM field_visits WHERE id=:id"),{"id":payload.id}).mappings().one_or_none()
        if old:
            if old["payload_hash"]!=digest or str(old["agent_id"])!=str(identity["account_id"]): raise HTTPException(409,"Visit identifier conflict")
            response.status_code=200
            response.headers["Cache-Control"]="no-store"
            return {k:v for k,v in old.items() if k!="payload_hash"}
        if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM operators WHERE id=:id)"),{"id":payload.operator_id}).scalar_one():
            raise HTTPException(404,"Operator not found")
        licenses=conn.execute(text("""SELECT id,reference,status,starts_on,ends_on,usage_type,territory
          FROM exploitation_licenses WHERE operator_id=:id ORDER BY id LIMIT 101"""),{"id":payload.operator_id}).mappings().all()
        snapshot={"as_of":datetime.now(timezone.utc).isoformat(),"truncated":len(licenses)>100,"records":[dict(r) for r in licenses[:100]],"historical_status_verified":False}
        row=conn.execute(text(f"""INSERT INTO field_visits(id,organization_id,operator_id,agent_id,visited_at,latitude_e6,longitude_e6,finding,notes,payload_hash,license_snapshot)
          VALUES(:id,:org,:operator_id,:agent,:visited_at,:latitude_e6,:longitude_e6,:finding,:notes,:digest,CAST(:snapshot AS json)) ON CONFLICT(id) DO NOTHING RETURNING {FIELDS}"""),
          {"org":org,"agent":identity["account_id"],"digest":digest,"snapshot":json.dumps(snapshot,default=str),**payload.model_dump()}).mappings().one_or_none()
        if row is None: raise HTTPException(409,"Visit identifier conflict")
        audit(conn,identity,"field.visit_recorded",payload.id)
    response.headers["Cache-Control"]="no-store"
    return dict(row)
