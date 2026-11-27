from datetime import datetime,timezone,timedelta
from typing import Literal
from uuid import UUID,uuid4
from fastapi import APIRouter,Depends,HTTPException,Query,Response
from pydantic import BaseModel,ConfigDict,Field,StrictInt,AwareDatetime,model_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.exploitation import audit
from app.module_access import require_enabled_module
from app.permissions import require_permission
from app.tenant import tenant_transaction

router=APIRouter(prefix="/api/v1/media-observations",tags=["media intelligence"])
class Observation(BaseModel):
    model_config=ConfigDict(extra="forbid",str_strip_whitespace=True)
    operator_id: UUID
    external_reference: str=Field(min_length=1,max_length=100)
    aired_at: AwareDatetime
    duration_seconds: StrictInt=Field(ge=1,le=86400)
    reported_title: str=Field(min_length=1,max_length=250)
    reported_artist: str=Field(min_length=1,max_length=200)
    fingerprint_sha256: str | None=Field(default=None,pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def check_date(self):
        if self.aired_at>datetime.now(timezone.utc)+timedelta(minutes=5):
            raise ValueError("Future observation")
        return self

class Review(BaseModel):
    model_config=ConfigDict(extra="forbid")
    decision: Literal["matched","unmatched"]
    work_id: UUID | None=None

    @model_validator(mode="after")
    def check_work(self):
        if (self.decision=="matched")!=(self.work_id is not None):
            raise ValueError("Invalid work association")
        return self

@router.get("")
def observations(response:Response,limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("media:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"media")
        rows=conn.execute(text("""SELECT m.*,COALESCE(r.decision,'pending') AS status,r.work_id,r.reviewed_by,r.reviewed_at
        FROM media_observations m LEFT JOIN media_reviews r ON r.organization_id=m.organization_id AND r.observation_id=m.id
        ORDER BY m.aired_at DESC,m.id LIMIT :limit OFFSET :offset"""),{"limit":limit,"offset":offset}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [dict(r) for r in rows]

@router.post("",status_code=201)
def create(payload:Observation,response:Response,identity=Depends(require_permission("media:write"))):
    record_id=uuid4();org=identity["organization_id"]
    try:
        with tenant_transaction(org) as conn:
            require_enabled_module(conn,"media")
            if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM operators WHERE id=:id)"),{"id":payload.operator_id}).scalar_one(): raise HTTPException(404,"Operator not found")
            row=conn.execute(text("""INSERT INTO media_observations(id,organization_id,operator_id,external_reference,aired_at,duration_seconds,reported_title,reported_artist,fingerprint_sha256,created_by)
            VALUES(:id,:org,:operator_id,:external_reference,:aired_at,:duration_seconds,:reported_title,:reported_artist,:fingerprint_sha256,:actor) RETURNING *"""),{"id":record_id,"org":org,"actor":identity["account_id"],**payload.model_dump()}).mappings().one()
            audit(conn,identity,"media.observed",record_id)
    except IntegrityError as exc:
        if getattr(exc.orig,"sqlstate",None)=="23505": raise HTTPException(409,"Duplicate observation") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return {**dict(row),"status":"pending"}

@router.get("/{observation_id}/candidates")
def candidates(observation_id:UUID,response:Response,identity=Depends(require_permission("media:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"media")
        require_enabled_module(conn,"works")
        observation=conn.execute(text("SELECT reported_title FROM media_observations WHERE id=:id"),{"id":observation_id}).scalar_one_or_none()
        if observation is None: raise HTTPException(404,"Observation not found")
        rows=conn.execute(text("""SELECT id,title,primary_artist_id FROM works WHERE category='music' AND status='registered'
        AND lower(trim(title))=lower(trim(:title)) ORDER BY id LIMIT 50"""),{"title":observation}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return {"method":"exact_title_metadata","verified_audio":False,"candidates":[dict(r) for r in rows]}

@router.post("/{observation_id}/review",status_code=201)
def review(observation_id:UUID,payload:Review,response:Response,identity=Depends(require_permission("media:review"))):
    org=identity["organization_id"]
    try:
        with tenant_transaction(org) as conn:
            require_enabled_module(conn,"media")
            require_enabled_module(conn,"works")
            if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM media_observations WHERE id=:id)"),{"id":observation_id}).scalar_one(): raise HTTPException(404,"Observation not found")
            if payload.work_id and not conn.execute(text("SELECT EXISTS(SELECT 1 FROM works WHERE id=:id AND category='music' AND status='registered')"),{"id":payload.work_id}).scalar_one(): raise HTTPException(404,"Eligible work not found")
            row=conn.execute(text("""INSERT INTO media_reviews(organization_id,observation_id,work_id,decision,reviewed_by)
            VALUES(:org,:id,:work_id,:decision,:actor) RETURNING *"""),{"org":org,"id":observation_id,"actor":identity["account_id"],**payload.model_dump()}).mappings().one()
            audit(conn,identity,"media.reviewed",observation_id)
    except IntegrityError as exc:
        if getattr(exc.orig,"sqlstate",None)=="23505": raise HTTPException(409,"Observation already reviewed") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return dict(row)
