from typing import Literal
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router=APIRouter(prefix="/api/v1/works",tags=["works"])
Category=Literal["music","literary","audiovisual","visual","other"]
Status=Literal["draft","registered","archived"]
FIELDS="id,reference,title,category,primary_artist_id,iswc,status,created_at,updated_at"

class WorkData(BaseModel):
    model_config=ConfigDict(extra="forbid",str_strip_whitespace=True)
    reference: str=Field(min_length=1,max_length=50,pattern=r"^[A-Za-z0-9_-]+$")
    title: str=Field(min_length=1,max_length=250)
    category: Category
    primary_artist_id: UUID
    iswc: str | None=Field(default=None,max_length=20)
    status: Status="draft"

    @field_validator("reference")
    @classmethod
    def normalize_reference(cls,v):
        return v.upper()

    @field_validator("iswc")
    @classmethod
    def normalize_iswc(cls,v):
        if v is None: return None
        import re
        v=re.sub(r"[.\s-]","",v.upper())
        if not re.fullmatch(r"T[0-9]{10}",v):
            raise ValueError("Invalid ISWC format")
        digits=[int(d) for d in v[1:]]
        if (1+sum((i+1)*d for i,d in enumerate(digits[:9]))+digits[9])%10:
            raise ValueError("Invalid ISWC check digit")
        return v

    @model_validator(mode="after")
    def check_category(self):
        if self.iswc and self.category!="music":
            raise ValueError("ISWC applies to musical works")
        return self

def audit(conn,identity,work_id,action,status):
    conn.execute(text("""INSERT INTO audit_events(organization_id,actor_id,action,resource_key,details)
        VALUES(:org,:actor,:action,:resource,jsonb_build_object('status',CAST(:status AS text)))"""),
        {"org":identity["organization_id"],"actor":identity["account_id"],"action":action,"resource":str(work_id),"status":status})

def check_artist(conn,artist_id):
    if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM artists WHERE id=:id)"),{"id":artist_id}).scalar_one():
        raise HTTPException(404,"Artist not found")

def conflict(exc):
    if getattr(exc.orig,"sqlstate",None)=="23505":
        raise HTTPException(409,"Work reference or ISWC already exists") from None
    if getattr(exc.orig,"sqlstate",None)=="23503":
        raise HTTPException(404,"Artist not found") from None
    raise exc

@router.get("")
def list_works(response: Response,q: str=Query("",max_length=250),category: Category | None=None,status: Status | None=None,
               limit: int=Query(50,ge=1,le=100),offset: int=Query(0,ge=0,le=1000000),
               identity=Depends(require_permission("works:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"works")
        rows=conn.execute(text(f"""SELECT {FIELDS} FROM works
            WHERE (CAST(:category AS text) IS NULL OR category=:category)
            AND (CAST(:status AS text) IS NULL OR status=:status)
            AND (strpos(lower(title),lower(:q))>0 OR strpos(lower(reference),lower(:q))>0
            OR strpos(lower(COALESCE(iswc,'')),lower(:q))>0)
            ORDER BY title,id LIMIT :limit OFFSET :offset"""),
            {"q":q.strip(),"category":category,"status":status,"limit":limit,"offset":offset}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [dict(row) for row in rows]

@router.get("/{work_id}")
def get_work(work_id: UUID,response: Response,identity=Depends(require_permission("works:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"works")
        row=conn.execute(text(f"SELECT {FIELDS} FROM works WHERE id=:id"),{"id":work_id}).mappings().one_or_none()
        if row is None: raise HTTPException(404,"Work not found")
    response.headers["Cache-Control"]="no-store"
    return dict(row)

@router.post("",status_code=201)
def create_work(payload: WorkData,response: Response,identity=Depends(require_permission("works:write"))):
    work_id=uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn,"works")
            check_artist(conn,payload.primary_artist_id)
            row=conn.execute(text(f"""INSERT INTO works(id,organization_id,reference,title,category,primary_artist_id,iswc,status)
                VALUES(:id,:org,:reference,:title,:category,:primary_artist_id,:iswc,:status) RETURNING {FIELDS}"""),
                {"id":work_id,"org":identity["organization_id"],**payload.model_dump()}).mappings().one()
            audit(conn,identity,work_id,"work.created",payload.status)
    except IntegrityError as exc: conflict(exc)
    response.headers["Cache-Control"]="no-store"
    return dict(row)

@router.put("/{work_id}")
def update_work(work_id: UUID,payload: WorkData,response: Response,identity=Depends(require_permission("works:write"))):
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn,"works")
            check_artist(conn,payload.primary_artist_id)
            row=conn.execute(text(f"""UPDATE works SET reference=:reference,title=:title,category=:category,
                primary_artist_id=:primary_artist_id,iswc=:iswc,status=:status,updated_at=now()
                WHERE id=:id RETURNING {FIELDS}"""),{"id":work_id,**payload.model_dump()}).mappings().one_or_none()
            if row is None: raise HTTPException(404,"Work not found")
            audit(conn,identity,work_id,"work.updated",payload.status)
    except IntegrityError as exc: conflict(exc)
    response.headers["Cache-Control"]="no-store"
    return dict(row)
