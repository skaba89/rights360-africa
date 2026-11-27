from typing import Literal
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, ConfigDict, field_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router=APIRouter(prefix="/api/v1/artists",tags=["artists"])
Status=Literal["pending","active","suspended","archived"]
FIELDS="id,member_number,legal_name,stage_name,email,phone,status,created_at,updated_at"

class ArtistData(BaseModel):
    model_config=ConfigDict(extra="forbid",str_strip_whitespace=True)
    member_number: str=Field(min_length=1,max_length=50,pattern=r"^[A-Za-z0-9_-]+$")
    legal_name: str=Field(min_length=1,max_length=200)
    stage_name: str | None=Field(default=None,max_length=200)
    email: str | None=Field(default=None,max_length=254,pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    phone: str | None=Field(default=None,max_length=40)
    status: Status="pending"

    @field_validator("member_number")
    @classmethod
    def normalize_number(cls,value):
        return value.upper()

def audit(conn,identity,artist_id,action,status):
    conn.execute(text("""INSERT INTO audit_events(organization_id,actor_id,action,resource_key,details)
        VALUES(:org,:actor,:action,:resource,jsonb_build_object('status',CAST(:status AS text)))"""),
        {"org":identity["organization_id"],"actor":identity["account_id"],"action":action,"resource":str(artist_id),"status":status})

@router.get("")
def list_artists(response: Response,q: str=Query("",max_length=200),status: Status | None=None,
                 limit: int=Query(50,ge=1,le=100),offset: int=Query(0,ge=0,le=1000000),
                 identity=Depends(require_permission("artists:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"artists")
        rows=conn.execute(text(f"""SELECT {FIELDS} FROM artists
            WHERE (CAST(:status AS text) IS NULL OR status=:status)
            AND (strpos(lower(legal_name),lower(:q))>0 OR strpos(lower(COALESCE(stage_name,'')),lower(:q))>0
            OR strpos(lower(member_number),lower(:q))>0)
            ORDER BY legal_name,id LIMIT :limit OFFSET :offset"""),
            {"q":q.strip(),"status":status,"limit":limit,"offset":offset}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [dict(row) for row in rows]

@router.get("/{artist_id}")
def get_artist(artist_id: UUID,response: Response,identity=Depends(require_permission("artists:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"artists")
        row=conn.execute(text(f"SELECT {FIELDS} FROM artists WHERE id=:id"),{"id":artist_id}).mappings().one_or_none()
        if row is None: raise HTTPException(404,"Artist not found")
    response.headers["Cache-Control"]="no-store"
    return dict(row)

@router.post("",status_code=201)
def create_artist(payload: ArtistData,response: Response,identity=Depends(require_permission("artists:write"))):
    artist_id=uuid4()
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn,"artists")
            row=conn.execute(text(f"""INSERT INTO artists(id,organization_id,member_number,legal_name,stage_name,email,phone,status)
                VALUES(:id,:org,:member_number,:legal_name,:stage_name,:email,:phone,:status) RETURNING {FIELDS}"""),
                {"id":artist_id,"org":identity["organization_id"],**payload.model_dump()}).mappings().one()
            audit(conn,identity,artist_id,"artist.created",payload.status)
    except IntegrityError as exc:
        if getattr(exc.orig,"sqlstate",None)=="23505": raise HTTPException(409,"Member number already exists") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return dict(row)

@router.put("/{artist_id}")
def update_artist(artist_id: UUID,payload: ArtistData,response: Response,identity=Depends(require_permission("artists:write"))):
    try:
        with tenant_transaction(identity["organization_id"]) as conn:
            require_enabled_module(conn,"artists")
            row=conn.execute(text(f"""UPDATE artists SET member_number=:member_number,legal_name=:legal_name,
                stage_name=:stage_name,email=:email,phone=:phone,status=:status,updated_at=now()
                WHERE id=:id RETURNING {FIELDS}"""),{"id":artist_id,**payload.model_dump()}).mappings().one_or_none()
            if row is None: raise HTTPException(404,"Artist not found")
            audit(conn,identity,artist_id,"artist.updated",payload.status)
    except IntegrityError as exc:
        if getattr(exc.orig,"sqlstate",None)=="23505": raise HTTPException(409,"Member number already exists") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return dict(row)
