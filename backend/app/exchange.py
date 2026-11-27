from typing import Literal
from uuid import uuid4
from fastapi import APIRouter,Depends,HTTPException,Query,Response
from pydantic import BaseModel,ConfigDict,Field,StrictBool,field_validator
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.artists import ArtistData
from app.works import WorkData
from app.exploitation import audit
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module

router=APIRouter(prefix="/api/v1/exchange",tags=["catalog exchange"])
SCHEMA="rights360.catalog.v1"

class ExchangeArtist(BaseModel):
    model_config=ConfigDict(extra="forbid",str_strip_whitespace=True)
    member_number: str=Field(min_length=1,max_length=50,pattern=r"^[A-Za-z0-9_-]+$")
    legal_name: str=Field(min_length=1,max_length=200)
    stage_name: str | None=Field(default=None,max_length=200)

    @field_validator("member_number")
    @classmethod
    def normalize(cls,v):
        return v.upper()

class ExchangeWork(BaseModel):
    model_config=ConfigDict(extra="forbid",str_strip_whitespace=True)
    reference: str=Field(min_length=1,max_length=50,pattern=r"^[A-Za-z0-9_-]+$")
    title: str=Field(min_length=1,max_length=250)
    category: Literal["music","literary","audiovisual","visual","other"]
    primary_member_number: str=Field(min_length=1,max_length=50,pattern=r"^[A-Za-z0-9_-]+$")
    iswc: str | None=Field(default=None,max_length=20)

    @field_validator("reference","primary_member_number")
    @classmethod
    def normalize(cls,v):
        return v.upper()

class Catalog(BaseModel):
    model_config=ConfigDict(extra="forbid")
    schema_version: Literal["rights360.catalog.v1"]
    artists: list[ExchangeArtist]=Field(default_factory=list,max_length=100)
    works: list[ExchangeWork]=Field(default_factory=list,max_length=100)

class ImportRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    catalog: Catalog
    dry_run: StrictBool=True

def plan(conn,catalog):
    errors=[]; artists={}; works=[]; seen_refs=set(); seen_iswc=set()
    for i,row in enumerate(catalog.artists):
        key=row.member_number
        if key in artists:
            errors.append({"dataset":"artists","row":i+1,"code":"duplicate_member_number"})
            continue
        old=conn.execute(text("SELECT id,legal_name,stage_name FROM artists WHERE member_number=:key"),{"key":key}).mappings().one_or_none()
        if old is not None and (old["legal_name"],old["stage_name"])!=(row.legal_name,row.stage_name):
            errors.append({"dataset":"artists","row":i+1,"code":"member_conflict"})
        artists[key]=(row,old["id"] if old is not None else None)
    for i,row in enumerate(catalog.works):
        try:
            from uuid import UUID
            validated=WorkData(reference=row.reference,title=row.title,category=row.category,primary_artist_id=UUID(int=0),iswc=row.iswc)
        except ValueError:
            errors.append({"dataset":"works","row":i+1,"code":"invalid_work_identifier"})
            continue
        if row.reference in seen_refs or (validated.iswc and validated.iswc in seen_iswc):
            errors.append({"dataset":"works","row":i+1,"code":"duplicate_work_identifier"})
            continue
        seen_refs.add(row.reference)
        if validated.iswc: seen_iswc.add(validated.iswc)
        if row.primary_member_number not in artists:
            existing=conn.execute(text("SELECT id FROM artists WHERE member_number=:key"),{"key":row.primary_member_number}).scalar_one_or_none()
            if existing is None:
                errors.append({"dataset":"works","row":i+1,"code":"unknown_member"})
                continue
            artists[row.primary_member_number]=(None,existing)
        old=conn.execute(text("SELECT id,reference,title,category,primary_artist_id,iswc FROM works WHERE reference=:ref OR (CAST(:iswc AS text) IS NOT NULL AND iswc=:iswc)"),{"ref":row.reference,"iswc":validated.iswc}).mappings().all()
        if old:
            if len(old)!=1 or (old[0]["reference"],old[0]["title"],old[0]["category"],old[0]["primary_artist_id"],old[0]["iswc"])!=(row.reference,row.title,row.category,artists[row.primary_member_number][1],validated.iswc):
                errors.append({"dataset":"works","row":i+1,"code":"work_conflict"})
            continue
        works.append((row,validated.iswc))
    return artists,works,errors

def require_catalog(conn):
    require_enabled_module(conn,"artists")
    require_enabled_module(conn,"works")

@router.get("/artists")
def export_artists(response:Response,limit:int=Query(100,ge=1,le=100),offset:int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("exchange:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_catalog(conn)
        rows=conn.execute(text("SELECT member_number,legal_name,stage_name FROM artists ORDER BY member_number LIMIT :limit OFFSET :offset"),{"limit":limit,"offset":offset}).mappings().all()
        audit(conn,identity,"exchange.artists_exported",uuid4())
    response.headers["Cache-Control"]="no-store"
    return {"schema_version":SCHEMA,"artists":[dict(r) for r in rows],"works":[]}

@router.get("/works")
def export_works(response:Response,limit:int=Query(100,ge=1,le=100),offset:int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("exchange:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_catalog(conn)
        rows=conn.execute(text("""SELECT w.reference,w.title,w.category,a.member_number AS primary_member_number,w.iswc
        FROM works w JOIN artists a ON a.organization_id=w.organization_id AND a.id=w.primary_artist_id
        ORDER BY w.reference LIMIT :limit OFFSET :offset"""),{"limit":limit,"offset":offset}).mappings().all()
        audit(conn,identity,"exchange.works_exported",uuid4())
    response.headers["Cache-Control"]="no-store"
    return {"schema_version":SCHEMA,"artists":[],"works":[dict(r) for r in rows]}

@router.post("/import")
def import_catalog(payload:ImportRequest,response:Response,identity=Depends(require_permission("exchange:write"))):
    org=identity["organization_id"]
    try:
        with tenant_transaction(org) as conn:
            require_catalog(conn)
            conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:org,365))"),{"org":str(org)})
            artists,works,errors=plan(conn,payload.catalog)
            new_artists=sum(row is not None and key is None for row,key in artists.values())
            report={"schema_version":SCHEMA,"dry_run":payload.dry_run,"valid":not errors,"new_artists":new_artists,"new_works":len(works),"errors":errors,"committed":False}
            if not errors and not payload.dry_run:
                ids={}
                for member,(row,existing) in artists.items():
                    if existing is not None:
                        ids[member]=existing
                        continue
                    artist_id=uuid4()
                    validated=ArtistData(**row.model_dump())
                    conn.execute(text("""INSERT INTO artists(id,organization_id,member_number,legal_name,stage_name,status)
                        VALUES(:id,:org,:member_number,:legal_name,:stage_name,'pending')"""),{"id":artist_id,"org":org,**validated.model_dump()})
                    audit(conn,identity,"exchange.artist_imported",artist_id)
                    ids[member]=artist_id
                for row,iswc in works:
                    work_id=uuid4()
                    conn.execute(text("""INSERT INTO works(id,organization_id,reference,title,category,primary_artist_id,iswc,status)
                        VALUES(:id,:org,:reference,:title,:category,:artist,:iswc,'draft')"""),{"id":work_id,"org":org,"reference":row.reference,"title":row.title,"category":row.category,"artist":ids[row.primary_member_number],"iswc":iswc})
                    audit(conn,identity,"exchange.work_imported",work_id)
                report["committed"]=True
    except IntegrityError as exc:
        if getattr(exc.orig,"sqlstate",None) in ("23505","23503"):
            raise HTTPException(409,"Catalog changed during import; validate again") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return report
