import hashlib
from typing import Literal
from uuid import UUID,uuid4
from fastapi import APIRouter,Depends,HTTPException,Query,Request,Response
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel,ConfigDict,Field,model_validator
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool
from app.auth import bearer,current_identity
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module
from app.exploitation import audit
from app import storage

router=APIRouter(prefix="/api/v1/documents",tags=["documents"])
MAX_BYTES=2097152
SUBJECTS={"artist_id":("artists","artists"),"work_id":("works","works"),"operator_id":("operators","licenses"),"license_id":("exploitation_licenses","licenses")}
META="version,sha256,size_bytes,created_by,created_at,object_key,quarantine_status"

class DocumentData(BaseModel):
    model_config=ConfigDict(extra="forbid",str_strip_whitespace=True)
    title:str=Field(min_length=1,max_length=200)
    category:Literal["contract","license","supporting","administrative","other"]
    artist_id:UUID|None=None
    work_id:UUID|None=None
    operator_id:UUID|None=None
    license_id:UUID|None=None

    @model_validator(mode="after")
    def validate_subject(self):
        if sum(getattr(self,k) is not None for k in SUBJECTS)>1: raise ValueError("One subject maximum")
        return self

def allowed(conn):
    require_enabled_module(conn,"documents")
    return set(conn.execute(text("""SELECT m.module_key FROM tenant_modules m JOIN module_entitlements e
        ON e.organization_id=m.organization_id AND e.module_key=m.module_key JOIN organizations o ON o.id=m.organization_id
        WHERE m.enabled AND e.granted AND o.active AND (e.expires_at IS NULL OR e.expires_at>now())""")).scalars())

def subject_allowed(row,modules):
    return all(row[k] is None or module in modules for k,(_,module) in SUBJECTS.items())

def get_doc(conn,doc_id,modules):
    row=conn.execute(text("SELECT * FROM documents WHERE id=:id"),{"id":doc_id}).mappings().one_or_none()
    if row is None or not subject_allowed(row,modules): raise HTTPException(404,"Document not found")
    return row

def lock(conn,doc_id):
    conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text),367))"),{"id":doc_id})

def _identity_or_token(credentials:HTTPAuthorizationCredentials|None=Depends(bearer),token:str|None=Query(None)):
    """Authenticate via Bearer OR a presigned ?token= (anonymous time-limited access)."""
    if token is not None:
        try:
            key=storage.verify_presign(token)
            org_str,doc_str,ver_str=key.split("|")
            return {"presigned":True,"organization_id":UUID(org_str),"account_id":None,
                    "doc_id":UUID(doc_str),"version":int(ver_str)}
        except Exception:
            raise HTTPException(401,"Invalid or expired presign token")
    if credentials is None: raise HTTPException(401,"Not authenticated")
    return current_identity(credentials)

@router.get("")
def listing(response:Response,limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0,le=1000000),identity=Depends(require_permission("documents:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        modules=allowed(conn)
        rows=conn.execute(text("""SELECT d.*,a.archived_at,(SELECT max(v.version) FROM document_versions v WHERE v.document_id=d.id) AS latest_version
            FROM documents d LEFT JOIN document_archives a ON a.organization_id=d.organization_id AND a.document_id=d.id
            WHERE (d.artist_id IS NULL OR :artists) AND (d.work_id IS NULL OR :works)
            AND ((d.operator_id IS NULL AND d.license_id IS NULL) OR :licenses)
            ORDER BY d.created_at DESC,d.id LIMIT :limit OFFSET :offset"""),{"artists":"artists" in modules,"works":"works" in modules,"licenses":"licenses" in modules,"limit":limit,"offset":offset}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [dict(r) for r in rows]

@router.post("",status_code=201)
def create(payload:DocumentData,response:Response,identity=Depends(require_permission("documents:write"))):
    doc_id=uuid4()
    with tenant_transaction(identity["organization_id"]) as conn:
        modules=allowed(conn)
        for key,(table,module) in SUBJECTS.items():
            value=getattr(payload,key)
            if value is not None and (module not in modules or not conn.execute(text(f"SELECT EXISTS(SELECT 1 FROM {table} WHERE id=:id)"),{"id":value}).scalar_one()):
                raise HTTPException(404,"Subject not found")
        row=conn.execute(text("""INSERT INTO documents(id,organization_id,title,category,artist_id,work_id,operator_id,license_id,created_by)
        VALUES(:id,:org,:title,:category,:artist_id,:work_id,:operator_id,:license_id,:actor) RETURNING *"""),{"id":doc_id,"org":identity["organization_id"],"actor":identity["account_id"],**payload.model_dump()}).mappings().one()
        audit(conn,identity,"document.created",doc_id)
    response.headers["Cache-Control"]="no-store"
    return dict(row)

@router.get("/{doc_id}/versions")
def versions(doc_id:UUID,response:Response,identity=Depends(require_permission("documents:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        get_doc(conn,doc_id,allowed(conn))
        rows=conn.execute(text(f"SELECT {META} FROM document_versions WHERE document_id=:id ORDER BY version DESC LIMIT 20"),{"id":doc_id}).mappings().all()
    response.headers["Cache-Control"]="no-store"
    return [dict(r) for r in rows]

def store(doc_id,data,expected,identity):
    org=identity["organization_id"]
    digest=hashlib.sha256(data).hexdigest()
    with tenant_transaction(org) as conn:
        modules=allowed(conn);lock(conn,doc_id);get_doc(conn,doc_id,modules)
        if conn.execute(text("SELECT EXISTS(SELECT 1 FROM document_archives WHERE document_id=:id)"),{"id":doc_id}).scalar_one(): raise HTTPException(409,"Document archived")
        current=conn.execute(text("SELECT COALESCE(max(version),0) FROM document_versions WHERE document_id=:id"),{"id":doc_id}).scalar_one()
        if current!=expected or current>=20: raise HTTPException(409,"Version conflict or limit reached")
        if conn.execute(text("SELECT EXISTS(SELECT 1 FROM document_versions WHERE document_id=:id AND sha256=:digest)"),{"id":doc_id,"digest":digest}).scalar_one(): raise HTTPException(409,"Duplicate content")
        # PHASE 6 — quota enforcement (no row => unlimited, existing tests unaffected).
        quota=conn.execute(text("SELECT max_bytes,max_documents,enforced FROM document_quotas WHERE organization_id=:org"),{"org":org}).mappings().one_or_none()
        if quota and quota["enforced"]:
            used=conn.execute(text("SELECT COALESCE(sum(size_bytes),0)::bigint AS bytes,count(*) AS docs FROM document_versions WHERE organization_id=:org"),{"org":org}).one()
            if used.bytes+len(data)>quota["max_bytes"] or used.docs>=quota["max_documents"]:
                raise HTTPException(413,"Storage quota exceeded")
        # PHASE 6 — quarantine on upload when the DSIG flag is lifted.
        quarantine=conn.execute(text("SELECT public.platform_setting_bool('documents_quarantine_enabled')")).scalar_one()
        qstatus="quarantine" if quarantine else "clean"
        # PHASE 6 — dual-write to object storage when enabled (content stays in Postgres).
        obj_enabled=conn.execute(text("SELECT public.platform_setting_bool('documents_object_storage_enabled')")).scalar_one()
        object_key=None
        if obj_enabled:
            enc=conn.execute(text("SELECT COALESCE((SELECT encryption_enabled FROM document_storage WHERE organization_id=:org),false)"),{"org":org}).scalar_one()
            object_key=f"{org}/{doc_id}/v{current+1}.bin"
            storage.put(object_key,data,enc)
        row=conn.execute(text(f"""INSERT INTO document_versions(organization_id,document_id,version,sha256,size_bytes,content,created_by,object_key,quarantine_status)
        VALUES(:org,:id,:version,:digest,:size,:content,:actor,:object_key,:qstatus) RETURNING {META}"""),{"org":org,"id":doc_id,"version":current+1,"digest":digest,"size":len(data),"content":data,"actor":identity["account_id"],"object_key":object_key,"qstatus":qstatus}).mappings().one()
        audit(conn,identity,"document.version_created",doc_id)
    return dict(row)

@router.post("/{doc_id}/versions",status_code=201)
async def upload(doc_id:UUID,request:Request,response:Response,expected_version:int=Query(...,ge=0,le=19),identity=Depends(require_permission("documents:write"))):
    if request.headers.get("content-type","").split(";")[0]!="application/pdf": raise HTTPException(415,"PDF only")
    data=bytearray()
    async for chunk in request.stream():
        if len(data)+len(chunk)>MAX_BYTES: raise HTTPException(413,"Document too large")
        data.extend(chunk)
    if not data.startswith(b"%PDF-") or not data.rstrip().endswith(b"%%EOF"): raise HTTPException(422,"Invalid PDF envelope")
    result=await run_in_threadpool(store,doc_id,bytes(data),expected_version,identity)
    response.headers["Cache-Control"]="no-store"
    return result

@router.get("/{doc_id}/versions/{version}/content")
def download(doc_id:UUID,version:int,token:str|None=Query(None),identity=Depends(_identity_or_token)):
    org=identity["organization_id"]
    if identity.get("presigned") and (identity["doc_id"]!=doc_id or identity["version"]!=version):
        raise HTTPException(403,"Token does not match the requested document")
    with tenant_transaction(org) as conn:
        if not identity.get("presigned"):
            modules=allowed(conn);get_doc(conn,doc_id,modules)
        row=conn.execute(text("SELECT content,sha256,object_key,quarantine_status FROM document_versions WHERE document_id=:id AND version=:version"),{"id":doc_id,"version":version}).mappings().one_or_none()
        if row is None: raise HTTPException(404,"Version not found")
        # PHASE 6 — never download a quarantined document.
        if row["quarantine_status"]=="quarantine": raise HTTPException(409,"Document in quarantine — download refused")
        # PHASE 6 — serve from object storage when the version lives there.
        if row["object_key"]:
            enc=conn.execute(text("SELECT COALESCE((SELECT encryption_enabled FROM document_storage WHERE organization_id=:org),false)"),{"org":org}).scalar_one()
            content=storage.get(row["object_key"],enc)
        else:
            content=row["content"]
        if hashlib.sha256(content).hexdigest()!=row["sha256"]: raise HTTPException(500,"Document integrity failure")
        # PHASE 6 — access journal (anonymous for presigned downloads).
        actor=identity.get("account_id")
        conn.execute(text("""INSERT INTO document_access_log(id,organization_id,document_id,version,action,account_id)
            VALUES(:lid,:org,:doc,:ver,'download',:actor)"""),
            {"lid":uuid4(),"org":org,"doc":doc_id,"ver":version,"actor":actor})
        if not identity.get("presigned"):
            audit(conn,identity,"document.downloaded",doc_id)
    return Response(content=content,media_type="application/octet-stream",headers={"Content-Disposition":f'attachment; filename="document-{doc_id}-v{version}.pdf"',"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"})

@router.post("/{doc_id}/archive",status_code=201)
def archive(doc_id:UUID,response:Response,identity=Depends(require_permission("documents:archive"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        modules=allowed(conn);lock(conn,doc_id);get_doc(conn,doc_id,modules)
        row=conn.execute(text("""INSERT INTO document_archives(organization_id,document_id,archived_by)
        VALUES(:org,:id,:actor) ON CONFLICT DO NOTHING RETURNING archived_at"""),{"org":identity["organization_id"],"id":doc_id,"actor":identity["account_id"]}).scalar_one_or_none()
        if row is None: raise HTTPException(409,"Already archived")
        audit(conn,identity,"document.archived",doc_id)
    response.headers["Cache-Control"]="no-store"
    return {"archived_at":row}
