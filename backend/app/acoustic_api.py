import hashlib
import json
from uuid import UUID,uuid4
from fastapi import APIRouter,Depends,HTTPException,Request,Response
from starlette.concurrency import run_in_threadpool
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.acoustic import signature,similarity,MAX_BYTES
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module
from app.exploitation import audit

router=APIRouter(prefix="/api/v1/acoustic",tags=["experimental acoustic matching"])
METHOD="spectral-goertzel-v1"

async def read_audio(request):
    if request.headers.get("content-type","").split(";")[0]!="audio/wav":
        raise HTTPException(415,"Expected audio/wav")
    data=bytearray()
    async for chunk in request.stream():
        if len(data)+len(chunk)>MAX_BYTES: raise HTTPException(413,"Audio too large")
        data.extend(chunk)
    return bytes(data)

def enroll(work_id,data,identity):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"media")
        require_enabled_module(conn,"works")
        if not conn.execute(text("SELECT EXISTS(SELECT 1 FROM works WHERE id=:id AND category='music' AND status='registered')"),{"id":work_id}).scalar_one():
            raise HTTPException(404,"Registered musical work not found")
        conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:org,366))"),{"org":str(identity["organization_id"])})
        if conn.execute(text("SELECT count(*) FROM acoustic_references")).scalar_one()>=20:
            raise HTTPException(409,"Experimental catalog limit reached")
        sig=signature(data)
        record_id=uuid4()
        try:
            conn.execute(text("""INSERT INTO acoustic_references(id,organization_id,work_id,audio_sha256,signature,created_by)
                VALUES(:id,:org,:work,:digest,CAST(:signature AS json),:actor)"""),{"id":record_id,"org":identity["organization_id"],"work":work_id,"digest":hashlib.sha256(data).hexdigest(),"signature":json.dumps(sig),"actor":identity["account_id"]})
        except IntegrityError as exc:
            if getattr(exc.orig,"sqlstate",None)=="23505": raise HTTPException(409,"Reference already exists") from None
            raise
        audit(conn,identity,"acoustic.reference_created",record_id)
    return {"id":record_id,"work_id":work_id,"method":METHOD}

@router.post("/references/{work_id}",status_code=201)
async def reference(work_id:UUID,request:Request,response:Response,identity=Depends(require_permission("media:review"))):
    data=await read_audio(request)
    result=await run_in_threadpool(enroll,work_id,data,identity)
    response.headers["Cache-Control"]="no-store"
    return result

def match(data,identity):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"media")
        require_enabled_module(conn,"works")
        rows=conn.execute(text("""SELECT a.id,a.work_id,a.signature,w.title FROM acoustic_references a JOIN works w
        ON w.organization_id=a.organization_id AND w.id=a.work_id WHERE w.status='registered' AND w.category='music' ORDER BY a.id LIMIT 20""")).mappings().all()
    query=signature(data)
    results=[{"reference_id":r["id"],"work_id":r["work_id"],"title":r["title"],"similarity":round(similarity(query,r["signature"]),4)} for r in rows]
    results.sort(key=lambda r:(-r["similarity"],str(r["reference_id"])))
    return {"method":METHOD,"experimental":True,"human_review_required":True,"candidates":results[:5]}

@router.post("/match")
async def search(request:Request,response:Response,identity=Depends(require_permission("media:write"))):
    data=await read_audio(request)
    result=await run_in_threadpool(match,data,identity)
    response.headers["Cache-Control"]="no-store"
    return result
