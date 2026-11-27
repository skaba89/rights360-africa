from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import text
from app.auth import current_identity, bearer, digest
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, StrictBool
from uuid import UUID, uuid4
from sqlalchemy.exc import IntegrityError, ProgrammingError
from app.db import get_engine

router = APIRouter(prefix="/api/v1/platform", tags=["platform administration"])

def require_platform_admin(identity=Depends(current_identity)):
    if identity["role"] != "admin" or not identity.get("mfa_enabled"):
        raise HTTPException(status_code=403, detail="Platform access denied")
    with get_engine().connect() as conn:
        allowed = conn.execute(text("""
            SELECT 1 FROM platform_admins
            WHERE account_id=:account AND organization_id=:org AND active
        """), {"account":identity["account_id"],"org":identity["organization_id"]}).scalar_one_or_none()
    if not allowed:
        raise HTTPException(status_code=403, detail="Platform access denied")
    return identity

@router.get("/me")
def platform_me(response: Response, identity=Depends(require_platform_admin)):
    response.headers["Cache-Control"] = "no-store"
    return {"account_id":identity["account_id"],"organization_id":identity["organization_id"],"platform_role":"super_admin"}

class OrganizationCreate(BaseModel):
    slug: str = Field(min_length=2,max_length=100,pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    name: str = Field(min_length=1,max_length=200)

class OrganizationStatus(BaseModel):
    active: StrictBool

def platform_token(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if credentials is None or len(credentials.credentials)>128:
        raise HTTPException(status_code=401,detail="Invalid session")
    return digest(credentials.credentials)

def translate_db_error(exc):
    state = getattr(exc.orig,"sqlstate",None)
    if state == "42501":
        raise HTTPException(status_code=403,detail="Platform access denied") from exc
    if state == "23505":
        raise HTTPException(status_code=409,detail="Organization already exists") from exc
    if state == "23514":
        raise HTTPException(status_code=409,detail="Protected platform organization") from exc
    raise exc

@router.get("/organizations")
def list_organizations(response: Response, limit: int=100, offset: int=0, token=Depends(platform_token), identity=Depends(require_platform_admin)):
    if not 1<=limit<=100 or offset<0:
        raise HTTPException(status_code=422,detail="Invalid pagination")
    try:
        with get_engine().connect() as conn:
            rows = conn.execute(text("SELECT * FROM public.platform_list_organizations(:token,:limit,:offset)"),{"token":token,"limit":limit,"offset":offset}).mappings().all()
    except (IntegrityError,ProgrammingError) as exc:
        translate_db_error(exc)
    response.headers["Cache-Control"]="no-store"
    return [dict(row) for row in rows]

@router.post("/organizations",status_code=201)
def create_organization(payload: OrganizationCreate, token=Depends(platform_token), identity=Depends(require_platform_admin)):
    name=payload.name.strip()
    if not name:
        raise HTTPException(status_code=422,detail="Empty name")
    try:
        with get_engine().begin() as conn:
            org_id=conn.execute(text("SELECT public.platform_create_organization(:token,:id,:slug,:name)"),{"token":token,"id":uuid4(),"slug":payload.slug,"name":name}).scalar_one()
    except (IntegrityError,ProgrammingError) as exc:
        translate_db_error(exc)
    return {"id":org_id,"slug":payload.slug,"name":name,"active":True}

@router.patch("/organizations/{organization_id}/status")
def change_status(organization_id: UUID, payload: OrganizationStatus, token=Depends(platform_token), identity=Depends(require_platform_admin)):
    try:
        with get_engine().begin() as conn:
            found=conn.execute(text("SELECT public.platform_set_organization_active(:token,:id,:active)"),{"token":token,"id":organization_id,"active":payload.active}).scalar_one()
    except (IntegrityError,ProgrammingError) as exc:
        translate_db_error(exc)
    if not found:
        raise HTTPException(status_code=404,detail="Organization not found")
    return {"id":organization_id,"active":payload.active}
