import secrets
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from app.auth import digest, hasher
from app.db import get_engine
from app.login_limits import reserve_login
from app.platform_admin import platform_token, require_platform_admin, translate_db_error

router = APIRouter(tags=["customer invitations"])

class InvitationCreate(BaseModel):
    email: str = Field(min_length=3,max_length=254,pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

class InvitationAccept(BaseModel):
    token: SecretStr = Field(min_length=64,max_length=64)
    password: SecretStr = Field(min_length=12,max_length=256)

@router.post("/api/v1/platform/organizations/{organization_id}/invitations",status_code=201)
def invite(organization_id: UUID, payload: InvitationCreate, response: Response, session=Depends(platform_token), identity=Depends(require_platform_admin)):
    raw = secrets.token_urlsafe(48)
    try:
        with get_engine().begin() as conn:
            invitation_id = conn.execute(text("SELECT public.platform_invite_admin(:session,:id,:org,:email,:hash)"),
                {"session":session,"id":uuid4(),"org":organization_id,"email":payload.email.lower(),"hash":digest(raw)}).scalar_one()
    except (IntegrityError,ProgrammingError) as exc:
        translate_db_error(exc)
    if invitation_id is None:
        raise HTTPException(status_code=404,detail="Active organization not found")
    response.headers["Cache-Control"]="no-store"
    return {"id":invitation_id,"token":raw,"expires_in":86400}

@router.post("/api/v1/auth/invitations/accept",status_code=201)
def accept(payload: InvitationAccept, request: Request, response: Response):
    raw=payload.token.get_secret_value()
    reserve_login("invite:"+digest(raw),UUID(int=0),request.client.host if request.client else "unknown")
    try:
        with get_engine().begin() as conn:
            org=conn.execute(text("SELECT public.accept_customer_invitation(:hash,:account,:password)"),
                {"hash":digest(raw),"account":uuid4(),"password":hasher.hash(payload.password.get_secret_value())}).scalar_one()
    except IntegrityError:
        raise HTTPException(status_code=400,detail="Invalid or expired invitation") from None
    if org is None:
        raise HTTPException(status_code=400,detail="Invalid or expired invitation")
    response.headers["Cache-Control"]="no-store"
    return {"organization_id":org,"mfa_required":True}
