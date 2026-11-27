import secrets
from typing import Literal
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from app.auth import digest, hasher
from app.db import get_engine
from app.invitations import InvitationCreate, InvitationAccept
from app.login_limits import reserve_login
from app.permissions import require_permission
from app.platform_admin import platform_token

router=APIRouter(tags=["member invitations"])

class MemberInvitationCreate(InvitationCreate):
    role: Literal["manager","auditor","artist"]

@router.post("/api/v1/organization/invitations",status_code=201)
def invite_member(payload: MemberInvitationCreate,response: Response,token=Depends(platform_token),identity=Depends(require_permission("members:write"))):
    raw=secrets.token_urlsafe(48)
    try:
        with get_engine().begin() as conn:
            invitation_id=conn.execute(text("SELECT public.tenant_invite_member(:session,:id,:email,:role,:hash)"),
                {"session":token,"id":uuid4(),"email":payload.email.lower(),"role":payload.role,"hash":digest(raw)}).scalar_one()
    except IntegrityError:
        raise HTTPException(status_code=409,detail="Account already exists") from None
    except ProgrammingError as exc:
        if getattr(exc.orig,"sqlstate",None)=="42501":
            raise HTTPException(status_code=403,detail="Invitation access denied") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return {"id":invitation_id,"token":raw,"expires_in":86400}

@router.delete("/api/v1/organization/invitations/{invitation_id}",status_code=204)
def revoke_invitation(invitation_id: UUID,token=Depends(platform_token),identity=Depends(require_permission("members:write"))):
    try:
        with get_engine().begin() as conn:
            found=conn.execute(text("SELECT public.tenant_revoke_invitation(:session,:id)"),{"session":token,"id":invitation_id}).scalar_one()
    except ProgrammingError as exc:
        if getattr(exc.orig,"sqlstate",None)=="42501":
            raise HTTPException(status_code=403,detail="Invitation access denied") from None
        raise
    if not found:
        raise HTTPException(status_code=404,detail="Pending invitation not found")
    return Response(status_code=204,headers={"Cache-Control":"no-store"})

@router.post("/api/v1/auth/member-invitations/accept",status_code=201)
def accept_member(payload: InvitationAccept,request: Request,response: Response):
    raw=payload.token.get_secret_value()
    reserve_login("invite:"+digest(raw),UUID(int=0),request.client.host if request.client else "unknown")
    try:
        with get_engine().begin() as conn:
            org=conn.execute(text("SELECT public.accept_member_invitation(:hash,:account,:password)"),
                {"hash":digest(raw),"account":uuid4(),"password":hasher.hash(payload.password.get_secret_value())}).scalar_one()
    except IntegrityError:
        raise HTTPException(status_code=400,detail="Invalid or expired invitation") from None
    if org is None:
        raise HTTPException(status_code=400,detail="Invalid or expired invitation")
    response.headers["Cache-Control"]="no-store"
    return {"organization_id":org,"mfa_required":False}
