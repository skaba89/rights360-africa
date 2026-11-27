from typing import Literal
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, StrictBool
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from app.db import get_engine
from app.permissions import require_permission
from app.platform_admin import platform_token

router = APIRouter(prefix="/api/v1/organization/members", tags=["organization members"])

class MemberUpdate(BaseModel):
    role: Literal["manager","auditor","artist"]
    active: StrictBool

@router.get("")
def members(response: Response, limit: int=Query(100,ge=1,le=100), offset: int=Query(0,ge=0,le=1000000),
            token=Depends(platform_token), identity=Depends(require_permission("members:read"))):
    try:
        with get_engine().connect() as conn:
            rows=conn.execute(text("SELECT * FROM public.tenant_list_members(:token,:limit,:offset)"),
                {"token":token,"limit":limit,"offset":offset}).mappings().all()
    except ProgrammingError as exc:
        if getattr(exc.orig,"sqlstate",None)=="42501":
            raise HTTPException(status_code=403,detail="Member access denied") from None
        raise
    response.headers["Cache-Control"]="no-store"
    return [dict(row) for row in rows]

@router.patch("/{account_id}")
def update_member(account_id: UUID, payload: MemberUpdate, token=Depends(platform_token),
                  identity=Depends(require_permission("members:write"))):
    try:
        with get_engine().begin() as conn:
            found=conn.execute(text("SELECT public.tenant_update_member(:token,:id,:role,:active)"),
                {"token":token,"id":account_id,"role":payload.role,"active":payload.active}).scalar_one()
    except ProgrammingError as exc:
        if getattr(exc.orig,"sqlstate",None)=="42501":
            raise HTTPException(status_code=403,detail="Member access denied") from None
        raise
    if not found:
        raise HTTPException(status_code=404,detail="Member not found")
    return {"account_id":account_id,"role":payload.role,"active":payload.active}
