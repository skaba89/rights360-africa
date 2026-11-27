from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import text
from app.auth import current_identity
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
