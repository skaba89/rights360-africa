from fastapi import HTTPException
from sqlalchemy import text

def require_enabled_module(conn, key: str):
    allowed=conn.execute(text("""
        SELECT EXISTS(SELECT 1 FROM tenant_modules m
        JOIN module_entitlements e ON e.organization_id=m.organization_id AND e.module_key=m.module_key
        JOIN organizations o ON o.id=m.organization_id
        WHERE m.module_key=:key AND m.enabled AND e.granted AND o.active
        AND (e.expires_at IS NULL OR e.expires_at>now()))
    """),{"key":key}).scalar_one()
    if not allowed:
        raise HTTPException(status_code=403,detail="Module unavailable")
