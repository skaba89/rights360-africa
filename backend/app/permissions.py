from fastapi import Depends, HTTPException
from app.auth import current_identity

PERMISSIONS = {
    "admin": frozenset({"organization:read", "modules:read", "modules:write", "members:read", "members:write", "artists:read", "artists:write", "works:read", "works:write", "licenses:read", "licenses:write", "licenses:approve", "billing:read", "billing:write", "distribution:read", "distribution:write", "payout:create", "payout:review", "field:read", "field:write", "media:read", "media:write", "media:review", "analytics:read", "exchange:read", "exchange:write", "documents:read", "documents:write", "documents:archive"}),
    "manager": frozenset({"organization:read", "modules:read", "artists:read", "artists:write", "works:read", "works:write", "licenses:read", "licenses:write", "billing:read", "distribution:read", "payout:create", "field:read", "field:write", "media:read", "media:write", "analytics:read", "exchange:read", "documents:read", "documents:write"}),
    "auditor": frozenset({"organization:read", "modules:read", "artists:read", "works:read", "licenses:read", "billing:read", "distribution:read", "payout:review", "field:read", "media:read", "analytics:read", "exchange:read", "documents:read"}),
    "artist": frozenset({"organization:read"}),
}

def require_permission(permission: str):
    def check(identity=Depends(current_identity)):
        if identity["role"] == "admin" and not identity.get("mfa_enabled", False):
            raise HTTPException(status_code=403, detail="MFA enrollment required")
        if permission not in PERMISSIONS.get(identity["role"], frozenset()):
            raise HTTPException(status_code=403, detail="Permission denied")
        return identity
    return check
