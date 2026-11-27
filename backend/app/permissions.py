from fastapi import Depends, HTTPException
from app.auth import current_identity

PERMISSIONS = {
    "admin": frozenset({"organization:read", "modules:read", "modules:write"}),
    "manager": frozenset({"organization:read", "modules:read"}),
    "auditor": frozenset({"organization:read", "modules:read"}),
    "artist": frozenset({"organization:read"}),
}

def require_permission(permission: str):
    def check(identity=Depends(current_identity)):
        if permission not in PERMISSIONS.get(identity["role"], frozenset()):
            raise HTTPException(status_code=403, detail="Permission denied")
        return identity
    return check
