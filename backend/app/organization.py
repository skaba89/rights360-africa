from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, StrictBool
from sqlalchemy import text
from app.permissions import require_permission
from app.tenant import tenant_transaction

router = APIRouter(prefix="/api/v1/organization", tags=["organization"])
MODULES = frozenset({"artists", "works", "licenses", "royalties", "finance", "field_control", "media", "analytics", "legal", "documents"})

class ModuleUpdate(BaseModel):
    enabled: StrictBool

@router.get("")
def organization(identity=Depends(require_permission("organization:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        row = conn.execute(text("SELECT id,slug,name FROM organizations")).mappings().one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="Organization not found")
        return dict(row)

@router.get("/modules")
def modules(identity=Depends(require_permission("modules:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        stored = dict(conn.execute(text("SELECT module_key,enabled FROM tenant_modules")).all())
        entitled = set(conn.execute(text("SELECT module_key FROM module_entitlements WHERE granted AND (expires_at IS NULL OR expires_at>now())")).scalars())
    return [{"module_key":key,"enabled":stored.get(key,False) and key in entitled,"entitled":key in entitled} for key in sorted(MODULES)]

@router.put("/modules/{module_key}")
def update_module(module_key: str, payload: ModuleUpdate, identity=Depends(require_permission("modules:write"))):
    if module_key not in MODULES:
        raise HTTPException(status_code=404, detail="Unknown module")
    with tenant_transaction(identity["organization_id"]) as conn:
        if payload.enabled and not conn.execute(text("SELECT EXISTS(SELECT 1 FROM module_entitlements WHERE module_key=:key AND granted AND (expires_at IS NULL OR expires_at>now()))"),{"key":module_key}).scalar_one():
            raise HTTPException(status_code=403,detail="Module not entitled")
        conn.execute(text("""INSERT INTO tenant_modules(organization_id,module_key,enabled)
            VALUES (:org,:key,:enabled)
            ON CONFLICT (organization_id,module_key) DO UPDATE SET enabled=EXCLUDED.enabled"""),
            {"org":identity["organization_id"],"key":module_key,"enabled":payload.enabled})
        conn.execute(text("""INSERT INTO audit_events(organization_id,actor_id,action,resource_key,details)
            VALUES (:org,:actor,'module.updated',:key,jsonb_build_object('enabled',CAST(:enabled AS boolean)))"""),
            {"org":identity["organization_id"],"actor":identity["account_id"],"key":module_key,"enabled":payload.enabled})
    return {"module_key":module_key,"enabled":payload.enabled}
