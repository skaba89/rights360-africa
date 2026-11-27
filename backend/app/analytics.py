from fastapi import APIRouter, Depends, Response
from sqlalchemy import text
from app.permissions import require_permission
from app.tenant import tenant_transaction
from app.module_access import require_enabled_module
from app.billing import serialize

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])

# Static SQL only. Each dataset is gated by its own effective entitlement.
COUNTS = {
    "artists": "SELECT count(*) AS total,count(*) FILTER (WHERE status='active') AS active FROM artists",
    "works": "SELECT count(*) AS total,count(*) FILTER (WHERE status='registered') AS registered FROM works",
    "licenses": """SELECT (SELECT count(*) FROM operators) AS operators,
        count(*) AS licenses,count(*) FILTER (WHERE status='active' AND CURRENT_DATE BETWEEN starts_on AND ends_on) AS effective FROM exploitation_licenses""",
    "field_control": "SELECT count(*) AS visits,count(*) FILTER (WHERE finding='suspected_noncompliance') AS suspected FROM field_visits",
    "media": """SELECT count(*) AS observations,count(*) FILTER (WHERE r.decision='matched') AS matched,
        count(*) FILTER (WHERE r.decision='unmatched') AS unmatched,count(*) FILTER (WHERE r.observation_id IS NULL) AS pending
        FROM media_observations m LEFT JOIN media_reviews r ON r.organization_id=m.organization_id AND r.observation_id=m.id"""
}

@router.get("/summary")
def summary(response: Response, identity=Depends(require_permission("analytics:read"))):
    with tenant_transaction(identity["organization_id"]) as conn:
        require_enabled_module(conn,"analytics")
        # READ COMMITTED is the existing transaction default; explicitly report this below.
        enabled=set(conn.execute(text("""SELECT m.module_key FROM tenant_modules m
            JOIN module_entitlements e ON e.organization_id=m.organization_id AND e.module_key=m.module_key
            JOIN organizations o ON o.id=m.organization_id
            WHERE m.enabled AND e.granted AND o.active AND (e.expires_at IS NULL OR e.expires_at>now())""")).scalars())
        result={"as_of":conn.execute(text("SELECT now()")).scalar_one(),"consistency":"read_committed","sections":{}}
        for key,sql in COUNTS.items():
            if key in enabled:
                result["sections"][key]=dict(conn.execute(text(sql)).mappings().one())
        if "finance" in enabled:
            rows=conn.execute(text("""WITH paid AS (
                SELECT organization_id,invoice_id,sum(amount_minor) AS total FROM royalty_receipts GROUP BY organization_id,invoice_id
            ) SELECT i.currency,count(*) AS invoices,sum(i.amount_minor) AS billed_minor,
            sum(COALESCE(p.total,0)) AS received_minor,
            sum(i.amount_minor-COALESCE(p.total,0)) AS outstanding_minor,
            COALESCE(sum(i.amount_minor-COALESCE(p.total,0)) FILTER (WHERE i.due_on<CURRENT_DATE),0) AS overdue_minor
            FROM royalty_invoices i LEFT JOIN paid p ON p.organization_id=i.organization_id AND p.invoice_id=i.id
            GROUP BY i.currency ORDER BY i.currency""")).mappings().all()
            result["sections"]["finance"]={"currencies":[serialize(r) for r in rows],"receipts_verified":False}
        if "royalties" in enabled:
            rows=conn.execute(text("""SELECT currency,count(*) AS distributions,sum(gross_minor) AS gross_minor,
                sum(commission_minor) AS commission_minor,sum(net_minor) AS net_minor
                FROM royalty_distributions GROUP BY currency ORDER BY currency""")).mappings().all()
            result["sections"]["royalties"]={"currencies":[serialize(r) for r in rows],"payment_executed":False}
    response.headers["Cache-Control"]="no-store"
    return result
