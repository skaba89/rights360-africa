from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse

from app.auth import router as auth_router
from app.startup_checks import validate_runtime


@asynccontextmanager
async def lifespan(app):
    # Fail fast on a missing/invalid MFA key before serving any request, instead
    # of crashing inside app.mfa.cipher() on the first MFA operation. Runs on
    # server startup (and TestClient context-manager entry); plain imports and
    # plain TestClient(app) usage do NOT trigger it, so pytest collection and
    # tooling that import the app are safe without a configured key.
    validate_runtime()
    yield


app = FastAPI(title="Rights360 Africa", version="0.1.0", lifespan=lifespan)
app.include_router(auth_router)
from app.organization import router as organization_router
app.include_router(organization_router)
from app.platform_admin import router as platform_router
app.include_router(platform_router)
from app.invitations import router as invitations_router
app.include_router(invitations_router)
from app.members import router as members_router
app.include_router(members_router)
from app.member_invitations import router as member_invitations_router
app.include_router(member_invitations_router)
from app.artists import router as artists_router
app.include_router(artists_router)
from app.works import router as works_router
app.include_router(works_router)
from app.rights_shares import router as rights_router
app.include_router(rights_router)
from app.exploitation import router as exploitation_router
app.include_router(exploitation_router)
from app.tariffs import router as tariffs_router
app.include_router(tariffs_router)
from app.billing import router as billing_router
app.include_router(billing_router)
from app.distribution import router as distribution_router
app.include_router(distribution_router)
from app.accounting import router as accounting_router
app.include_router(accounting_router)
from app.payouts import router as payouts_router
app.include_router(payouts_router)
from app.field_control import router as field_router
app.include_router(field_router)
from app.media import router as media_router
app.include_router(media_router)
from app.analytics import router as analytics_router
app.include_router(analytics_router)
from app.exchange import router as exchange_router
app.include_router(exchange_router)
from app.acoustic_api import router as acoustic_router
app.include_router(acoustic_router)
from app.documents import router as documents_router
app.include_router(documents_router)
from app.legal import router as legal_router
app.include_router(legal_router)
from app.rights_advanced import router as rights_advanced_router
app.include_router(rights_advanced_router)
from app.finance import router as finance_router
app.include_router(finance_router)
from app.payments import router as payments_router
app.include_router(payments_router)
from app.ged import router as ged_router
app.include_router(ged_router)

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home():
    return (Path(__file__).parent / "home.html").read_text(encoding="utf-8")

@app.get("/healthz")
def health():
    return {"status": "ok", "service": "rights360-api"}

@app.get("/readyz")
def ready():
    from app.db import check_database
    from sqlalchemy.exc import SQLAlchemyError
    from fastapi import HTTPException
    try:
        check_database()
    except (SQLAlchemyError, KeyError):
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"status": "ready"}

PORTAL_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}

@app.get("/portal", include_in_schema=False)
def portal():
    return HTMLResponse((Path(__file__).parent / "portal.html").read_text(encoding="utf-8"),headers=PORTAL_HEADERS)

@app.get("/portal.css", include_in_schema=False)
def portal_css():
    return FileResponse(Path(__file__).parent / "portal.css",media_type="text/css",headers=PORTAL_HEADERS)

@app.get("/portal.js", include_in_schema=False)
def portal_js():
    return FileResponse(Path(__file__).parent / "portal.js",media_type="application/javascript",headers=PORTAL_HEADERS)

@app.get("/offline.js", include_in_schema=False)
def offline_js():
    return FileResponse(Path(__file__).parent / "offline.js",media_type="application/javascript",headers=PORTAL_HEADERS)

@app.get("/field-sw.js", include_in_schema=False)
def field_sw():
    return FileResponse(Path(__file__).parent / "field-sw.js",media_type="application/javascript",headers=PORTAL_HEADERS)

@app.get("/field-manifest.json", include_in_schema=False)
def field_manifest():
    return FileResponse(Path(__file__).parent / "field-manifest.json",media_type="application/manifest+json",headers=PORTAL_HEADERS)

@app.get("/field-icon.svg", include_in_schema=False)
def field_icon():
    return FileResponse(Path(__file__).parent / "field-icon.svg",media_type="image/svg+xml",headers=PORTAL_HEADERS)
