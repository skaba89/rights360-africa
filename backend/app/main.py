from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse

from app.auth import router as auth_router

app = FastAPI(title="Rights360 Africa", version="0.1.0")
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
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
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
