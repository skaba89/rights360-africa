from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.auth import router as auth_router

app = FastAPI(title="Rights360 Africa", version="0.1.0")
app.include_router(auth_router)
from app.organization import router as organization_router
app.include_router(organization_router)
from app.platform_admin import router as platform_router
app.include_router(platform_router)

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
