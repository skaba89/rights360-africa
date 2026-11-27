from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Rights360 Africa", version="0.1.0")

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def home():
    return (Path(__file__).parent / "home.html").read_text(encoding="utf-8")

@app.get("/healthz")
def health():
    return {"status": "ok", "service": "rights360-api"}
