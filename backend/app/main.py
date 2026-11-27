from fastapi import FastAPI

app = FastAPI(title="Rights360 Africa", version="0.1.0")

@app.get("/healthz")
def health():
    return {"status": "ok", "service": "rights360-api"}
