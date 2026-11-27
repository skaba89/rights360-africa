from fastapi.testclient import TestClient
from app.main import app

def test_health():
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "rights360-api"}
