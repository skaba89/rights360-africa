from fastapi.testclient import TestClient
from app.main import app

def test_analytics_routes():
    client=TestClient(app)
    assert client.get("/api/v1/analytics/summary").status_code==401
    assert 'id="analytics-workspace" hidden' in client.get("/portal").text
    assert "/api/v1/analytics/summary" in client.get("/portal.js").text
