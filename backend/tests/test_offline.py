from fastapi.testclient import TestClient
from app.main import app

def test_offline_assets():
    client=TestClient(app)
    manifest=client.get("/field-manifest.json")
    assert manifest.status_code==200
    assert manifest.json()["start_url"]=="/portal"
    assert manifest.json()["display"]=="standalone"
    for path in ("/portal","/offline.js","/field-sw.js","/field-icon.svg"):
        response=client.get(path)
        assert response.status_code==200
        assert response.headers["cache-control"]=="no-store"
    assert "worker-src 'self'" in client.get("/portal").headers["content-security-policy"]
    assert 'src="/offline.js"' in client.get("/portal").text
    assert client.get("/api/v1/field-visits").status_code==401
