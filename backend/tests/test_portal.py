from fastapi.testclient import TestClient
from app.main import app

def test_portal_assets_and_security():
    client=TestClient(app)
    page=client.get("/portal")
    assert page.status_code==200
    assert "login-form" in page.text and "confirm-form" in page.text and "invite-form" in page.text
    assert page.headers["cache-control"]=="no-store"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert "'unsafe-inline'" not in page.headers["content-security-policy"]
    assert client.get("/portal.css").headers["content-type"].startswith("text/css")
    js=client.get("/portal.js")
    assert js.status_code==200
    assert "/api/v1/auth/login" in js.text and "/api/v1/auth/mfa/confirm" in js.text
    assert "localStorage" not in js.text and "sessionStorage" not in js.text
    assert 'href="/portal"' in client.get("/").text
