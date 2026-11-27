from fastapi.testclient import TestClient
from app.main import app

def test_console_markup_and_api_wiring():
    client = TestClient(app)
    page = client.get("/portal")
    assert page.status_code == 200
    assert 'id="platform-view" hidden' in page.text
    assert 'id="open-platform" hidden' in page.text
    for name in ("create-org","grant-form","platform-invite","change-status","next-orgs"):
        assert f'id="{name}"' in page.text
    script = client.get("/portal.js").text
    for path in ("/api/v1/platform/me","/api/v1/platform/organizations","/entitlements","/invitations","/status"):
        assert path in script
    assert "innerHTML" not in script
    assert "localStorage" not in script
    assert client.get("/api/v1/platform/organizations").status_code == 401
