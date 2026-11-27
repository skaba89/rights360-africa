from fastapi.testclient import TestClient
from app.main import app

def test_institution_dashboard_wiring():
    client=TestClient(app)
    page=client.get("/portal")
    assert page.status_code == 200
    assert 'id="institution-view" hidden' in page.text
    for name in ("institution-module-list","member-list","member-invite-form","member-revoke-form"):
        assert f'id="{name}"' in page.text
    script=client.get("/portal.js").text
    assert "/api/v1/organization" in script
    assert 'tenantBase+"/modules"' in script
    assert 'tenantBase+"/members?limit=20' in script
    assert 'tenantBase+"/invitations"' in script
    assert "innerHTML" not in script
    assert client.get("/api/v1/organization/members").status_code == 401
    assert client.get("/api/v1/organization/modules").status_code == 401
