import pytest
from pydantic import ValidationError
from uuid import uuid4
from fastapi.testclient import TestClient
from app.works import WorkData
from app.main import app

def test_work_validation():
    data={"reference":"w-01","title":"Example","category":"music","primary_artist_id":uuid4()}
    assert WorkData(**data).reference=="W-01"
    assert WorkData(**data,iswc="T-000.000.001-0").iswc=="T0000000010"
    with pytest.raises(ValidationError):
        WorkData(**data,iswc="T0000000011")
    with pytest.raises(ValidationError):
        WorkData(**{**data,"category":"literary"},iswc="T0000000010")
    with pytest.raises(ValidationError):
        WorkData(**data,organization_id=uuid4())

def test_work_routes():
    client=TestClient(app)
    assert client.get("/api/v1/works").status_code==401
    assert 'id="work-workspace" hidden' in client.get("/portal").text
    assert "/api/v1/works" in client.get("/portal.js").text
