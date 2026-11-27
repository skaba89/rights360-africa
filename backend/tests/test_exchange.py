import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from app.exchange import Catalog,ImportRequest
from app.main import app

def test_exchange_contract():
    data={"schema_version":"rights360.catalog.v1","artists":[{"member_number":"m-1","legal_name":"Artist"}],"works":[]}
    assert Catalog(**data).artists[0].member_number=="M-1"
    assert ImportRequest(catalog=data).dry_run is True
    with pytest.raises(ValidationError):
        Catalog(**{**data,"schema_version":"unsupported"})
    with pytest.raises(ValidationError):
        Catalog(**{**data,"artists":[{"member_number":"m-1","legal_name":"Artist","email":"a@example.invalid"}]})
    with pytest.raises(ValidationError):
        Catalog(**{**data,"artists":data["artists"]*101})

def test_routes():
    client=TestClient(app)
    assert client.get("/api/v1/exchange/artists").status_code==401
    assert client.get("/api/v1/exchange/works").status_code==401
    assert 'id="exchange-workspace" hidden' in client.get("/portal").text
