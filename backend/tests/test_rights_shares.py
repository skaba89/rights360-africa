import pytest
from uuid import uuid4
from pydantic import ValidationError
from fastapi.testclient import TestClient
from app.rights_shares import Declaration
from app.main import app

def test_share_totals():
    a={"artist_id":uuid4(),"role":"author","basis_points":6000}
    b={"artist_id":uuid4(),"role":"composer","basis_points":4000}
    assert Declaration(expected_version=0,status="complete",shares=[a,b]).status=="complete"
    for shares in ([a],[a,a],[a,{**b,"basis_points":5000}]):
        with pytest.raises(ValidationError):
            Declaration(expected_version=0,status="complete",shares=shares)
    with pytest.raises(ValidationError):
        Declaration(expected_version=0,shares=[{**a,"basis_points":1.5}])

def test_rights_routes():
    client=TestClient(app)
    assert client.get(f"/api/v1/works/{uuid4()}/rights").status_code==401
    assert 'id="rights-workspace" hidden' in client.get("/portal").text
