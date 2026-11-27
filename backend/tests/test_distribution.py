from uuid import uuid4
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app.distribution import allocate
from app.main import app

def test_largest_remainder():
    shares=[{"artist_id":uuid4(),"role":"author","basis_points":3333},{"artist_id":uuid4(),"role":"composer","basis_points":3333},{"artist_id":uuid4(),"role":"publisher","basis_points":3334}]
    for gross in (1,2,101,10**18):
        commission,net,lines=allocate(gross,1000,shares)
        assert commission+net==gross
        assert sum(s["amount_minor"] for s in lines)==net
        assert all(s["amount_minor"]>=0 for s in lines)
        assert allocate(gross,1000,list(reversed(shares)))==(commission,net,lines)
    with pytest.raises(HTTPException):
        allocate(100,0,shares[:1])

def test_distribution_routes():
    client=TestClient(app)
    assert client.get("/api/v1/distributions").status_code==401
    assert 'id="distribution-workspace" hidden' in client.get("/portal").text
