from uuid import uuid4
from datetime import datetime,timezone,timedelta
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from app.field_control import Visit
from app.main import app

def test_visit_validation():
    data={"id":uuid4(),"operator_id":uuid4(),"visited_at":datetime.now(timezone.utc),"finding":"observed","notes":"Test"}
    assert Visit(**data).latitude_e6 is None
    assert Visit(**data,latitude_e6=0,longitude_e6=0).longitude_e6==0
    for extra in ({"latitude_e6":0},{"latitude_e6":90000001,"longitude_e6":0},{"visited_at":datetime.now(timezone.utc)+timedelta(hours=1)},{"agent_id":uuid4()}):
        with pytest.raises(ValidationError):
            Visit(**{**data,**extra})

def test_routes():
    client=TestClient(app)
    assert client.get("/api/v1/field-visits").status_code==401
    assert client.get("/api/v1/field-visits/operators").status_code==401
    assert 'id="field-workspace" hidden' in client.get("/portal").text
