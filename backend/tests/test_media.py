from uuid import uuid4
from datetime import datetime,timezone
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from app.media import Observation,Review
from app.main import app

def test_observation_validation():
    data={"operator_id":uuid4(),"external_reference":"test","aired_at":datetime.now(timezone.utc),"duration_seconds":180,"reported_title":"Title","reported_artist":"Artist"}
    assert Observation(**data).duration_seconds==180
    for extra in ({"duration_seconds":0},{"fingerprint_sha256":"invalid"},{"organization_id":uuid4()}):
        with pytest.raises(ValidationError):
            Observation(**{**data,**extra})
    with pytest.raises(ValidationError):
        Review(decision="matched")
    with pytest.raises(ValidationError):
        Review(decision="unmatched",work_id=uuid4())

def test_media_routes():
    client=TestClient(app)
    assert client.get("/api/v1/media-observations").status_code==401
    assert 'id="media-workspace" hidden' in client.get("/portal").text
