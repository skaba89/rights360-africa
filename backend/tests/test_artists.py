import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from app.artists import ArtistData
from app.main import app

def test_artist_validation():
    assert ArtistData(member_number="abc-1",legal_name=" Example ").member_number=="ABC-1"
    with pytest.raises(ValidationError):
        ArtistData(member_number="abc",legal_name=" ")
    with pytest.raises(ValidationError):
        ArtistData(member_number="abc",legal_name="Example",organization_id="injected")
    with pytest.raises(ValidationError):
        ArtistData(member_number="abc",legal_name="Example",status="invalid")

def test_artist_routes_and_portal():
    client=TestClient(app)
    assert client.get("/api/v1/artists").status_code==401
    assert 'id="artist-workspace" hidden' in client.get("/portal").text
    assert "/api/v1/artists" in client.get("/portal.js").text
