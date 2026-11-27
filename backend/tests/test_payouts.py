from uuid import uuid4
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from app.payouts import Order,state
from app.main import app

def test_review_states():
    assert state([])=="pending"
    assert state([{"decision":"approve"}])=="pending"
    assert state([{"decision":"approve"},{"decision":"approve"}])=="approved_for_review_only"
    assert state([{"decision":"reject"}])=="rejected"
    with pytest.raises(ValidationError):
        Order(distribution_id=uuid4(),artist_id=uuid4(),channel="bank",amount_minor=100)

def test_routes():
    client=TestClient(app)
    assert client.get("/api/v1/payouts").status_code==401
    assert 'id="payout-workspace" hidden' in client.get("/portal").text
