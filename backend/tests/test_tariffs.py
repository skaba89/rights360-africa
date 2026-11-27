from uuid import uuid4
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
from app.tariffs import TariffData, QuoteData, calculate
from app.main import app

def test_calculations():
    base={"license_id":uuid4(),"usage_date":"2026-01-01"}
    assert calculate("flat",100,QuoteData(**base))==100
    assert calculate("capacity",200,QuoteData(**base,quantity=5))==1000
    assert calculate("frequency",300,QuoteData(**base,quantity=7))==2100
    assert calculate("revenue",500,QuoteData(**base,revenue_minor=1000000))==50000
    assert calculate("revenue",5000,QuoteData(**base,revenue_minor=1))==1
    with pytest.raises(HTTPException):
        calculate("flat",100,QuoteData(**base,quantity=1))
    with pytest.raises(ValidationError):
        QuoteData(**base,quantity=1.2)

def test_tariff_validation_and_routes():
    data={"reference":"rate-1","expected_version":0,"category":"radio","usage_type":"broadcast","method":"revenue","currency":"GNF","rate":500,"starts_on":"2026-01-01","ends_on":"2026-12-31"}
    assert TariffData(**data).reference=="RATE-1"
    with pytest.raises(ValidationError):
        TariffData(**{**data,"rate":10001})
    client=TestClient(app)
    assert client.get("/api/v1/tariffs").status_code==401
    assert 'id="tariff-workspace" hidden' in client.get("/portal").text
