from uuid import uuid4
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from app.billing import InvoiceData,ReceiptData,serialize
from app.main import app

def test_billing_validation():
    data={"reference":"inv-1","license_id":uuid4(),"tariff_id":uuid4(),"usage_date":"2026-01-01","due_on":"2026-02-01"}
    assert InvoiceData(**data).reference=="INV-1"
    with pytest.raises(ValidationError):
        InvoiceData(**data,amount_minor=100)
    with pytest.raises(ValidationError):
        ReceiptData(reference="p-1",amount_minor=0,received_on="2026-01-01")
    assert serialize({"amount_minor":10**18})["amount_minor"]==str(10**18)

def test_billing_routes():
    client=TestClient(app)
    assert client.get("/api/v1/invoices").status_code==401
    assert 'id="billing-workspace" hidden' in client.get("/portal").text
