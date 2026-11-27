from uuid import uuid4
from fastapi.testclient import TestClient
from app.accounting import build_lines
from app.main import app

def test_double_entry():
    artist=uuid4()
    for kind,source,shares in [
        ("invoice",{"amount_minor":100},[]),
        ("receipt",{"amount_minor":100},[]),
        ("distribution",{"gross_minor":100,"commission_minor":15},[{"artist_id":artist,"amount_minor":85}]),
    ]:
        rows=build_lines(kind,source,shares)
        assert sum(r["debit_minor"] for r in rows)==sum(r["credit_minor"] for r in rows)==100
        assert all((r["debit_minor"]>0) != (r["credit_minor"]>0) for r in rows)
    assert build_lines("distribution",{"gross_minor":100,"commission_minor":0},[{"artist_id":artist,"amount_minor":100}])[1]["artist_id"]==artist

def test_accounting_routes():
    client=TestClient(app)
    assert client.get("/api/v1/accounting/entries").status_code==401
    assert client.get("/api/v1/accounting/balances").status_code==401
    assert 'id="accounting-workspace" hidden' in client.get("/portal").text
