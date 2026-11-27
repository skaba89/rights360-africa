from fastapi.testclient import TestClient
from app.main import app

def test_home():
    response = TestClient(app).get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Rights360 Africa" in response.text
    assert "À développer" in response.text
