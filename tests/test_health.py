from fastapi.testclient import TestClient
from jarvis.api import app


def test_health_reports_startup_and_version() -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "version": "0.1.0",
        "startup_complete": True,
    }


def test_version_endpoint() -> None:
    with TestClient(app) as client:
        response = client.get("/version")

    assert response.json() == {"version": "0.1.0"}
