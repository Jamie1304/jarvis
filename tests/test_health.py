from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jarvis.api import create_app
from jarvis.core.config import Settings, get_settings
from jarvis.core.health import HealthService
from jarvis.runtime import ApplicationRuntime, RuntimeStatus


def test_health_reports_canonical_runtime_readiness(tmp_path: Path) -> None:
    app = create_app(Settings(app_data_dir=tmp_path / "data", _env_file=None))
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "version": "0.1.0",
        "startup_complete": True,
    }


def test_version_endpoint(tmp_path: Path) -> None:
    app = create_app(Settings(app_data_dir=tmp_path / "data", _env_file=None))
    with TestClient(app) as client:
        response = client.get("/version")

    assert response.json() == {"version": "0.1.0"}


def test_health_reports_safe_mode_for_rejected_security_configuration(tmp_path: Path) -> None:
    app_data = tmp_path / "must-not-exist"
    app = create_app(
        Settings(
            app_data_dir=app_data,
            remote_approval_enabled=True,
            _env_file=None,
        )
    )

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["status"] == "safe_mode"
    assert response.json()["startup_complete"] is False
    assert not app_data.exists()


def test_malformed_environment_is_redacted_as_safe_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JARVIS_PORT", "not-an-integer")
    get_settings.cache_clear()
    try:
        app = create_app()
        with TestClient(app) as client:
            response = client.get("/health")
        assert response.status_code == 503
        assert response.json() == {
            "status": "safe_mode",
            "version": "0.1.0",
            "startup_complete": False,
        }
    finally:
        get_settings.cache_clear()


def test_runtime_records_machine_readable_malformed_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("JARVIS_PORT", "not-an-integer")
    get_settings.cache_clear()
    try:
        runtime = ApplicationRuntime.create_from_environment()
        assert runtime.status is RuntimeStatus.SAFE_MODE
        assert runtime.container is None
        assert runtime.security_report is not None
        assert runtime.security_report.violations[0].code.value == "configuration_invalid"
    finally:
        get_settings.cache_clear()


def test_health_service_rejects_unknown_unavailable_status() -> None:
    service = HealthService("1.0")

    with pytest.raises(ValueError, match="error or safe_mode"):
        service.mark_unavailable("healthy-enough")

    assert service.status().status == "starting"
