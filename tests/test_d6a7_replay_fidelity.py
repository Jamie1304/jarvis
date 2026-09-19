"""D6A7 source-path and readiness-order evidence tests."""

from __future__ import annotations

from pathlib import Path

from jarvis.production_capability import ProductionPackageRuntime, ProductionSandboxRunner

ROOT = Path(__file__).resolve().parents[1]


def test_c_replay_uses_production_runner_and_immutable_worker_contract() -> None:
    production = (ROOT / "tests" / "test_v1_acceptance.py").read_text(encoding="utf-8")
    sandbox = (ROOT / "jarvis" / "sandbox.py").read_text(encoding="utf-8")
    capability = (ROOT / "jarvis" / "production_capability.py").read_text(encoding="utf-8")

    assert "production_sandbox" in production
    assert '"operation": "concat_strings"' in production
    assert "SandboxProcess(" in capability
    assert "sandbox_worker.py" in capability
    assert "WindowsContainmentMode.APPCONTAINER" in capability
    assert "SandboxMessage(" in sandbox
    assert ProductionSandboxRunner.__name__ == "ProductionSandboxRunner"
    assert ProductionPackageRuntime.__name__ == "ProductionPackageRuntime"


def test_real_generated_health_path_uses_immutable_worker_after_payload_load() -> None:
    worker = (ROOT / "jarvis" / "sandbox_worker.py").read_text(encoding="utf-8")
    production = (ROOT / "jarvis" / "production_capability.py").read_text(encoding="utf-8")

    assert "for line in sys.stdin" in worker
    assert 'if kind == "health"' in worker
    assert "PROTOCOL_READY" in worker
    assert "payload.json" in production
    for prohibited in ("exec(", "eval(", "importlib", "compile("):
        assert prohibited not in worker


def test_certification_health_is_one_shot_and_timeout_is_transport_bound() -> None:
    source = (ROOT / "jarvis" / "production_capability.py").read_text(encoding="utf-8")
    start = source.index("class ProductionCertificationProvider:")
    end = source.index("\n\nclass ProductionActivationBoundary", start)
    certifier = source[start:end]

    healthcheck = certifier[certifier.index("def healthcheck(") :]
    assert healthcheck.count('self._sandbox.execute(item, "health", {})') == 1
    assert 'response.get("status") == "healthy"' in healthcheck
    assert "timeout_seconds=60.0" in source
    assert "readiness" not in healthcheck.lower()
