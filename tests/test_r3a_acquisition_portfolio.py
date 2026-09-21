"""R3A acquisition and model-portfolio qualification through trusted seams."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

import httpx
import pytest
from jarvis.acquisition import (
    AcquisitionApprovalRequired,
    AcquisitionArtifactRecord,
    AcquisitionBroker,
    AcquisitionDeferred,
    AcquisitionDenied,
    AcquisitionEffectOutcome,
    AcquisitionIntegrityEvidence,
    AcquisitionPhase,
    AcquisitionPolicy,
    AcquisitionPolicyMode,
    AcquisitionRequest,
    AcquisitionResultStatus,
    AcquisitionRisk,
    AcquisitionStaleRequest,
    AcquisitionTransportError,
    AcquisitionUnknownOutcome,
    AcquisitionValidationError,
    ArtifactState,
    BoundedDownloadTransport,
    BrokerAcquisitionAuthorizer,
    DisposableQualificationResult,
    DownloadEvidence,
    InMemoryAcquisitionLedger,
    NoSecurityDispositionProvider,
    PrivacyImpact,
    ProvenanceMetadata,
    ResourceType,
    SecurityDisposition,
    SecurityDispositionResult,
    SQLiteAcquisitionLedger,
    UnknownExecutablePolicy,
    build_acquisition_presentation,
)
from jarvis.ai.knowledge import (
    CookbookObservation,
    CookbookOutcome,
    CookbookSummary,
    ModelIdentity,
    ModelKnowledgeService,
    ModelKnowledgeStore,
    ModelMeasurementView,
    VerifierAgreement,
    identity_for,
)
from jarvis.ai.model_manager import (
    LocalModelManager,
    LocalModelRecord,
    LocalModelSpec,
    ModelArtifact,
    ModelHealth,
    ModelLifecycleState,
    ModelRemovalUnknownOutcome,
)
from jarvis.ai.models import ModelRole
from jarvis.ai.portfolio import (
    BrokerModelRemovalAuthorizer,
    DominanceAnalysis,
    DominanceClassification,
    InMemoryRetirementStore,
    InsufficientPortfolioEvidence,
    ModelPortfolioEvidence,
    ModelPortfolioOptimizer,
    ModelUsabilityEvidence,
    ModelUsabilityStatus,
    PortfolioError,
    RemovalEffectOutcome,
    RemovalUnknownOutcome,
    RemovalVerification,
    RetirementPlan,
    RetirementProtection,
    RetirementState,
    SQLiteRetirementStore,
    StaleRetirementPlan,
)
from jarvis.ai.providers.ollama_runtime import OllamaModelAdapter, OllamaRuntimeManager
from jarvis.ai.providers.registry import (
    ModelMetadata,
    ProviderDefinition,
    ProviderLocality,
    ProviderMetadata,
    ProviderRegistry,
)
from jarvis.core.errors import ProviderError
from jarvis.hardware import ModelMeasurement
from jarvis.permissions import (
    AuthorizationReceipt,
    Decision,
    Permission,
    PermissionBroker,
    PolicyEngine,
    PolicyRule,
    ScopeConstraint,
)
from jarvis.resources import (
    ResourceGovernor,
    ResourcePolicy,
    ResourceSnapshot,
)

from tests.fakes import FakeAIProvider

PAYLOAD = b"R3A acceptance-owned safe resource\n"
PAYLOAD_HASH = hashlib.sha256(PAYLOAD).hexdigest()


class _PayloadHandler(BaseHTTPRequestHandler):
    payload = PAYLOAD
    partial = False
    include_content_length = True
    status_code = 200
    redirect_location: str | None = None

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/resource.bin":
            self.send_response(404)
            self.end_headers()
            return
        if self.redirect_location is not None:
            self.send_response(302)
            self.send_header("Location", self.redirect_location)
            self.end_headers()
            return
        body = self.payload
        self.send_response(self.status_code)
        if self.include_content_length:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.status_code != 200:
            return
        self.wfile.write(body[: max(1, len(body) // 2)] if self.partial else body)
        self.wfile.flush()
        if self.partial:
            self.close_connection = True

    def log_message(self, _format: str, *_args: object) -> None:
        return None


class _TrustedScan:
    async def assess(
        self, _request: AcquisitionRequest, _materialized: Path
    ) -> SecurityDispositionResult:
        return SecurityDispositionResult(
            SecurityDisposition.PASSED_BY_TRUSTED_PROVIDER,
            "acceptance-owned trusted scan disposition",
            "acceptance.scan",
        )


class _Qualification:
    def __init__(self, passed: bool) -> None:
        self.passed = passed

    async def qualify(
        self, _request: AcquisitionRequest, _materialized: Path
    ) -> DisposableQualificationResult:
        return DisposableQualificationResult(
            self.passed,
            "disposable qualification passed" if self.passed else "disposable qualification failed",
            "acceptance-vm",
        )


class _FailingSecurity:
    async def assess(
        self, _request: AcquisitionRequest, _materialized: Path
    ) -> SecurityDispositionResult:
        raise RuntimeError("security provider stopped")


class _FailingQualification:
    async def qualify(
        self, _request: AcquisitionRequest, _materialized: Path
    ) -> DisposableQualificationResult:
        raise RuntimeError("qualification provider stopped")


class _PendingSecurity:
    async def assess(
        self, _request: AcquisitionRequest, _materialized: Path
    ) -> SecurityDispositionResult:
        return SecurityDispositionResult(
            SecurityDisposition.REQUIRED_PENDING,
            "security disposition remains pending",
            "acceptance.pending-security",
        )


class _AcquisitionAuthority:
    async def authorize(
        self,
        _request: AcquisitionRequest,
        _phase: AcquisitionPhase,
        *,
        task_id: UUID,
        user_id: str | None,
    ) -> object:
        del task_id, user_id
        return object()

    async def begin(self, _receipt: object) -> None:
        return None

    async def finish(self, _receipt: object, _outcome: object) -> None:
        return None


class _FixedTelemetry:
    def __init__(self, snapshot: ResourceSnapshot) -> None:
        self._snapshot = snapshot

    def snapshot(self) -> ResourceSnapshot:
        return self._snapshot


@contextmanager
def _resource_server(
    *,
    payload: bytes = PAYLOAD,
    partial: bool = False,
    include_content_length: bool = True,
    status_code: int = 200,
    redirect_location: str | None = None,
) -> Iterator[tuple[ThreadingHTTPServer, str]]:
    handler = type(
        "R3AHandler",
        (_PayloadHandler,),
        {
            "payload": payload,
            "partial": partial,
            "include_content_length": include_content_length,
            "status_code": status_code,
            "redirect_location": redirect_location,
        },
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}/resource.bin"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(
    source: str | None,
    *,
    resource_type: ResourceType = ResourceType.DATA,
    expected_hash: str | None = PAYLOAD_HASH,
    size: int | None = len(PAYLOAD),
    target: str | None = "resources/acceptance.bin",
    risk: AcquisitionRisk = AcquisitionRisk.LOW,
    jarvis_owned: bool = True,
    provenance: ProvenanceMetadata | None = None,
    expires_at: datetime | None = None,
) -> AcquisitionRequest:
    request_created_at = (
        expires_at - timedelta(seconds=2) if expires_at is not None else datetime.now(UTC)
    )
    return AcquisitionRequest(
        resource_id="acceptance.resource",
        resource_type=resource_type,
        purpose="provide an acceptance-owned consumer resource",
        required_for="R3A acquisition acceptance",
        expected_benefit="consumer can read the materialized bytes",
        requested_version="1",
        source=source,
        publisher=None,
        provenance=provenance or ProvenanceMetadata(source_identity=source, trusted_source=True),
        download_size_bytes=size,
        installed_size_bytes=size,
        target_location=target,
        license_metadata=None,
        purchase_cost=None,
        network_required=True,
        administrator_required=False,
        restart_required=False,
        security_risk=risk,
        privacy_impact=PrivacyImpact.LOCAL_ONLY,
        alternatives=("defer until resource is available",),
        verification_plan="consumer reads the downloaded file and expected SHA-256 matches",
        rollback_plan="remove only the acceptance-owned materialized file",
        expected_sha256=expected_hash,
        jarvis_owned=jarvis_owned,
        created_at=request_created_at,
        expires_at=expires_at,
    )


@pytest.mark.asyncio
async def test_real_bounded_acquisition_materializes_and_consumes_bytes(tmp_path: Path) -> None:
    with _resource_server() as (_server, source):
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "downloads"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=True,
            ),
            InMemoryAcquisitionLedger(),
        )
        consumed: list[bytes] = []

        def consume(path: Path) -> str:
            consumed.append(path.read_bytes())
            return "consumer-pass"

        request = _request(source)
        result = await broker.acquire(
            request,
            disk_free_bytes=10_000,
            consumer=consume,
        )
        assert result.status is AcquisitionResultStatus.REGISTERED
        assert result.integrity is not None and result.integrity.verified is True
        assert result.materialized_path is not None and result.materialized_path.is_file()
        assert consumed == [PAYLOAD]
        duplicate = await broker.acquire(request, disk_free_bytes=10_000)
        assert duplicate.status is AcquisitionResultStatus.DUPLICATE
        assert result.artifact.state is ArtifactState.REGISTERED
        await broker.aclose()


@pytest.mark.asyncio
async def test_acquisition_integrity_size_traversal_partial_and_unknown_hash_fail_closed(
    tmp_path: Path,
) -> None:
    with _resource_server() as (_server, source):
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "downloads"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
        )
        with pytest.raises(AcquisitionTransportError, match="hash"):
            await broker.acquire(_request(source, expected_hash="0" * 64), disk_free_bytes=10_000)
        with pytest.raises(AcquisitionTransportError, match="size"):
            await broker.acquire(_request(source, size=1), disk_free_bytes=10_000)
        with pytest.raises(AcquisitionTransportError, match="escapes"):
            await broker.acquire(_request(source, target="../escape.bin"), disk_free_bytes=10_000)
        unresolved = await broker.acquire(
            _request(source, expected_hash=None), disk_free_bytes=10_000
        )
        assert unresolved.status is AcquisitionResultStatus.VERIFICATION_REQUIRED
        assert unresolved.artifact.state is ArtifactState.VERIFICATION_REQUIRED
        consumer_failure = _request(source, target="resources/consumer-failure.bin")
        with pytest.raises(AcquisitionUnknownOutcome):
            await broker.acquire(
                consumer_failure,
                disk_free_bytes=10_000,
                consumer=lambda _path: (_ for _ in ()).throw(RuntimeError("consumer stopped")),
            )
        with pytest.raises(AcquisitionUnknownOutcome, match="reconciliation"):
            await broker.acquire(consumer_failure, disk_free_bytes=10_000)
        reconciled = await broker.reconcile(consumer_failure)
        assert reconciled.status is AcquisitionResultStatus.REGISTERED
        assert reconciled.artifact.state is ArtifactState.REGISTERED
        duplicate_after_reconcile = await broker.acquire(consumer_failure, disk_free_bytes=10_000)
        assert duplicate_after_reconcile.status is AcquisitionResultStatus.DUPLICATE
        await broker.aclose()

    with _resource_server(partial=True) as (_server, source):
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "partial"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
        )
        with pytest.raises(AcquisitionTransportError):
            await broker.acquire(_request(source), disk_free_bytes=10_000)
        assert not tuple((tmp_path / "partial" / ".staging").glob("*.part"))
        await broker.aclose()


def test_acquisition_policy_is_scope_specific_and_projection_is_truthful() -> None:
    unknown = AcquisitionRequest(
        "model.unknown",
        ResourceType.MODEL,
        "provide a local model",
        source=None,
        target_location=None,
        provenance=ProvenanceMetadata(provider_reported_digest="opaque-provider-digest"),
    )
    presentation = build_acquisition_presentation(unknown)
    assert "UNKNOWN" in presentation.resources
    assert "UNKNOWN" in presentation.source
    assert presentation.request_fingerprint == unknown.fingerprint

    trusted = _request("https://models.example.test/resource.bin")
    assert (
        AcquisitionPolicy(AcquisitionPolicyMode.OFF)
        .decide(trusted, phase=AcquisitionPhase.DOWNLOAD)
        .status.value
        == "deny"
    )
    low_risk = AcquisitionPolicy(
        AcquisitionPolicyMode.LOW_RISK_ONLY,
        maximum_automatic_download_bytes=100,
    )
    assert (
        low_risk.decide(
            trusted,
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=1000,
        ).status.value
        == "allow"
    )
    assert (
        low_risk.decide(
            _request(
                "https://models.example.test/resource.bin",
                provenance=ProvenanceMetadata(trusted_source=False),
            ),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=1000,
        ).status.value
        == "deny"
    )
    assert (
        low_risk.decide(trusted, AcquisitionPhase.DOWNLOAD, disk_free_bytes=None).status.value
        == "defer_unknown"
    )
    phase_policy = AcquisitionPolicy(
        AcquisitionPolicyMode.WITHIN_LIMITS,
        allow_automatic_install=True,
        require_known_disk_capacity=False,
    )
    assert (
        phase_policy.decide(trusted, AcquisitionPhase.INSTALL, disk_free_bytes=1000).status.value
        == "allow"
    )
    assert (
        phase_policy.decide(trusted, AcquisitionPhase.EXECUTE, disk_free_bytes=1000).status.value
        == "require_approval"
    )
    assert (
        phase_policy.decide(
            trusted, AcquisitionPhase.GRANT_PRIVILEGES, disk_free_bytes=1000
        ).status.value
        == "require_approval"
    )
    assert (
        phase_policy.decide(
            replace(trusted, administrator_required=True),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=1000,
        ).status.value
        == "deny"
    )
    assert (
        phase_policy.decide(
            replace(trusted, purchase_cost=1.0),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=1000,
        ).status.value
        == "require_approval"
    )
    admin_policy = replace(
        phase_policy,
        administrator_installation_allowed=True,
        paid_resource_requires_approval=False,
        model_acquisition_limit_bytes=10,
    )
    assert (
        admin_policy.decide(
            replace(trusted, administrator_required=True),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=1000,
        ).status.value
        == "require_approval"
    )
    assert (
        admin_policy.decide(
            replace(trusted, purchase_cost=1.0),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=1000,
        ).status.value
        == "allow"
    )
    assert (
        admin_policy.decide(
            replace(
                trusted, resource_type=ResourceType.MODEL, source=None, download_size_bytes=None
            ),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=1000,
        ).status.value
        == "defer_unknown"
    )
    assert (
        admin_policy.decide(
            replace(trusted, resource_type=ResourceType.MODEL, source=None, download_size_bytes=11),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=1000,
        ).status.value
        == "deny"
    )


@pytest.mark.asyncio
async def test_acquisition_contracts_and_transport_boundaries_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(AcquisitionValidationError, match="requires a source"):
        AcquisitionRequest("missing-source", ResourceType.DATA, "bounded test resource")
    with pytest.raises(AcquisitionValidationError, match="SHA-256"):
        _request("https://models.example.test/resource.bin", expected_hash="not-a-hash")
    with pytest.raises(AcquisitionValidationError, match="timezone-aware"):
        AcquisitionRequest(
            "naive-time",
            ResourceType.DATA,
            "bounded test resource",
            source="https://models.example.test/resource.bin",
            created_at=datetime.now(),
        )
    with pytest.raises(AcquisitionValidationError, match="after creation"):
        now = datetime.now(UTC)
        AcquisitionRequest(
            "expired-contract",
            ResourceType.DATA,
            "bounded test resource",
            source="https://models.example.test/resource.bin",
            created_at=now,
            expires_at=now,
        )
    with pytest.raises(AcquisitionValidationError, match="Maximum download size"):
        AcquisitionPolicy(maximum_automatic_download_bytes=-1)
    with pytest.raises(AcquisitionValidationError, match="Artifact update"):
        AcquisitionArtifactRecord(
            "a" * 64,
            "acceptance.resource",
            ArtifactState.FAILED,
            None,
            None,
            None,
            "retained failure",
            datetime.now(UTC),
            datetime.now(UTC) - timedelta(seconds=1),
        )
    with pytest.raises(AcquisitionValidationError, match="Integrity byte count"):
        AcquisitionIntegrityEvidence("a" * 64, "a" * 64, -1)

    transport = BoundedDownloadTransport(tmp_path / "transport")
    with pytest.raises(AcquisitionTransportError, match="HTTP"):
        await transport.download("ftp://models.example.test/resource.bin", "safe.bin")
    with pytest.raises(AcquisitionValidationError, match="destination"):
        await transport.download("https://models.example.test/resource.bin", "")
    with pytest.raises(AcquisitionTransportError, match="escapes"):
        await transport.download("https://models.example.test/resource.bin", "../escape.bin")


def test_acquisition_validation_matrix_and_policy_limits_are_explicit() -> None:
    trusted = _request("https://models.example.test/resource.bin")
    invalid_cases: tuple[Callable[[], AcquisitionRequest], ...] = (
        lambda: replace(trusted, resource_type=cast(ResourceType, object())),
        lambda: replace(trusted, provenance=cast(ProvenanceMetadata, object())),
        lambda: replace(trusted, download_size_bytes=-1),
        lambda: replace(trusted, installed_size_bytes=-1),
        lambda: replace(trusted, purchase_cost=-1),
        lambda: replace(trusted, network_required=cast(bool | None, 1)),
        lambda: replace(trusted, jarvis_owned=cast(bool, 1)),
        lambda: replace(trusted, security_risk=cast(AcquisitionRisk, object())),
        lambda: replace(trusted, alternatives=cast(tuple[str, ...], ["not-a-tuple"])),
    )
    for invalid in invalid_cases:
        with pytest.raises(AcquisitionValidationError):
            invalid()
    with pytest.raises(AcquisitionValidationError, match="policy enum"):
        AcquisitionPolicy(mode=cast(AcquisitionPolicyMode, object()))
    with pytest.raises(AcquisitionValidationError, match="policy"):
        AcquisitionPolicy(trusted_sources_only=cast(bool, 1))
    policy = AcquisitionPolicy(
        AcquisitionPolicyMode.WITHIN_LIMITS,
        maximum_automatic_download_bytes=10,
        model_acquisition_limit_bytes=10,
        require_known_disk_capacity=True,
        unknown_executable_policy=UnknownExecutablePolicy.REQUIRE_TRUSTED_SCAN,
    )
    with pytest.raises(AcquisitionValidationError, match="Policy request"):
        policy.decide(cast(AcquisitionRequest, object()), AcquisitionPhase.DOWNLOAD)
    with pytest.raises(AcquisitionValidationError, match="Policy request"):
        policy.decide(trusted, cast(AcquisitionPhase, object()))
    assert (
        policy.decide(
            replace(trusted, download_size_bytes=None), AcquisitionPhase.DOWNLOAD
        ).status.value
        == "defer_unknown"
    )
    assert (
        policy.decide(trusted, AcquisitionPhase.DOWNLOAD, disk_free_bytes=1).status.value == "deny"
    )
    assert (
        policy.decide(
            replace(trusted, download_size_bytes=11),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=100,
        ).status.value
        == "deny"
    )
    assert (
        policy.decide(
            replace(
                trusted, resource_type=ResourceType.MODEL, source=None, download_size_bytes=None
            ),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=100,
        ).status.value
        == "defer_unknown"
    )
    assert (
        policy.decide(
            replace(trusted, resource_type=ResourceType.DRIVER),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=100,
        ).status.value
        == "require_approval"
    )
    assert (
        policy.decide(
            replace(trusted, resource_type=ResourceType.EXECUTABLE, download_size_bytes=1),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=100,
        ).status.value
        == "require_approval"
    )
    low_risk_policy = AcquisitionPolicy(
        AcquisitionPolicyMode.LOW_RISK_ONLY,
        maximum_automatic_download_bytes=100,
    )
    assert (
        low_risk_policy.decide(
            replace(trusted, security_risk=AcquisitionRisk.HIGH, download_size_bytes=1),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=100,
        ).status.value
        == "require_approval"
    )
    managed = replace(trusted, jarvis_owned=False)
    assert (
        AcquisitionPolicy(
            AcquisitionPolicyMode.JARVIS_MANAGED,
            require_known_disk_capacity=False,
        )
        .decide(managed, AcquisitionPhase.DOWNLOAD, disk_free_bytes=100)
        .status.value
        == "require_approval"
    )


def test_acquisition_policy_and_value_boundaries_are_fail_closed(tmp_path: Path) -> None:
    request = _request("https://models.example.test/resource.bin", size=1)
    created = datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=2)))
    normalized = replace(
        request,
        created_at=created,
        expires_at=created + timedelta(hours=1),
    )
    assert normalized.created_at == created
    assert normalized.expires_at == created + timedelta(hours=1)

    policy = AcquisitionPolicy(
        AcquisitionPolicyMode.WITHIN_LIMITS,
        maximum_automatic_download_bytes=10,
        model_acquisition_limit_bytes=10,
        require_known_disk_capacity=True,
        unknown_executable_policy=UnknownExecutablePolicy.REQUIRE_TRUSTED_SCAN,
    )
    for phase in (
        AcquisitionPhase.INSTALL,
        AcquisitionPhase.EXECUTE,
        AcquisitionPhase.GRANT_PRIVILEGES,
    ):
        assert policy.decide(request, phase, disk_free_bytes=10).status.value == (
            "require_approval"
        )
    assert (
        AcquisitionPolicy(AcquisitionPolicyMode.OFF, require_known_disk_capacity=False)
        .decide(request, AcquisitionPhase.DOWNLOAD)
        .status.value
        == "deny"
    )
    admin = replace(request, administrator_required=True)
    assert (
        policy.decide(admin, AcquisitionPhase.DOWNLOAD, disk_free_bytes=10).status.value == "deny"
    )
    admin_policy = replace(policy, administrator_installation_allowed=True)
    assert (
        admin_policy.decide(admin, AcquisitionPhase.DOWNLOAD, disk_free_bytes=10).status.value
        == "require_approval"
    )
    paid = replace(request, purchase_cost=1.0)
    assert policy.decide(paid, AcquisitionPhase.DOWNLOAD, disk_free_bytes=10).status.value == (
        "require_approval"
    )
    untrusted = replace(
        request,
        provenance=ProvenanceMetadata(
            source_identity=request.source,
            trusted_source=False,
        ),
    )
    assert policy.decide(untrusted, AcquisitionPhase.DOWNLOAD, disk_free_bytes=10).status.value == (
        "deny"
    )
    unknown_source = replace(
        request,
        provenance=ProvenanceMetadata(source_identity=request.source),
    )
    assert (
        policy.decide(unknown_source, AcquisitionPhase.DOWNLOAD, disk_free_bytes=10).status.value
        == "defer_unknown"
    )
    model_policy = replace(policy, maximum_automatic_download_bytes=None)
    model = replace(
        request,
        resource_type=ResourceType.MODEL,
        source=None,
        download_size_bytes=11,
    )
    assert (
        model_policy.decide(model, AcquisitionPhase.DOWNLOAD, disk_free_bytes=100).status.value
        == "deny"
    )
    assert policy.decide(request, AcquisitionPhase.DOWNLOAD).status.value == "defer_unknown"

    presentation = build_acquisition_presentation(
        admin, policy.decide(admin, AcquisitionPhase.DOWNLOAD)
    )
    assert "administrator authority required" in presentation.authority
    assert build_acquisition_presentation(request).authority == "policy decision pending"
    with pytest.raises(AcquisitionValidationError, match="Presentation request"):
        build_acquisition_presentation(cast(AcquisitionRequest, object()))
    with pytest.raises(AcquisitionValidationError, match="Download root"):
        BoundedDownloadTransport(cast(Path, object()))
    with pytest.raises(AcquisitionValidationError, match="timeout"):
        BoundedDownloadTransport(tmp_path / "timeout", timeout_seconds=0)
    with pytest.raises(AcquisitionValidationError, match="Download evidence"):
        DownloadEvidence(
            "https://models.example.test/resource.bin",
            cast(Path, object()),
            0,
            "a" * 64,
            None,
            None,
            None,
        )
    with pytest.raises(AcquisitionValidationError, match="reuse"):
        DownloadEvidence(
            "https://models.example.test/resource.bin",
            tmp_path / "x",
            0,
            "a" * 64,
            None,
            None,
            None,
            cast(bool, 1),
        )
    with pytest.raises(AcquisitionValidationError, match="Artifact state"):
        AcquisitionArtifactRecord(
            "a" * 64,
            "resource",
            cast(ArtifactState, object()),
            None,
            None,
            None,
            "invalid",
            created,
            created,
        )
    assert AcquisitionIntegrityEvidence(None, None, None).verified is None


@pytest.mark.asyncio
async def test_bounded_transport_reuse_http_errors_and_unmeasured_length(tmp_path: Path) -> None:
    with _resource_server() as (_server, source):
        transport = BoundedDownloadTransport(tmp_path / "reuse")
        first = await transport.download(source, "reuse.bin", expected_sha256=PAYLOAD_HASH)
        second = await transport.download(source, "reuse.bin", expected_sha256=PAYLOAD_HASH)
        assert isinstance(first, DownloadEvidence)
        assert second.reused_existing is True
        (transport.root / "existing-directory").mkdir()
        with pytest.raises(AcquisitionTransportError, match="regular file"):
            await transport.download(source, "existing-directory")
        (transport.root / "unsafe-parent").write_text("not a directory", encoding="utf-8")
        with pytest.raises(AcquisitionTransportError):
            transport._validate_directory_chain(transport.root / "unsafe-parent")  # noqa: SLF001

    with _resource_server(include_content_length=False) as (_server, source):
        transport = BoundedDownloadTransport(tmp_path / "unmeasured")
        with pytest.raises(AcquisitionTransportError, match="size limit"):
            await transport.download(source, "too-large.bin", maximum_bytes=1)

    with _resource_server(status_code=500) as (_server, source):
        with pytest.raises(AcquisitionTransportError, match="HTTP"):
            await BoundedDownloadTransport(tmp_path / "http-error").download(source, "error.bin")

    with _resource_server(redirect_location="https://models.example.test/other") as (
        _server,
        source,
    ):
        with pytest.raises(AcquisitionTransportError, match="HTTP"):
            await BoundedDownloadTransport(tmp_path / "redirect").download(source, "redirect.bin")


@pytest.mark.asyncio
async def test_security_and_qualification_contracts_remain_conservative(
    tmp_path: Path,
) -> None:
    provider = NoSecurityDispositionProvider()
    data = await provider.assess(_request("https://models.example.test/resource.bin"), tmp_path)
    executable = await provider.assess(
        _request(
            "https://models.example.test/resource.bin",
            resource_type=ResourceType.EXECUTABLE,
        ),
        tmp_path,
    )
    assert data.disposition is SecurityDisposition.NOT_REQUIRED_BY_POLICY
    assert executable.disposition is SecurityDisposition.REQUIRED_PENDING
    with pytest.raises(AcquisitionValidationError, match="Security disposition"):
        SecurityDispositionResult(cast(SecurityDisposition, object()), "malformed")
    with pytest.raises(AcquisitionValidationError, match="Qualification result"):
        DisposableQualificationResult(cast(bool, 1), "malformed")
    with pytest.raises(AcquisitionValidationError, match="Qualification detail"):
        DisposableQualificationResult(False, "")


def test_acquisition_ledger_persists_terminal_and_failure_evidence(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    record = AcquisitionArtifactRecord(
        "a" * 64,
        "acceptance.resource",
        ArtifactState.FAILED,
        "resources/failed.bin",
        None,
        None,
        "network interruption retained for reconciliation",
        now,
        now,
    )
    path = tmp_path / "acquisition.sqlite3"
    store = SQLiteAcquisitionLedger(path)
    store.put(record)
    assert store.get(record.request_fingerprint) == record
    assert store.records() == (record,)
    store.close()
    reopened = SQLiteAcquisitionLedger(path)
    assert reopened.records() == (record,)
    reopened.close()
    with pytest.raises(AcquisitionValidationError, match="ledger record"):
        InMemoryAcquisitionLedger().put(cast(AcquisitionArtifactRecord, object()))
    with pytest.raises(AcquisitionValidationError, match="ledger path"):
        SQLiteAcquisitionLedger(cast(Path, object()))
    with pytest.raises(AcquisitionValidationError, match="Download evidence"):
        DownloadEvidence(
            "https://models.example.test/resource.bin", path, -1, "a" * 64, None, None, None
        )


@pytest.mark.asyncio
async def test_acquisition_phase_authority_uses_distinct_scopes_and_receipts(
    tmp_path: Path,
) -> None:
    target_root = tmp_path / "authority-root"
    target_root.mkdir()
    task_id = uuid4()
    phase_permissions = {
        AcquisitionPhase.DOWNLOAD: Permission.RESOURCE_DOWNLOAD,
        AcquisitionPhase.INSTALL: Permission.RESOURCE_INSTALL,
        AcquisitionPhase.EXECUTE: Permission.RESOURCE_EXECUTE,
        AcquisitionPhase.GRANT_PRIVILEGES: Permission.PRIVILEGE_GRANT,
    }
    rules: list[PolicyRule] = []
    for phase, permission in phase_permissions.items():
        tool_id = f"acquisition.{phase.value}"
        rules.append(
            PolicyRule(
                f"acceptance.{phase.value}",
                permission,
                Decision.ALLOW,
                ScopeConstraint(
                    paths=(str(target_root),) if phase is not AcquisitionPhase.DOWNLOAD else (),
                    hosts=("models.example.test",) if phase is AcquisitionPhase.DOWNLOAD else (),
                    command_families=("resource",)
                    if phase in {AcquisitionPhase.EXECUTE, AcquisitionPhase.GRANT_PRIVILEGES}
                    else (),
                    tools=frozenset({tool_id}),
                    tasks=frozenset({task_id}),
                ),
                frozenset({f"acquisition.{phase.value}"}),
            )
        )
    broker = PermissionBroker(PolicyEngine(tuple(rules)))
    authority = BrokerAcquisitionAuthorizer(broker, target_root=target_root)
    request = _request("https://models.example.test/resource.bin")
    receipts: list[AuthorizationReceipt] = []
    for phase in phase_permissions:
        receipt = await authority.authorize(request, phase, task_id=task_id, user_id=None)
        assert isinstance(receipt, AuthorizationReceipt)
        receipts.append(receipt)
        await authority.begin(receipt)
        assert broker.is_active_receipt(receipt)
        await authority.finish(receipt, AcquisitionEffectOutcome.EFFECT_CONFIRMED)
    assert len({id(receipt) for receipt in receipts}) == 4
    with pytest.raises(AcquisitionValidationError):
        await authority.authorize(
            cast(AcquisitionRequest, object()),
            AcquisitionPhase.DOWNLOAD,
            task_id=task_id,
            user_id=None,
        )
    with pytest.raises(AcquisitionDenied, match="escapes"):
        await authority.authorize(
            replace(request, target_location="../escape.bin"),
            AcquisitionPhase.INSTALL,
            task_id=task_id,
            user_id=None,
        )
    with pytest.raises(AcquisitionDenied, match="malformed"):
        await authority.begin(object())
    with pytest.raises(AcquisitionDenied, match="malformed"):
        await authority.finish(object(), AcquisitionEffectOutcome.PRE_EFFECT_FAILURE)
    empty_authority = BrokerAcquisitionAuthorizer(PermissionBroker(PolicyEngine(())))
    with pytest.raises(AcquisitionDenied):
        await empty_authority.authorize(
            request, AcquisitionPhase.DOWNLOAD, task_id=task_id, user_id=None
        )


@pytest.mark.asyncio
async def test_acquisition_broker_uses_real_download_authority_and_resource_admission(
    tmp_path: Path,
) -> None:
    with _resource_server() as (_server, source):
        target_root = tmp_path / "authorized-root"
        target_root.mkdir()
        task_id = uuid4()
        rule = PolicyRule(
            "acceptance.resource-download",
            Permission.RESOURCE_DOWNLOAD,
            Decision.ALLOW,
            ScopeConstraint(
                hosts=("127.0.0.1",),
                tools=frozenset({"acquisition.download"}),
                tasks=frozenset({task_id}),
            ),
            frozenset({"acquisition.download"}),
        )
        permission_broker = PermissionBroker(PolicyEngine((rule,)))
        authority = BrokerAcquisitionAuthorizer(permission_broker, target_root=target_root)
        telemetry = _FixedTelemetry(
            ResourceSnapshot(datetime.now(UTC), disk_free_bytes=10_000, cpu_cores=8)
        )
        governor = ResourceGovernor(telemetry, policy=ResourcePolicy(low_disk_bytes=0))
        broker = AcquisitionBroker(
            BoundedDownloadTransport(target_root),
            AcquisitionPolicy(
                AcquisitionPolicyMode.ASK_ALWAYS,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            permission_authority=authority,
            resource_governor=governor,
        )
        with pytest.raises(AcquisitionApprovalRequired):
            await broker.acquire(
                _request(source, target="resources/missing-task.bin"),
                disk_free_bytes=10_000,
            )
        result = await broker.acquire(
            _request(source, target="resources/authorized.bin"),
            task_id=task_id,
            disk_free_bytes=10_000,
        )
        assert result.status is AcquisitionResultStatus.REGISTERED
        reservations = governor.reservations()
        assert len(reservations) == 2
        assert all(item.status.value == "completed" for item in reservations)
        await broker.aclose()

        blocked = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "blocked-root"),
            AcquisitionPolicy(
                AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            resource_governor=ResourceGovernor(
                _FixedTelemetry(ResourceSnapshot(datetime.now(UTC), disk_free_bytes=0))
            ),
        )
        with pytest.raises(AcquisitionDeferred, match="disk capacity"):
            await blocked.acquire(
                _request(source, target="resources/blocked.bin"),
                disk_free_bytes=10_000,
            )
        await blocked.aclose()


@pytest.mark.asyncio
async def test_executable_disposition_and_disposable_qualification_fail_closed(
    tmp_path: Path,
) -> None:
    with _resource_server() as (_server, source):
        request = _request(source, resource_type=ResourceType.EXECUTABLE)
        policy = AcquisitionPolicy(
            AcquisitionPolicyMode.JARVIS_MANAGED,
            unknown_executable_policy=UnknownExecutablePolicy.REQUIRE_DISPOSABLE_QUALIFICATION,
            require_known_disk_capacity=False,
        )
        no_qualification = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "no-qualification"),
            policy,
            InMemoryAcquisitionLedger(),
            permission_authority=_AcquisitionAuthority(),
            security=_TrustedScan(),
        )
        pending = await no_qualification.acquire(
            request,
            task_id=uuid4(),
            disk_free_bytes=10_000,
        )
        assert pending.status is AcquisitionResultStatus.VERIFICATION_REQUIRED
        await no_qualification.aclose()

        failed_qualification = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "failed-qualification"),
            policy,
            InMemoryAcquisitionLedger(),
            permission_authority=_AcquisitionAuthority(),
            security=_TrustedScan(),
            qualifier=_Qualification(False),
        )
        failed = await failed_qualification.acquire(
            replace(request, target_location="resources/failed.bin"),
            task_id=uuid4(),
            disk_free_bytes=10_000,
        )
        assert failed.status is AcquisitionResultStatus.VERIFICATION_REQUIRED
        await failed_qualification.aclose()

        passed_qualification = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "passed-qualification"),
            policy,
            InMemoryAcquisitionLedger(),
            permission_authority=_AcquisitionAuthority(),
            security=_TrustedScan(),
            qualifier=_Qualification(True),
        )
        passed = await passed_qualification.acquire(
            replace(request, target_location="resources/passed.bin"),
            task_id=uuid4(),
            disk_free_bytes=10_000,
        )
        assert passed.status is AcquisitionResultStatus.REGISTERED
        await passed_qualification.aclose()


@pytest.mark.asyncio
async def test_acquisition_security_or_qualification_failure_is_unknown_and_not_replayed(
    tmp_path: Path,
) -> None:
    with _resource_server() as (_server, source):
        security_broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "security-failure"),
            AcquisitionPolicy(
                AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            security=_FailingSecurity(),
        )
        security_request = _request(source, target="resources/security-failure.bin")
        with pytest.raises(AcquisitionUnknownOutcome):
            await security_broker.acquire(security_request, disk_free_bytes=10_000)
        assert security_broker.ledger.get(security_request.fingerprint) is not None
        with pytest.raises(AcquisitionUnknownOutcome, match="reconciliation"):
            await security_broker.acquire(security_request, disk_free_bytes=10_000)
        await security_broker.aclose()

        qualification_broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "qualification-failure"),
            AcquisitionPolicy(
                AcquisitionPolicyMode.JARVIS_MANAGED,
                unknown_executable_policy=UnknownExecutablePolicy.REQUIRE_DISPOSABLE_QUALIFICATION,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            security=_TrustedScan(),
            qualifier=_FailingQualification(),
            permission_authority=_AcquisitionAuthority(),
        )
        qualification_request = _request(
            source,
            resource_type=ResourceType.EXECUTABLE,
            target="resources/qualification-failure.bin",
        )
        with pytest.raises(AcquisitionUnknownOutcome):
            await qualification_broker.acquire(
                qualification_request,
                task_id=uuid4(),
                disk_free_bytes=10_000,
            )
        await qualification_broker.aclose()


@pytest.mark.asyncio
async def test_acquisition_async_consumer_target_and_reconcile_boundaries(tmp_path: Path) -> None:
    with _resource_server() as (_server, source):
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "boundaries"),
            AcquisitionPolicy(
                AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
            security=_TrustedScan(),
        )
        request = _request(source, target="resources/async-consumer.bin")

        async def consume(path: Path) -> str:
            return f"consumed:{path.read_bytes().decode()}"

        registered = await broker.acquire(request, disk_free_bytes=10_000, consumer=consume)
        assert registered.status is AcquisitionResultStatus.REGISTERED
        assert registered.consumer_result is not None
        pending_broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "pending"),
            broker.policy,
            InMemoryAcquisitionLedger(),
            security=_PendingSecurity(),
        )
        pending = await pending_broker.acquire(
            replace(request, target_location="resources/pending.bin"),
            disk_free_bytes=10_000,
        )
        assert pending.status is AcquisitionResultStatus.VERIFICATION_REQUIRED
        assert pending.security is not None
        assert pending.security.disposition is SecurityDisposition.REQUIRED_PENDING
        with pytest.raises(AcquisitionValidationError, match="target"):
            await broker.acquire(
                replace(request, target_location=None),
                disk_free_bytes=10_000,
            )
        with pytest.raises(AcquisitionValidationError, match="request"):
            await broker.reconcile(cast(AcquisitionRequest, object()))
        with pytest.raises(AcquisitionUnknownOutcome, match="no acquisition evidence"):
            await broker.reconcile(_request(source, target="resources/not-recorded.bin"))
        await pending_broker.aclose()
        await broker.aclose()


@pytest.mark.asyncio
async def test_acquisition_stale_request_and_executable_policy_are_explicit(tmp_path: Path) -> None:
    with _resource_server() as (_server, source):
        broker = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "downloads"),
            AcquisitionPolicy(
                mode=AcquisitionPolicyMode.JARVIS_MANAGED,
                require_known_disk_capacity=False,
            ),
            InMemoryAcquisitionLedger(),
        )
        expired = _request(source, expires_at=datetime.now(UTC) - timedelta(seconds=1))
        with pytest.raises(AcquisitionStaleRequest):
            await broker.acquire(expired, disk_free_bytes=10_000)
        executable_policy = AcquisitionPolicy(
            mode=AcquisitionPolicyMode.WITHIN_LIMITS,
            unknown_executable_policy=UnknownExecutablePolicy.DENY,
            require_known_disk_capacity=False,
        )
        decision = executable_policy.decide(
            _request(source, resource_type=ResourceType.EXECUTABLE),
            AcquisitionPhase.DOWNLOAD,
            disk_free_bytes=10_000,
        )
        assert decision.status.value == "deny"
        denied = AcquisitionBroker(
            BoundedDownloadTransport(tmp_path / "denied"),
            AcquisitionPolicy(AcquisitionPolicyMode.OFF, require_known_disk_capacity=False),
            InMemoryAcquisitionLedger(),
        )
        with pytest.raises(AcquisitionDenied):
            await denied.acquire(_request(source), disk_free_bytes=10_000)
        await denied.aclose()
        await broker.aclose()


@pytest.mark.asyncio
async def test_ollama_provider_removal_is_typed_and_unknown_on_transport_failure() -> None:
    requests: list[tuple[str, str]] = []

    def delete_handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        return httpx.Response(200, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(delete_handler))
    runtime = OllamaRuntimeManager(
        endpoint="http://127.0.0.1:11434",
        model="qwen3.5:9b",
        autostart=False,
        executable=None,
        start_timeout_seconds=0.2,
        stop_owned_on_exit=False,
        client=client,
    )
    adapter = OllamaModelAdapter(runtime, client=client)
    spec = LocalModelSpec(
        "qwen3.5:9b",
        ModelMetadata("qwen3.5:9b", 8_192),
        ModelArtifact("ollama://qwen3.5:9b", None, 100, provider_managed=True),
        provider_managed=True,
        installed=True,
    )
    try:
        await adapter.remove(spec)
        assert requests == [("DELETE", "/api/delete")]
        file_managed = replace(
            spec,
            artifact=ModelArtifact("fixture://file-model", "a" * 64, 100),
            provider_managed=False,
        )
        with pytest.raises(ProviderError, match="file-managed"):
            await adapter.remove(file_managed)
    finally:
        await adapter.aclose()
        await client.aclose()

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("removal timeout", request=request)

    timeout_client = httpx.AsyncClient(transport=httpx.MockTransport(timeout_handler))
    timeout_runtime = OllamaRuntimeManager(
        endpoint="http://127.0.0.1:11434",
        model="qwen3.5:9b",
        autostart=False,
        executable=None,
        start_timeout_seconds=0.2,
        stop_owned_on_exit=False,
        client=timeout_client,
    )
    timeout_adapter = OllamaModelAdapter(timeout_runtime, client=timeout_client)
    try:
        with pytest.raises(ModelRemovalUnknownOutcome, match="ambiguous"):
            await timeout_adapter.remove(spec)
    finally:
        await timeout_adapter.aclose()
        await timeout_client.aclose()


class _DisposableModelProvider:
    def __init__(self, root: Path, specs: tuple[LocalModelSpec, ...]) -> None:
        self.root = root
        self.specs = {spec.model_id: spec for spec in specs}
        self.removal_calls: list[str] = []
        self.ambiguous = False
        self.ambiguous_deletes = False

    async def ensure_provider(self) -> object:
        return self

    async def discover(self) -> tuple[LocalModelSpec, ...]:
        found: list[LocalModelSpec] = []
        for model_id, spec in self.specs.items():
            path = self.root / f"{model_id}.model"
            if path.is_file():
                found.append(
                    LocalModelSpec(
                        model_id,
                        spec.metadata,
                        spec.artifact,
                        provider_managed=True,
                        installed=True,
                        provider_digest=spec.provider_digest,
                    )
                )
        return tuple(found)

    async def acquire(self, spec: LocalModelSpec) -> None:
        (self.root / f"{spec.model_id}.model").write_bytes(b"disposable model")

    async def verify(self, spec: LocalModelSpec) -> bool:
        return (self.root / f"{spec.model_id}.model").is_file()

    async def load(self, spec: LocalModelSpec) -> object:
        return spec.model_id

    async def unload(self, _model_id: str, _handle: object | None) -> None:
        return None

    async def remove(self, spec: LocalModelSpec) -> None:
        self.removal_calls.append(spec.model_id)
        if self.ambiguous:
            if self.ambiguous_deletes:
                (self.root / f"{spec.model_id}.model").unlink(missing_ok=True)
            raise ModelRemovalUnknownOutcome("fixture removal interrupted")
        (self.root / f"{spec.model_id}.model").unlink()

    async def health(self, model_id: str, _handle: object | None) -> ModelHealth:
        path = self.root / f"{model_id}.model"
        return ModelHealth(model_id, path.is_file(), "disposable provider truth", datetime.now(UTC))

    async def benchmark(self, model_id: str, _handle: object) -> ModelMeasurement:
        return ModelMeasurement(
            model_id, datetime.now(UTC), "disposable benchmark", throughput=20.0
        )

    async def recover_provider(self) -> object:
        return self

    async def aclose(self) -> None:
        return None


class _RemovalAuthority:
    def __init__(self) -> None:
        self.events: list[str] = []

    async def authorize(self, _plan: object, *, task_id: UUID, user_id: str | None) -> object:
        self.events.append(f"authorize:{task_id}:{user_id}")
        return object()

    async def begin(self, _receipt: object) -> None:
        self.events.append("begin")

    async def finish(self, _receipt: object, outcome: object) -> None:
        self.events.append(f"finish:{getattr(outcome, 'value', outcome)}")


def _usable_replacement(_identity: object) -> ModelUsabilityEvidence:
    return ModelUsabilityEvidence(
        configured=True,
        connected=True,
        reachable=True,
        authenticated=True,
        entitled=True,
        quota_usable=True,
        capacity_usable=True,
        model_usable=True,
        policy_eligible=True,
        resource_eligible=True,
        request_usable=True,
        detail="acceptance-owned request-specific usability probe passed",
    )


def _portfolio_fixture(
    tmp_path: Path,
    *,
    include_specialist: bool = False,
) -> tuple[
    LocalModelManager,
    ModelKnowledgeService,
    ProviderRegistry,
    _DisposableModelProvider,
    ModelPortfolioOptimizer,
]:
    root = tmp_path / "provider"
    root.mkdir()
    model_ids = ("old", "new", "specialist") if include_specialist else ("old", "new")
    metadata = tuple(
        ModelMetadata(
            model_id,
            8_192,
            capabilities=frozenset({"coding", "vision"})
            if model_id == "specialist"
            else frozenset({"coding"}),
            roles=frozenset({ModelRole.GENERAL}),
            modalities=frozenset({"text"}),
            storage_bytes={"old": 16, "new": 12, "specialist": 20}[model_id],
            ram_bytes=1,
            source="fixture.provider",
        )
        for model_id in model_ids
    )
    specs = tuple(
        LocalModelSpec(
            item.model_id,
            item,
            ModelArtifact(
                f"fixture://{item.model_id}",
                None,
                item.storage_bytes,
                provider_digest=f"digest:{item.model_id}",
                provider_managed=True,
            ),
            provider_managed=True,
            installed=True,
            provider_digest=f"digest:{item.model_id}",
        )
        for item in metadata
    )
    provider = _DisposableModelProvider(root, specs)
    for item in specs:
        (root / f"{item.model_id}.model").write_bytes(b"disposable model")
    knowledge = ModelKnowledgeService(ModelKnowledgeStore(tmp_path / "knowledge.sqlite3"))
    manager = LocalModelManager(
        tmp_path / "models",
        knowledge=knowledge,
        provider_id="fixture",
        provider_adapter=provider,
    )
    provider_metadata = ProviderMetadata(
        "fixture",
        "Fixture provider",
        "1",
        local_only=True,
        locality=ProviderLocality.LOCAL,
    )
    knowledge.store.register_provider(provider_metadata)
    registry = ProviderRegistry(
        (ProviderDefinition(provider_metadata, lambda _config: FakeAIProvider(), metadata),)
    )
    authority = _RemovalAuthority()
    optimizer = ModelPortfolioOptimizer(
        manager,
        knowledge,
        registry,
        provider_id="fixture",
        retirement_store=InMemoryRetirementStore(),
        removal_authorization=authority,
        router_integrity=lambda identity: all(
            model.model_id != identity.model_id for model in registry.definition("fixture").models
        ),
        storage_measurement=lambda identity: (
            (root / f"{identity.model_id}.model").stat().st_size
            if (root / f"{identity.model_id}.model").is_file()
            else 0
        ),
        replacement_usability=_usable_replacement,
    )
    return manager, knowledge, registry, provider, optimizer


def _record_cookbook(
    knowledge: ModelKnowledgeService,
    manager: LocalModelManager,
    model_id: str,
    *,
    task_class: str = "coding",
    successes: int = 3,
) -> None:
    identity = identity_for("fixture", manager.inspect(model_id).spec.metadata)
    for index in range(3):
        success = index < successes
        knowledge.record_cookbook(
            CookbookObservation(
                identity,
                task_class,
                CookbookOutcome.VERIFIED_SUCCESS if success else CookbookOutcome.FAILURE,
                datetime.now(UTC),
                operation_class=task_class,
                role=ModelRole.GENERAL,
                machine_scope="this_machine",
                verified=success,
                verifier_agreement=(
                    VerifierAgreement.DETERMINISTIC_VERIFICATION
                    if success
                    else VerifierAgreement.UNKNOWN
                ),
                observation_id=f"{model_id}-{task_class}-{index}",
            )
        )


def test_retirement_store_persists_protection_and_approval_bindings(tmp_path: Path) -> None:
    metadata = ModelMetadata("old", 8_192, storage_bytes=16)
    replacement_metadata = ModelMetadata("new", 8_192, storage_bytes=12)
    now = datetime.now(UTC)
    task_id = uuid4()
    plan = RetirementPlan(
        uuid4(),
        identity_for("fixture", metadata),
        identity_for("fixture", replacement_metadata),
        "digest:old",
        ModelLifecycleState.AVAILABLE,
        RetirementState.ACTIVE,
        now,
        now + timedelta(seconds=10),
        "f" * 64,
        "durable retirement evidence",
        RetirementProtection(privacy_route=True, reacquisition_known=True),
        task_id,
        "trusted-user",
    )
    path = tmp_path / "retirements.sqlite3"
    store = SQLiteRetirementStore(path)
    store.put(plan)
    assert store.get(plan.plan_id) == plan
    assert store.history(plan.plan_id) == (plan,)
    assert store.active_plans() == (plan,)
    store.close()
    reopened = SQLiteRetirementStore(path)
    restored = reopened.get(plan.plan_id)
    assert restored == plan
    assert restored is not None and restored.protection.privacy_route
    reopened.close()


def test_retirement_store_migrates_legacy_rows_without_inventing_protection(
    tmp_path: Path,
) -> None:
    metadata = ModelMetadata("old", 8_192, storage_bytes=16)
    replacement_metadata = ModelMetadata("new", 8_192, storage_bytes=12)
    now = datetime.now(UTC)
    plan_id = uuid4()
    path = tmp_path / "legacy-retirements.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        """CREATE TABLE model_retirement_history (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_id TEXT NOT NULL,
            model_json TEXT NOT NULL,
            replacement_json TEXT NOT NULL,
            expected_digest TEXT,
            expected_state TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            retention_until TEXT,
            analysis_fingerprint TEXT NOT NULL,
            detail TEXT NOT NULL
        )"""
    )
    connection.execute(
        """INSERT INTO model_retirement_history
        (plan_id, model_json, replacement_json, expected_digest, expected_state, state,
         created_at, retention_until, analysis_fingerprint, detail)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            str(plan_id),
            identity_for("fixture", metadata).storage_key,
            identity_for("fixture", replacement_metadata).storage_key,
            "digest:old",
            ModelLifecycleState.AVAILABLE.value,
            RetirementState.ACTIVE.value,
            now.isoformat(),
            (now + timedelta(seconds=10)).isoformat(),
            "f" * 64,
            "legacy retirement evidence",
        ),
    )
    connection.commit()
    connection.close()
    store = SQLiteRetirementStore(path)
    restored = store.get(plan_id)
    assert restored is not None
    assert restored.protection == RetirementProtection()
    assert restored.approval_task_id is None and restored.approval_user_id is None
    store.close()


def test_model_usability_evidence_does_not_equate_availability_with_usability() -> None:
    assert _usable_replacement(object()).status is ModelUsabilityStatus.USABLE
    assert (
        ModelUsabilityEvidence(configured=True, connected=True).status
        is ModelUsabilityStatus.UNKNOWN
    )
    assert (
        ModelUsabilityEvidence(
            configured=True,
            connected=True,
            authenticated=True,
            entitled=False,
        ).status
        is ModelUsabilityStatus.NOT_USABLE
    )
    with pytest.raises(PortfolioError, match="usability detail"):
        ModelUsabilityEvidence(detail="")


@pytest.mark.asyncio
async def test_model_removal_authority_binds_permission_and_effect_receipt() -> None:
    now = datetime.now(UTC)
    task_id = uuid4()
    plan = RetirementPlan(
        uuid4(),
        identity_for("fixture", ModelMetadata("old", 8_192)),
        identity_for("fixture", ModelMetadata("new", 8_192)),
        "digest:old",
        ModelLifecycleState.AVAILABLE,
        RetirementState.REMOVAL_APPROVED,
        now,
        now + timedelta(seconds=10),
        "f" * 64,
        "trusted removal plan",
        RetirementProtection(reacquisition_known=True),
    )
    rule = PolicyRule(
        "acceptance.model-removal",
        Permission.MODEL_REMOVE,
        Decision.ALLOW,
        ScopeConstraint(
            tools=frozenset({"model.retirement.remove"}),
            tasks=frozenset({task_id}),
        ),
        frozenset({"model.retirement.remove"}),
    )
    broker = PermissionBroker(PolicyEngine((rule,)))
    authority = BrokerModelRemovalAuthorizer(broker)
    receipt = await authority.authorize(plan, task_id=task_id, user_id="trusted-user")
    assert isinstance(receipt, AuthorizationReceipt)
    await authority.begin(receipt)
    assert broker.is_active_receipt(receipt)
    await authority.finish(receipt, RemovalEffectOutcome.EFFECT_CONFIRMED)
    with pytest.raises(PortfolioError, match="receipt"):
        await authority.begin(object())
    with pytest.raises(PortfolioError, match="receipt"):
        await authority.finish(object(), RemovalEffectOutcome.PRE_EFFECT_FAILURE)

    denied = BrokerModelRemovalAuthorizer(PermissionBroker(PolicyEngine(())))
    with pytest.raises(PortfolioError):
        await denied.authorize(plan, task_id=task_id, user_id=None)


@pytest.mark.asyncio
async def test_portfolio_dominance_specialist_alias_and_minimality_are_evidence_driven(
    tmp_path: Path,
) -> None:
    manager, knowledge, registry, _provider, optimizer = _portfolio_fixture(tmp_path)
    await manager.discover()
    _record_cookbook(knowledge, manager, "old", successes=2)
    _record_cookbook(knowledge, manager, "new", successes=3)
    evidence = await optimizer.current_evidence(task_classes=("coding",), router_usage={"old": 4})
    assert next(item for item in evidence if item.identity.model_id == "old").actual_router_use == 4
    analysis = optimizer.analyze(evidence, task_classes=("coding",))
    old = next(item for item in analysis if item.candidate.identity.model_id == "old")
    assert old.classification is DominanceClassification.REDUNDANT_CANDIDATE
    assert old.replacement is not None and old.replacement.identity.model_id == "new"
    assert optimizer.minimal_portfolio(evidence, ("coding",)) == (old.replacement.identity,)
    assert optimizer.minimal_portfolio(evidence, ()) == tuple(item.identity for item in evidence)
    assert optimizer.minimal_portfolio(evidence, ("unknown-task",)) == ()
    unavailable = replace(evidence[0], available=False)
    unavailable_analysis = optimizer.analyze((unavailable, evidence[1]), task_classes=("coding",))
    assert unavailable_analysis[0].classification is DominanceClassification.NOT_REDUNDANT
    bare_old = replace(evidence[0], task_summaries=(), provider_digest="bare-old")
    bare_new = replace(evidence[1], task_summaries=(), provider_digest="bare-new")
    assert (
        optimizer.analyze((bare_old, bare_new), task_classes=("coding",))[0].classification
        is DominanceClassification.INSUFFICIENT_EVIDENCE
    )

    alias_old = ModelPortfolioEvidence(
        evidence[0].identity,
        evidence[0].metadata,
        True,
        provider_digest="same-digest",
        task_summaries=evidence[0].task_summaries,
    )
    alias_new = ModelPortfolioEvidence(
        evidence[1].identity,
        evidence[1].metadata,
        True,
        provider_digest="same-digest",
        task_summaries=evidence[1].task_summaries,
    )
    aliases = optimizer.analyze((alias_old, alias_new), task_classes=("coding",))
    assert aliases[0].classification is DominanceClassification.NOT_REDUNDANT
    assert aliases[0].physical_alias is True
    assert registry.definition("fixture").metadata.explicitly_local
    await optimizer.aclose()
    await manager.aclose()
    knowledge.close()


@pytest.mark.asyncio
async def test_portfolio_preserves_unique_capability_and_proposes_only_dominated_model(
    tmp_path: Path,
) -> None:
    manager, knowledge, _registry, _provider, optimizer = _portfolio_fixture(
        tmp_path, include_specialist=True
    )
    await manager.discover()
    _record_cookbook(knowledge, manager, "old", successes=2)
    _record_cookbook(knowledge, manager, "new", successes=3)
    _record_cookbook(knowledge, manager, "specialist", successes=1)
    measured_at = datetime.now(UTC)
    for model_id, storage_bytes, throughput in (
        ("old", 16, 40.0),
        ("new", 12, 60.0),
        ("specialist", 20, 20.0),
    ):
        knowledge.record_measurement(
            identity_for("fixture", manager.inspect(model_id).spec.metadata),
            ModelMeasurement(
                model_id,
                measured_at,
                "controlled-portfolio-benchmark",
                storage_bytes=storage_bytes,
                load_seconds=1.0,
                throughput=throughput,
            ),
        )

    evidence = await optimizer.current_evidence(task_classes=("coding",))
    assert {item.identity.model_id for item in evidence} == {"old", "new", "specialist"}
    analysis = optimizer.analyze(evidence, task_classes=("coding",))
    by_model = {item.candidate.identity.model_id: item for item in analysis}
    assert by_model["old"].classification is DominanceClassification.REDUNDANT_CANDIDATE
    assert by_model["old"].replacement is not None
    assert by_model["old"].replacement.identity.model_id == "new"
    assert by_model["specialist"].classification is DominanceClassification.SPECIALIST
    assert "vision" in by_model["specialist"].unique_dimensions
    assert by_model["new"].classification is not DominanceClassification.REDUNDANT_CANDIDATE

    retirement = optimizer.propose_retirement(
        by_model["old"], RetirementProtection(reacquisition_known=True), retention_seconds=1
    )
    assert retirement.model.model_id == "old"
    with pytest.raises(InsufficientPortfolioEvidence):
        optimizer.propose_retirement(
            by_model["specialist"], RetirementProtection(reacquisition_known=True)
        )
    await optimizer.aclose()
    await manager.aclose()
    knowledge.close()


@pytest.mark.asyncio
async def test_portfolio_contract_validation_and_retirement_proposal_bounds(tmp_path: Path) -> None:
    manager, knowledge, _registry, _provider, optimizer = _portfolio_fixture(tmp_path)
    await manager.discover()
    _record_cookbook(knowledge, manager, "old", successes=2)
    _record_cookbook(knowledge, manager, "new", successes=3)
    evidence = await optimizer.current_evidence(task_classes=("coding",))
    with pytest.raises(PortfolioError, match="Model record"):
        optimizer.evidence_for(cast(LocalModelRecord, object()))
    with pytest.raises(PortfolioError, match="candidates"):
        optimizer.analyze(cast(tuple[ModelPortfolioEvidence, ...], (object(),)))
    base = evidence[0]
    invalid_cases: tuple[Callable[[], ModelPortfolioEvidence], ...] = (
        lambda: replace(base, physical_size_bytes=-1),
        lambda: replace(base, actual_router_use=-1),
        lambda: replace(base, privacy_eligible=cast(bool | None, 1)),
        lambda: replace(base, stability=2.0),
    )
    for invalid in invalid_cases:
        with pytest.raises(PortfolioError):
            invalid()
    with pytest.raises(PortfolioError, match="classification"):
        DominanceAnalysis(
            base,
            None,
            cast(DominanceClassification, object()),
            "invalid classification",
        )
    with pytest.raises(PortfolioError, match="protection flags"):
        RetirementProtection(user_pinned=cast(bool, 1))
    with pytest.raises(PortfolioError, match="Reacquisition"):
        RetirementProtection(reacquisition_known=cast(bool | None, 1))
    with pytest.raises(PortfolioError, match="evidence"):
        RetirementProtection.from_dict(cast(object, []))
    analysis = optimizer.analyze(evidence, task_classes=("coding",))[0]
    with pytest.raises(InsufficientPortfolioEvidence):
        optimizer.propose_retirement(
            replace(analysis, classification=DominanceClassification.SPECIALIST),
            RetirementProtection(reacquisition_known=True),
        )
    for retention_seconds in (0, 31_536_001):
        with pytest.raises(PortfolioError, match="retention"):
            optimizer.propose_retirement(
                analysis,
                RetirementProtection(reacquisition_known=True),
                retention_seconds=retention_seconds,
            )
    await optimizer.aclose()
    await manager.aclose()
    knowledge.close()


@pytest.mark.asyncio
async def test_portfolio_evidence_plan_and_store_contracts_fail_closed(tmp_path: Path) -> None:
    manager, knowledge, _registry, _provider, optimizer = _portfolio_fixture(tmp_path)
    await manager.discover()
    evidence = await optimizer.current_evidence(task_classes=("coding",))
    base, replacement = evidence
    invalid_evidence: tuple[Callable[[], ModelPortfolioEvidence], ...] = (
        lambda: ModelPortfolioEvidence(cast(ModelIdentity, object()), base.metadata, True),
        lambda: ModelPortfolioEvidence(
            base.identity, replace(base.metadata, model_id="different"), True
        ),
        lambda: ModelPortfolioEvidence(base.identity, base.metadata, cast(bool, 1)),
        lambda: replace(base, provider_digest=cast(str, 1)),
        lambda: replace(
            base,
            task_summaries=cast(tuple[CookbookSummary, ...], (object(),)),
        ),
        lambda: replace(base, measurement=cast(ModelMeasurementView, object())),
        lambda: replace(base, stability=-0.1),
    )
    for invalid in invalid_evidence:
        with pytest.raises(PortfolioError):
            invalid()
    assert base.capability_dimensions
    assert base.same_physical_identity_key == ("fixture", base.provider_digest)
    assert base.summary_for("missing") is None
    measurement = ModelMeasurementView(
        base.identity,
        datetime.now(UTC),
        "acceptance-measurement",
        "this_machine",
        storage_bytes=8,
        load_seconds=2.0,
        throughput=50.0,
    )
    measured = replace(
        base,
        measurement=measurement,
        metadata=replace(base.metadata, quality_score=0.8, latency_ms=100.0),
        stability=0.9,
    )
    assert ModelPortfolioOptimizer._utility(measured, ()) > 0  # noqa: SLF001
    larger = replace(
        base,
        measurement=replace(measurement, storage_bytes=16),
    )
    assert ModelPortfolioOptimizer._resource_better(measured, larger)  # noqa: SLF001
    assert not ModelPortfolioOptimizer._resource_better(larger, measured)  # noqa: SLF001
    no_storage = replace(
        measured,
        measurement=replace(measurement, storage_bytes=None),
    )
    assert not ModelPortfolioOptimizer._resource_better(no_storage, measured)  # noqa: SLF001

    dominance_invalid: tuple[Callable[[], DominanceAnalysis], ...] = (
        lambda: DominanceAnalysis(
            base,
            cast(ModelPortfolioEvidence, object()),
            DominanceClassification.REDUNDANT_CANDIDATE,
            "invalid replacement",
        ),
        lambda: DominanceAnalysis(
            base,
            None,
            DominanceClassification.NOT_REDUNDANT,
            "invalid task evidence",
            cast(tuple[str, ...], ["coding"]),
        ),
        lambda: DominanceAnalysis(
            base,
            None,
            DominanceClassification.NOT_REDUNDANT,
            "invalid dimensions",
            unique_dimensions=cast(frozenset[str], {"coding"}),
        ),
        lambda: DominanceAnalysis(
            base,
            None,
            DominanceClassification.NOT_REDUNDANT,
            "invalid utility",
            candidate_utility=-1,
        ),
        lambda: DominanceAnalysis(
            base,
            None,
            DominanceClassification.NOT_REDUNDANT,
            "invalid alias",
            physical_alias=cast(bool, 1),
        ),
    )
    for invalid_dominance in dominance_invalid:
        with pytest.raises(PortfolioError):
            invalid_dominance()

    now = datetime.now(UTC)
    plan = RetirementPlan(
        uuid4(),
        base.identity,
        replacement.identity,
        base.provider_digest,
        ModelLifecycleState.AVAILABLE,
        RetirementState.ACTIVE,
        now,
        now + timedelta(seconds=10),
        "a" * 64,
        "contract-boundary plan",
    )
    assert plan.fingerprint
    verified = RemovalVerification(
        plan,
        True,
        True,
        True,
        True,
        True,
        0,
        16,
        0,
        True,
        True,
    )
    assert verified.registry_verified
    for incomplete in (
        replace(verified, provider_absent=False),
        replace(verified, registry_updated=False),
        replace(verified, router_excludes_model=False),
        replace(verified, fallback_healthy=False),
        replace(verified, capability_health=False),
        replace(verified, broken_dependencies=1),
        replace(verified, history_preserved=False),
        replace(verified, storage_delta_verified=False),
    ):
        assert not incomplete.registry_verified
    invalid_plans: tuple[Callable[[], RetirementPlan], ...] = (
        lambda: replace(plan, plan_id=cast(UUID, object())),
        lambda: replace(plan, model=cast(ModelIdentity, object())),
        lambda: replace(plan, expected_state=cast(ModelLifecycleState, object())),
        lambda: replace(plan, protection=cast(RetirementProtection, object())),
        lambda: replace(plan, approval_task_id=cast(UUID, object())),
        lambda: replace(plan, approval_user_id=cast(str, 1)),
        lambda: replace(plan, state=cast(RetirementState, object())),
        lambda: replace(plan, created_at=datetime.now()),
        lambda: replace(plan, retention_until=now),
        lambda: replace(plan, analysis_fingerprint=""),
        lambda: replace(plan, detail=""),
    )
    for invalid_plan in invalid_plans:
        with pytest.raises(PortfolioError):
            invalid_plan()
    with pytest.raises(PortfolioError, match="record"):
        InMemoryRetirementStore().put(cast(RetirementPlan, object()))
    await optimizer.aclose()
    await manager.aclose()
    knowledge.close()


@pytest.mark.asyncio
async def test_specialist_and_protected_models_never_enter_destructive_retirement(
    tmp_path: Path,
) -> None:
    manager, knowledge, _registry, _provider, optimizer = _portfolio_fixture(tmp_path)
    await manager.discover()
    _record_cookbook(knowledge, manager, "old")
    _record_cookbook(knowledge, manager, "new")
    evidence = await optimizer.current_evidence(task_classes=("coding",))
    specialist_old = ModelPortfolioEvidence(
        evidence[0].identity,
        ModelMetadata(
            "old",
            8_192,
            capabilities=frozenset({"vision"}),
            roles=frozenset({ModelRole.GENERAL}),
            modalities=frozenset({"image"}),
            storage_bytes=16,
        ),
        True,
        provider_digest="specialist-old",
        task_summaries=evidence[0].task_summaries,
    )
    specialist_new = ModelPortfolioEvidence(
        evidence[1].identity,
        evidence[1].metadata,
        True,
        provider_digest="specialist-new",
        task_summaries=evidence[1].task_summaries,
    )
    specialist = optimizer.analyze((specialist_old, specialist_new), task_classes=("coding",))[0]
    assert specialist.classification is DominanceClassification.SPECIALIST
    base = optimizer.analyze(evidence, task_classes=("coding",))[0]
    for protection in (
        RetirementProtection(user_pinned=True, reacquisition_known=True),
        RetirementProtection(sole_local_fallback=True, reacquisition_known=True),
        RetirementProtection(in_use=True, reacquisition_known=True),
        RetirementProtection(required_by_capability=True, reacquisition_known=True),
        RetirementProtection(required_by_lkg=True, reacquisition_known=True),
        RetirementProtection(privacy_route=True, reacquisition_known=True),
        RetirementProtection(never_delete=True, reacquisition_known=True),
        RetirementProtection(active_task_dependency=True, reacquisition_known=True),
        RetirementProtection(reacquisition_known=None),
    ):
        with pytest.raises(PortfolioError, match="protected"):
            optimizer.propose_retirement(base, protection, retention_seconds=1)
    await optimizer.aclose()
    await manager.aclose()
    knowledge.close()


@pytest.mark.asyncio
async def test_disposable_provider_removal_requires_lifecycle_and_verifies_history(
    tmp_path: Path,
) -> None:
    manager, knowledge, registry, provider, optimizer = _portfolio_fixture(tmp_path)
    await manager.discover()
    _record_cookbook(knowledge, manager, "old", successes=2)
    _record_cookbook(knowledge, manager, "new", successes=3)
    evidence = await optimizer.current_evidence(task_classes=("coding",))
    old_analysis = next(
        item
        for item in optimizer.analyze(evidence, task_classes=("coding",))
        if item.candidate.identity.model_id == "old"
    )
    now = [datetime.now(UTC)]
    optimizer = ModelPortfolioOptimizer(
        manager,
        knowledge,
        registry,
        provider_id="fixture",
        retirement_store=InMemoryRetirementStore(),
        removal_authorization=_RemovalAuthority(),
        clock=lambda: now[0],
        router_integrity=lambda identity: all(
            model.model_id != identity.model_id for model in registry.definition("fixture").models
        ),
        storage_measurement=lambda identity: (
            (provider.root / f"{identity.model_id}.model").stat().st_size
            if (provider.root / f"{identity.model_id}.model").is_file()
            else 0
        ),
        replacement_usability=_usable_replacement,
    )
    plan = optimizer.propose_retirement(
        old_analysis,
        RetirementProtection(reacquisition_known=True),
        retention_seconds=1,
    )
    with pytest.raises(PortfolioError, match="invalid retirement transition"):
        optimizer.transition(plan.plan_id, RetirementState.REMOVAL_APPROVED)
    with pytest.raises(PortfolioError, match="retention-window"):
        await optimizer.approve_removal(plan.plan_id, task_id=uuid4())
    plan = optimizer.transition(plan.plan_id, RetirementState.UNDER_REVIEW)
    plan = optimizer.transition(plan.plan_id, RetirementState.ROUTING_DISABLED)
    assert all(model.model_id != "old" for model in registry.definition("fixture").models)
    plan = optimizer.re_enable(plan.plan_id)
    assert plan.state is RetirementState.ACTIVE
    assert any(model.model_id == "old" for model in registry.definition("fixture").models)
    plan = optimizer.transition(plan.plan_id, RetirementState.UNDER_REVIEW)
    plan = optimizer.transition(plan.plan_id, RetirementState.ROUTING_DISABLED)
    plan = optimizer.transition(plan.plan_id, RetirementState.RETIREMENT_CANDIDATE)
    plan = optimizer.transition(plan.plan_id, RetirementState.RETENTION_WINDOW)
    with pytest.raises(PortfolioError, match="retention window"):
        await optimizer.approve_removal(plan.plan_id, task_id=uuid4())
    now[0] += timedelta(seconds=2)
    plan = await optimizer.approve_removal(plan.plan_id, task_id=uuid4(), user_id="trusted-user")
    assert plan.state is RetirementState.REMOVAL_APPROVED
    verification = await optimizer.remove(plan.plan_id)
    assert verification.registry_verified
    assert verification.plan.state is RetirementState.REGISTRY_VERIFIED
    assert provider.removal_calls == ["old"]
    assert not (provider.root / "old.model").exists()
    assert any(model.model_id == "new" for model in registry.definition("fixture").models)
    assert knowledge.inspect_model(old_analysis.candidate.identity).identity.model_id == "old"
    await optimizer.aclose()
    await manager.aclose()
    knowledge.close()


@pytest.mark.asyncio
async def test_retirement_does_not_treat_available_fallback_as_usable_without_evidence(
    tmp_path: Path,
) -> None:
    manager, knowledge, registry, provider, evidence_optimizer = _portfolio_fixture(tmp_path)
    await manager.discover()
    _record_cookbook(knowledge, manager, "old")
    _record_cookbook(knowledge, manager, "new")
    evidence = await evidence_optimizer.current_evidence(task_classes=("coding",))
    analysis = next(
        item
        for item in evidence_optimizer.analyze(evidence, task_classes=("coding",))
        if item.candidate.identity.model_id == "old"
    )
    clock = [datetime.now(UTC)]
    optimizer = ModelPortfolioOptimizer(
        manager,
        knowledge,
        registry,
        provider_id="fixture",
        retirement_store=InMemoryRetirementStore(),
        removal_authorization=_RemovalAuthority(),
        clock=lambda: clock[0],
        router_integrity=lambda identity: all(
            model.model_id != identity.model_id for model in registry.definition("fixture").models
        ),
        storage_measurement=lambda identity: (
            (provider.root / f"{identity.model_id}.model").stat().st_size
            if (provider.root / f"{identity.model_id}.model").is_file()
            else 0
        ),
    )
    plan = optimizer.propose_retirement(
        analysis,
        RetirementProtection(reacquisition_known=True),
        retention_seconds=1,
    )
    for target in (
        RetirementState.UNDER_REVIEW,
        RetirementState.ROUTING_DISABLED,
        RetirementState.RETIREMENT_CANDIDATE,
        RetirementState.RETENTION_WINDOW,
    ):
        plan = optimizer.transition(plan.plan_id, target)
    clock[0] += timedelta(seconds=2)
    await optimizer.approve_removal(plan.plan_id, task_id=uuid4())
    with pytest.raises(StaleRetirementPlan, match="availability is insufficient"):
        await optimizer.remove(plan.plan_id)
    assert provider.removal_calls == []
    await optimizer.aclose()
    await evidence_optimizer.aclose()
    await manager.aclose()
    knowledge.close()


@pytest.mark.asyncio
async def test_retirement_effect_boundary_rejects_new_dependency_without_removal(
    tmp_path: Path,
) -> None:
    manager, knowledge, registry, provider, _optimizer = _portfolio_fixture(tmp_path)
    await manager.discover()
    _record_cookbook(knowledge, manager, "old")
    _record_cookbook(knowledge, manager, "new")
    evidence = await ModelPortfolioOptimizer(
        manager,
        knowledge,
        registry,
        provider_id="fixture",
        retirement_store=InMemoryRetirementStore(),
    ).current_evidence(task_classes=("coding",))
    analysis = next(
        item
        for item in ModelPortfolioOptimizer(
            manager,
            knowledge,
            registry,
            provider_id="fixture",
            retirement_store=InMemoryRetirementStore(),
        ).analyze(evidence, task_classes=("coding",))
        if item.candidate.identity.model_id == "old"
    )
    clock = [datetime.now(UTC)]
    optimizer = ModelPortfolioOptimizer(
        manager,
        knowledge,
        registry,
        provider_id="fixture",
        retirement_store=InMemoryRetirementStore(),
        removal_authorization=_RemovalAuthority(),
        clock=lambda: clock[0],
        dependency_references=lambda _identity: ("active-task",),
        replacement_usability=_usable_replacement,
    )
    plan = optimizer.propose_retirement(
        analysis,
        RetirementProtection(reacquisition_known=True),
        retention_seconds=1,
    )
    for target in (
        RetirementState.UNDER_REVIEW,
        RetirementState.ROUTING_DISABLED,
        RetirementState.RETIREMENT_CANDIDATE,
        RetirementState.RETENTION_WINDOW,
    ):
        plan = optimizer.transition(plan.plan_id, target)
    clock[0] += timedelta(seconds=2)
    await optimizer.approve_removal(plan.plan_id, task_id=uuid4())
    with pytest.raises(PortfolioError, match="dependency"):
        await optimizer.remove(plan.plan_id)
    assert provider.removal_calls == []
    await optimizer.aclose()
    await manager.aclose()
    knowledge.close()


@pytest.mark.asyncio
async def test_retirement_effect_boundary_guards_each_stale_precondition(tmp_path: Path) -> None:
    manager, knowledge, registry, provider, _optimizer = _portfolio_fixture(tmp_path)
    await manager.discover()
    _record_cookbook(knowledge, manager, "old", successes=2)
    _record_cookbook(knowledge, manager, "new", successes=3)
    evidence = await _optimizer.current_evidence(task_classes=("coding",))
    analysis = next(
        item
        for item in _optimizer.analyze(evidence, task_classes=("coding",))
        if item.candidate.identity.model_id == "old"
    )
    clock = [datetime.now(UTC)]
    store = InMemoryRetirementStore()
    authority = _RemovalAuthority()
    router_ok = [True]
    capability_ok = [True]
    optimizer = ModelPortfolioOptimizer(
        manager,
        knowledge,
        registry,
        provider_id="fixture",
        retirement_store=store,
        removal_authorization=authority,
        clock=lambda: clock[0],
        router_integrity=lambda _identity: router_ok[0],
        capability_health=lambda _identity: capability_ok[0],
        storage_measurement=lambda identity: (
            (provider.root / f"{identity.model_id}.model").stat().st_size
            if (provider.root / f"{identity.model_id}.model").is_file()
            else 0
        ),
        replacement_usability=_usable_replacement,
    )
    plan = RetirementPlan(
        uuid4(),
        analysis.candidate.identity,
        analysis.replacement.identity if analysis.replacement is not None else evidence[1].identity,
        analysis.candidate.provider_digest,
        ModelLifecycleState.AVAILABLE,
        RetirementState.REMOVAL_APPROVED,
        clock[0],
        clock[0] + timedelta(seconds=1),
        "b" * 64,
        "stale-boundary plan",
        RetirementProtection(reacquisition_known=True),
    )

    store.put(replace(plan, state=RetirementState.ACTIVE))
    with pytest.raises(PortfolioError, match="approved plan"):
        await optimizer.remove(plan.plan_id)
    store.put(plan)
    with pytest.raises(PortfolioError, match="fresh trusted"):
        await optimizer.remove(plan.plan_id)

    def arm(candidate: RetirementPlan) -> None:
        store.put(candidate)
        optimizer._receipts[candidate.plan_id] = object()  # noqa: SLF001

    arm(replace(plan, model=identity_for("other", analysis.candidate.metadata)))
    with pytest.raises(StaleRetirementPlan, match="provider identity"):
        await optimizer.remove(plan.plan_id)
    arm(replace(plan, protection=RetirementProtection(user_pinned=True, reacquisition_known=True)))
    with pytest.raises(StaleRetirementPlan, match="protection"):
        await optimizer.remove(plan.plan_id)
    arm(plan)
    with pytest.raises(StaleRetirementPlan, match="routing"):
        await optimizer.remove(plan.plan_id)
    optimizer._routing_disabled.add(plan.model)  # noqa: SLF001
    arm(replace(plan, expected_provider_digest="changed"))
    with pytest.raises(StaleRetirementPlan, match="digest"):
        await optimizer.remove(plan.plan_id)
    arm(replace(plan, expected_state=ModelLifecycleState.IDLE))
    with pytest.raises(StaleRetirementPlan, match="lifecycle"):
        await optimizer.remove(plan.plan_id)

    router_ok[0] = False
    arm(plan)
    with pytest.raises(StaleRetirementPlan, match="eligible for routing"):
        await optimizer.remove(plan.plan_id)
    router_ok[0] = True
    capability_ok[0] = False
    arm(plan)
    with pytest.raises(StaleRetirementPlan, match="capability health"):
        await optimizer.remove(plan.plan_id)
    capability_ok[0] = True
    (provider.root / "new.model").unlink()
    arm(plan)
    with pytest.raises(StaleRetirementPlan, match="replacement"):
        await optimizer.remove(plan.plan_id)
    (provider.root / "new.model").write_bytes(b"disposable model")
    await manager.discover()

    store.put(plan)
    reconciled = await optimizer.reconcile_removal(plan.plan_id)
    assert "still exposes" in reconciled.detail
    await optimizer.aclose()
    await manager.aclose()
    knowledge.close()


@pytest.mark.asyncio
async def test_ambiguous_provider_removal_is_reconciled_without_retry(tmp_path: Path) -> None:
    manager, knowledge, _registry, provider, optimizer = _portfolio_fixture(tmp_path)
    await manager.discover()
    _record_cookbook(knowledge, manager, "old")
    _record_cookbook(knowledge, manager, "new")
    evidence = await optimizer.current_evidence(task_classes=("coding",))
    old_analysis = next(
        item
        for item in optimizer.analyze(evidence, task_classes=("coding",))
        if item.candidate.identity.model_id == "old"
    )
    clock = [datetime.now(UTC)]
    optimizer = ModelPortfolioOptimizer(
        manager,
        knowledge,
        ProviderRegistry(
            (
                ProviderDefinition(
                    ProviderMetadata(
                        "fixture", "Fixture", "1", local_only=True, locality=ProviderLocality.LOCAL
                    ),
                    lambda _config: FakeAIProvider(),
                    tuple(item.spec.metadata for item in await manager.discover()),
                ),
            )
        ),
        provider_id="fixture",
        retirement_store=InMemoryRetirementStore(),
        removal_authorization=_RemovalAuthority(),
        clock=lambda: clock[0],
        replacement_usability=_usable_replacement,
    )
    plan = optimizer.propose_retirement(
        old_analysis,
        RetirementProtection(reacquisition_known=True),
        retention_seconds=1,
    )
    for target in (
        RetirementState.UNDER_REVIEW,
        RetirementState.ROUTING_DISABLED,
        RetirementState.RETIREMENT_CANDIDATE,
        RetirementState.RETENTION_WINDOW,
    ):
        plan = optimizer.transition(plan.plan_id, target)
    clock[0] += timedelta(seconds=2)
    await optimizer.approve_removal(plan.plan_id, task_id=uuid4())
    provider.ambiguous = True
    provider.ambiguous_deletes = True
    with pytest.raises(RemovalUnknownOutcome):
        await optimizer.remove(plan.plan_id)
    assert provider.removal_calls == ["old"]
    reconciled = await optimizer.reconcile_removal(plan.plan_id)
    assert reconciled.state is RetirementState.REGISTRY_VERIFIED
    assert "reconciled provider removal" in reconciled.detail
    await optimizer.aclose()
    await manager.aclose()
    knowledge.close()
