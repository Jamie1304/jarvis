"""Trusted production composition for VM-first and scoped host execution."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from jarvis.permissions.broker import PermissionBroker
from jarvis.permissions.models import AuthorizationReceipt
from jarvis.vm.bridge import (
    HostBridge,
    HostBridgeOperation,
    HostBridgeRequest,
    HostBridgeResult,
)
from jarvis.vm.fabric import ExecutionFabric
from jarvis.vm.models import (
    EnvironmentKind,
    GuestCommand,
    GuestResult,
    Instance,
    InstanceState,
    NetworkPolicy,
    RouteDecision,
    Template,
    VirtualizationAvailability,
)
from jarvis.vm.provider import VirtualizationProvider
from jarvis.vm.router import ExecutionIntent, ExecutionRouter


class VMExecutionError(RuntimeError):
    """Base error for a VM execution with no host fallback."""


class VMExecutionUnavailable(VMExecutionError):
    """The requested guest route could not be provided by the selected VM."""

    def __init__(self, evidence: VMExecutionEvidence) -> None:
        super().__init__(evidence.error_code or "VM execution is unavailable")
        self.evidence = evidence


@dataclass(frozen=True, slots=True)
class VMExecutionEvidence:
    """Bounded trusted observation of one routed guest command."""

    task_id: UUID
    intent: ExecutionIntent
    route: RouteDecision
    provider: str
    instance_id: UUID | None
    instance_purpose: EnvironmentKind | None
    guest_request_id: UUID
    guest_ready: bool
    status: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    cancelled: bool = False
    evidence_digest: str = ""
    host_bridge_operations: tuple[str, ...] = ()
    error_code: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "task_id": str(self.task_id),
            "trusted_execution_intent": {
                "task_class": self.intent.task_class,
                "host_resource_dependency": self.intent.host_resource_dependency,
                "physical_device_dependency": self.intent.physical_device_dependency,
                "host_application_required": self.intent.host_application_required,
                "exact_host_mutation": self.intent.exact_host_mutation,
                "isolation_required": self.intent.isolation_required,
                "persistence_required": self.intent.persistence_required,
                "network_required": self.intent.network_required,
                "ui_required": self.intent.ui_required,
                "explicit_host_request": self.intent.explicit_host_request,
                "risk": self.intent.risk,
            },
            "route": {
                "environment": self.route.environment.value,
                "reason": self.route.reason,
                "host_bridges": self.route.host_bridges,
                "isolation_level": self.route.isolation_level,
                "fallbacks": tuple(item.value for item in self.route.fallbacks),
                "approval_required": self.route.approval_required,
            },
            "provider": self.provider,
            "instance_id": str(self.instance_id) if self.instance_id is not None else None,
            "instance_purpose": (
                self.instance_purpose.value if self.instance_purpose is not None else None
            ),
            "guest_command_request_id": str(self.guest_request_id),
            "guest_ready": self.guest_ready,
            "status": self.status,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "evidence_digest": self.evidence_digest,
            "host_bridge_operations": self.host_bridge_operations,
            "error_code": self.error_code,
        }


@dataclass(frozen=True, slots=True)
class HostWriteEvidence:
    """Trusted post-effect observation for the scoped host-file transaction."""

    task_id: UUID
    route: RouteDecision
    request: HostBridgeRequest
    authorization: HostBridgeResult
    resource: str
    scope: str
    bytes_written: int
    content_digest: str
    post_effect_verified: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "task_id": str(self.task_id),
            "route": self.route.environment.value,
            "route_reason": self.route.reason,
            "host_bridge_request_id": str(self.request.request_id),
            "operation": self.request.operation.value,
            "resource": self.resource,
            "scope": self.scope,
            "risk": self.request.risk,
            "approval_identity": self.request.approval_identity,
            "argument_fingerprint": self.request.argument_fingerprint,
            "action_fingerprint": self.request.action_fingerprint,
            "expires_at": self.request.expires_at.isoformat()
            if self.request.expires_at is not None
            else None,
            "authorized": self.authorization.allowed,
            "authorization_reason": self.authorization.reason,
            "bytes_written": self.bytes_written,
            "content_digest": self.content_digest,
            "post_effect_verified": self.post_effect_verified,
        }


class VMExecutionService:
    """Application-owned coordinator for routing, guest execution, and HostBridge."""

    WORKBENCH_TEMPLATE_ID = "jarvis-workbench"
    _WORKBENCH_BASE_IMAGE = "jarvis-workbench-v1"
    _SAFE_EXECUTABLES = frozenset({"printf", "echo", "true", "pwd"})

    def __init__(
        self,
        provider: VirtualizationProvider,
        permission_broker: PermissionBroker,
        *,
        state_root: Path,
        host_root: Path,
        router: ExecutionRouter | None = None,
        fabric: ExecutionFabric | None = None,
        host_bridge: HostBridge | None = None,
    ) -> None:
        self.provider = provider
        self.permission_broker = permission_broker
        self.state_root = state_root.expanduser().resolve()
        self.host_root = host_root.expanduser().resolve()
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.host_root.mkdir(parents=True, exist_ok=True)
        self.router = router or ExecutionRouter()
        self.fabric = fabric or ExecutionFabric(provider)
        self.host_bridge = host_bridge or HostBridge()
        self.host_instance_id = uuid4()
        self._execution_evidence: list[VMExecutionEvidence] = []
        self._host_write_evidence: list[HostWriteEvidence] = []

    @property
    def provider_name(self) -> str:
        return self.provider.name

    @property
    def execution_evidence(self) -> tuple[VMExecutionEvidence, ...]:
        return tuple(self._execution_evidence)

    @property
    def host_write_evidence(self) -> tuple[HostWriteEvidence, ...]:
        return tuple(self._host_write_evidence)

    def probe(self) -> VirtualizationAvailability:
        try:
            availability = self.provider.probe()
        except Exception:
            return VirtualizationAvailability.UNAVAILABLE
        return (
            availability
            if isinstance(availability, VirtualizationAvailability)
            else VirtualizationAvailability.UNAVAILABLE
        )

    def route(self, intent: ExecutionIntent) -> RouteDecision:
        return self.router.route(intent)

    async def execute_guest(
        self,
        task_id: UUID,
        intent: ExecutionIntent,
        command: GuestCommand,
    ) -> VMExecutionEvidence:
        """Route and execute one bounded typed command with no host fallback."""

        route = self.route(intent)
        if route.environment not in {
            EnvironmentKind.WORKBENCH_VM,
            EnvironmentKind.DISPOSABLE_TEST_VM,
            EnvironmentKind.DISPOSABLE_REPAIR_VM,
        }:
            raise ValueError("guest execution requires a VM route")
        self._validate_guest_command(command)
        availability = self.probe()
        if availability is not VirtualizationAvailability.AVAILABLE:
            evidence = self._unavailable_evidence(
                task_id,
                intent,
                route,
                command.request_id,
                f"vm_provider_{availability.value}",
            )
            self._execution_evidence.append(evidence)
            raise VMExecutionUnavailable(evidence)

        instance: Instance | None = None
        disposable = route.environment in {
            EnvironmentKind.DISPOSABLE_TEST_VM,
            EnvironmentKind.DISPOSABLE_REPAIR_VM,
        }
        try:
            instance = await self._ensure_instance(route.environment, task_id)
            ready = await self._ensure_ready(instance)
            result = await self.provider.execute(ready.instance_id, command)
            evidence = self._result_evidence(task_id, intent, route, ready, result)
        except (OSError, KeyError, RuntimeError, TimeoutError, ValueError) as error:
            if instance is not None and disposable:
                await self._cleanup_disposable(instance.instance_id)
            evidence = self._unavailable_evidence(
                task_id,
                intent,
                route,
                command.request_id,
                "vm_execution_unavailable",
            )
            self._execution_evidence.append(evidence)
            del error
            raise VMExecutionUnavailable(evidence) from None
        if disposable:
            try:
                await self._cleanup_disposable(instance.instance_id)
            except (OSError, KeyError, RuntimeError, TimeoutError, ValueError):
                evidence = replace(
                    evidence,
                    status="failed",
                    error_code="disposable_cleanup_failed",
                )
                self._execution_evidence.append(evidence)
                raise VMExecutionError("disposable VM cleanup failed") from None
        self._execution_evidence.append(evidence)
        return evidence

    async def execute_host_write(
        self,
        task_id: UUID,
        intent: ExecutionIntent,
        relative_path: str,
        content: str,
        receipt: AuthorizationReceipt,
        normalized_arguments: Mapping[str, object],
        *,
        tool_id: str,
        action: str,
    ) -> HostWriteEvidence:
        """Perform one exact acceptance-owned host write after broker approval."""

        route = self.route(intent)
        if route.environment is not EnvironmentKind.HOST:
            raise ValueError("host write requires an explicit host route")
        target = self.host_resource(relative_path)
        if type(content) is not str or len(content) > 4_096:
            raise ValueError("host content is not bounded")
        approval_identity = self._approval_identity(receipt)
        request = HostBridgeRequest(
            request_id=uuid4(),
            task_id=task_id,
            instance_id=self.host_instance_id,
            operation=HostBridgeOperation.FILE_WRITE,
            resource=str(target),
            scope=str(self.host_root),
            risk="medium",
            expires_at=receipt.expires_at,
            tool_id=tool_id,
            action=action,
            argument_fingerprint=receipt.argument_fingerprint,
            action_fingerprint=receipt.action_fingerprint,
            approval_identity=approval_identity,
        )
        authorization = self.host_bridge.authorize_with_receipt(
            request,
            receipt=receipt,
            broker=self.permission_broker,
            normalized_arguments=normalized_arguments,
            expected_instance_id=self.host_instance_id,
        )
        if not authorization.allowed:
            evidence = HostWriteEvidence(
                task_id,
                route,
                request,
                authorization,
                str(target),
                str(self.host_root),
                0,
                "",
                False,
            )
            self._host_write_evidence.append(evidence)
            return evidence
        if target.exists() or target.is_symlink():
            raise VMExecutionError("host acceptance target already exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="")
        observed = target.read_text(encoding="utf-8")
        verified = observed == content
        if not verified:
            raise VMExecutionError("host post-effect verification failed")
        digest = hashlib.sha256(observed.encode("utf-8")).hexdigest()
        evidence = HostWriteEvidence(
            task_id,
            route,
            request,
            authorization,
            str(target),
            str(self.host_root),
            len(observed.encode("utf-8")),
            digest,
            verified,
        )
        self._host_write_evidence.append(evidence)
        return evidence

    def host_resource(self, relative_path: str) -> Path:
        if (
            type(relative_path) is not str
            or not relative_path
            or len(relative_path) > 256
            or relative_path != relative_path.strip()
            or "\\" in relative_path
            or any(character in relative_path for character in ("*", "?", ":"))
        ):
            raise ValueError("host resource must be a narrow relative path")
        candidate = Path(relative_path)
        if candidate.is_absolute() or any(part in {".", ".."} for part in candidate.parts):
            raise ValueError("host resource traversal is not permitted")
        target = (self.host_root / candidate).resolve(strict=False)
        try:
            target.relative_to(self.host_root)
        except ValueError as error:
            raise ValueError("host resource escapes the acceptance root") from error
        cursor = self.host_root
        for part in candidate.parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError("host resource contains a symlink")
        if target.is_symlink():
            raise ValueError("host resource is a symlink")
        return target

    async def aclose(self) -> None:
        """Close the coordinator without destroying the persistent Workbench."""

    async def _ensure_instance(self, purpose: EnvironmentKind, task_id: UUID) -> Instance:
        if purpose is EnvironmentKind.WORKBENCH_VM:
            instances = await self.provider.instances()
            existing = next(
                (
                    item
                    for item in instances
                    if item.template_id == self.WORKBENCH_TEMPLATE_ID
                    and item.provider == self.provider.name
                    and item.purpose is EnvironmentKind.WORKBENCH_VM
                    and item.metadata_tag == "jarvis-owned"
                    and item.state is not InstanceState.DESTROYED
                ),
                None,
            )
            if existing is not None:
                return existing
            return await self.fabric.create(self._template(purpose), task_id=None)
        if purpose in {
            EnvironmentKind.DISPOSABLE_TEST_VM,
            EnvironmentKind.DISPOSABLE_REPAIR_VM,
        }:
            return await self._create_disposable(purpose, task_id)
        raise ValueError("unsupported VM purpose")

    async def _ensure_ready(self, instance: Instance) -> Instance:
        if instance.state is InstanceState.READY:
            return instance
        return await self.fabric.start_ready(instance.instance_id)

    async def _create_disposable(self, purpose: EnvironmentKind, task_id: UUID) -> Instance:
        provider = cast(Any, self.provider)
        if callable(getattr(provider, "export", None)) and callable(
            getattr(provider, "import_clone", None)
        ):
            source = await self._ensure_instance(EnvironmentKind.WORKBENCH_VM, task_id)
            source_was_ready = source.state is InstanceState.READY
            if source_was_ready:
                await self.provider.stop(source.instance_id)
            clone_name = f"jarvis-r1-{purpose.value}-{uuid4().hex[:12]}"
            clone_root = self.state_root / "disposable" / clone_name
            archive = self.state_root / "disposable" / f"{clone_name}.tar"
            clone_root.parent.mkdir(parents=True, exist_ok=True)
            template = self._template(purpose, template_id=clone_name)
            try:
                await provider.export(source.instance_id, archive)
                created = cast(
                    Instance,
                    await provider.import_clone(
                        source.instance_id,
                        clone_name,
                        clone_root,
                        archive,
                        template,
                        owner_task_id=task_id,
                    ),
                )
            finally:
                archive.unlink(missing_ok=True)
                if source_was_ready:
                    await self.fabric.start_ready(source.instance_id)
            return created
        created = await self.fabric.create(self._template(purpose), task_id=task_id)
        return created

    async def _cleanup_disposable(self, instance_id: UUID) -> None:
        await self.fabric.cleanup_disposable(instance_id)

    def _template(self, purpose: EnvironmentKind, *, template_id: str | None = None) -> Template:
        is_workbench = purpose is EnvironmentKind.WORKBENCH_VM
        return Template(
            template_id or self.WORKBENCH_TEMPLATE_ID,
            self.provider.name,
            "linux",
            "x86_64",
            self._WORKBENCH_BASE_IMAGE,
            purpose,
            NetworkPolicy.INTERNET_ONLY if is_workbench else NetworkPolicy.NO_NETWORK,
            trusted=True,
        )

    def _result_evidence(
        self,
        task_id: UUID,
        intent: ExecutionIntent,
        route: RouteDecision,
        instance: Instance,
        result: GuestResult,
    ) -> VMExecutionEvidence:
        return VMExecutionEvidence(
            task_id,
            intent,
            route,
            self.provider.name,
            instance.instance_id,
            instance.purpose,
            result.request_id,
            True,
            "completed",
            result.exit_code,
            result.stdout[:4_000],
            result.stderr[:4_000],
            result.timed_out,
            result.cancelled,
            result.evidence_digest,
            (),
            None,
        )

    def _unavailable_evidence(
        self,
        task_id: UUID,
        intent: ExecutionIntent,
        route: RouteDecision,
        request_id: UUID,
        error_code: str,
    ) -> VMExecutionEvidence:
        return VMExecutionEvidence(
            task_id,
            intent,
            route,
            self.provider.name,
            None,
            None,
            request_id,
            False,
            "unavailable",
            None,
            "",
            "",
            False,
            False,
            "",
            (),
            error_code,
        )

    @classmethod
    def _validate_guest_command(cls, command: GuestCommand) -> None:
        if command.executable not in cls._SAFE_EXECUTABLES:
            raise ValueError("guest executable is outside the trusted VM command policy")
        for argument in command.args:
            if (
                not isinstance(argument, str)
                or any(character in argument for character in ("\x00", "\r", "\n"))
                or any(marker in argument for marker in ("/mnt/", "C:\\", "powershell", "wsl.exe"))
            ):
                raise ValueError("guest argument is outside the trusted VM command policy")

    @staticmethod
    def _approval_identity(receipt: AuthorizationReceipt) -> str | None:
        for request in receipt.approval_requests:
            if request.approval_identity is not None:
                return request.approval_identity
        for grant in receipt.remembered_grants:
            return grant.identity_id
        return None
