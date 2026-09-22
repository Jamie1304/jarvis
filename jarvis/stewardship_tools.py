"""Brokered, read-only stewardship observation for the canonical task path."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from jarvis.permissions.models import (
    ActionDescriptor,
    Permission,
    PermissionRequest,
    PermissionScope,
    Risk,
)
from jarvis.system_stewardship import SystemStewardshipCoordinator
from jarvis.tools.base import Tool
from jarvis.tools.models import (
    SemanticVersion,
    ToolEffectDisposition,
    ToolEvidence,
    ToolExecutionContext,
    ToolManifest,
    ToolPlatform,
    ToolResult,
    ToolResultStatus,
)


class StewardshipObservationInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class StewardshipObservationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    observation_id: str
    fingerprint: str
    lifecycle: str
    storage_pressure: tuple[tuple[str, str], ...]
    detected_bytes: int
    safe_candidate_bytes: int
    protected_bytes: int
    duplicate_scan_state: str
    security_state: str
    startup_state: str
    acquisition_states: tuple[str, ...]
    model_ids: tuple[str, ...]


class StewardshipObservationTool(Tool[StewardshipObservationInput, StewardshipObservationOutput]):
    """Expose only the coordinator's bounded projection after broker approval."""

    def __init__(
        self,
        coordinator: SystemStewardshipCoordinator,
        *,
        scope_paths: tuple[Path, ...],
    ) -> None:
        self._coordinator = coordinator
        self._scope_paths = tuple(scope_paths)

    @property
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool_id="stewardship.observe",
            name="Observe system stewardship",
            description="Observe bounded system, storage, acquisition, and model evidence.",
            version=SemanticVersion(1, 0, 0),
            capability_tags=frozenset({"stewardship", "system-health", "observation"}),
            input_schema=StewardshipObservationInput,
            output_schema=StewardshipObservationOutput,
            declared_permissions=frozenset({Permission.FILESYSTEM_READ}),
            supported_platforms=frozenset(
                {ToolPlatform.WINDOWS, ToolPlatform.LINUX, ToolPlatform.MACOS}
            ),
            timeout_seconds=30,
        )

    @property
    def input_model(self) -> type[StewardshipObservationInput]:
        return StewardshipObservationInput

    def _describe_action(
        self, context: ToolExecutionContext, value: StewardshipObservationInput
    ) -> ActionDescriptor:
        del context, value
        return ActionDescriptor(
            action="stewardship.observe",
            arguments_summary=(),
            risk=Risk.LOW,
            permissions=(
                PermissionRequest(
                    Permission.FILESYSTEM_READ,
                    PermissionScope(paths=tuple(str(path) for path in self._scope_paths)),
                ),
            ),
        )

    async def _execute_authorized(
        self, context: ToolExecutionContext, value: StewardshipObservationInput
    ) -> ToolResult:
        del context, value
        try:
            observation = await self._coordinator.observe()
            output = StewardshipObservationOutput(
                observation_id=str(observation.observation_id),
                fingerprint=observation.fingerprint,
                lifecycle=observation.lifecycle.value,
                storage_pressure=tuple(
                    (volume_id, state.value) for volume_id, state in observation.storage.pressure
                ),
                detected_bytes=observation.storage.detected_bytes,
                safe_candidate_bytes=observation.storage.safe_candidate_bytes,
                protected_bytes=observation.storage.protected_bytes,
                duplicate_scan_state=observation.storage.duplicate_scan_state,
                security_state=observation.system.security.overall.value,
                startup_state=observation.system.startup.overall.value,
                acquisition_states=tuple(
                    record.state.value for record in observation.acquisition_records
                ),
                model_ids=tuple(item.identity.storage_key for item in observation.models),
            )
        except Exception:
            return ToolResult.failure(
                ToolResultStatus.UNAVAILABLE,
                "stewardship_observation_unavailable",
                "Trusted stewardship observation is unavailable",
                effect_disposition=ToolEffectDisposition.NO_EFFECT,
            )
        return ToolResult(
            ToolResultStatus.SUCCESS,
            output=output,
            evidence=(
                ToolEvidence("stewardship.observed", "stewardship.observed"),
                ToolEvidence("stewardship.fingerprint", "stewardship.fingerprint"),
            ),
            effect_disposition=ToolEffectDisposition.NO_EFFECT,
        )


__all__ = [
    "StewardshipObservationInput",
    "StewardshipObservationOutput",
    "StewardshipObservationTool",
]
