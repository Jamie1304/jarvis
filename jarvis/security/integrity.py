"""Default-deny repository classification and mutation authorization."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from uuid import UUID, uuid4

from jarvis.security.models import (
    ClassifiedPath,
    IntegrityClass,
    MutationAuthority,
    MutationAuthorization,
    MutationAuthorizationSource,
    MutationContext,
    MutationDecision,
    MutationReason,
    MutationStage,
)
from jarvis.security.modification_policy import (
    ModificationTrustClassifier,
    ModificationTrustError,
    ModificationTrustLevel,
)

SECURITY_POLICY_VERSION = 1

_TRUSTED_CORE_TREES = (
    ".github/workflows",
    "jarvis/improvement",
    "jarvis/permissions",
    "jarvis/security",
    "tests/trusted_core",
)
_TRUSTED_CORE_FILES = frozenset(
    {
        "jarvis/api.py",
        "jarvis/bootstrap.py",
        "jarvis/core/config.py",
        "jarvis/core/health.py",
        "jarvis/runtime.py",
        "jarvis/recovery.py",
        "jarvis/task_controller.py",
        "jarvis/tools/__init__.py",
        "jarvis/tools/base.py",
        "jarvis/tools/models.py",
        "jarvis/tools/registry.py",
        "docs/security-constitution.md",
        ".env.example",
        "pyproject.toml",
        "requirements-dev.lock",
        "requirements.lock",
        "scripts/quality.py",
    }
)
_INTEGRATION_TREES = ("integrations",)
_GENERATED_TREES = ("generated", "knowledge/generated")
_INERT_ARTIFACT_SUFFIXES = frozenset({".csv", ".json", ".md", ".txt", ".yaml", ".yml"})
_USER_CONFIG_TREES = ("config",)
_USER_CONFIG_FILES = frozenset({".env", ".env.local"})
_DATA_TREES = (
    ".jarvis",
    "artifacts",
    "cache",
    "data",
    "logs",
    "models",
    "tmp",
)
_PRODUCTION_TREES = ("docs", "frontend", "jarvis", "scripts", "tests")
_PRODUCTION_FILES = frozenset({".gitignore", "contributing.md", "readme.md"})
_WINDOWS_RESERVED = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "conin$",
        "conout$",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_CONTROL_FILENAMES = frozenset(
    {
        ".coveragerc",
        ".gitmodules",
        ".pylintrc",
        ".ruff.toml",
        "cargo.lock",
        "cargo.toml",
        "environment.yaml",
        "environment.yml",
        "go.mod",
        "go.sum",
        "mypy.ini",
        "package-lock.json",
        "package.json",
        "pipfile",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pyproject.toml",
        "pytest.ini",
        "requirements-dev.lock",
        "requirements.lock",
        "requirements.txt",
        "ruff.toml",
        "setup.cfg",
        "setup.py",
        "sitecustomize.py",
        "tox.ini",
        "usercustomize.py",
        "uv.lock",
        "yarn.lock",
    }
)

type Clock = Callable[[], datetime]


class IntegrityClassificationError(ValueError):
    """A path cannot safely cross the trusted mutation boundary."""


class UnknownIntegrityPathError(IntegrityClassificationError):
    """A valid relative path is absent from the compiled integrity manifest."""


def normalize_repository_path(value: str) -> str:
    """Validate one unambiguous, platform-independent repository path."""

    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or value != value.strip()
        or len(value) > 1024
        or any(
            character in value
            for character in ("\x00", "\n", "\r", "\\", ":", "<", ">", '"', "|", "?", "*")
        )
        or any(ord(character) < 32 for character in value)
    ):
        raise IntegrityClassificationError("Repository path is malformed")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise IntegrityClassificationError("Repository path is ambiguous or not relative")
    for part in path.parts:
        stem = part.split(".", 1)[0].casefold()
        if part.endswith((" ", ".")) or stem in _WINDOWS_RESERVED:
            raise IntegrityClassificationError("Repository path is unsafe on Windows")
    return path.as_posix()


class RepositoryIntegrityClassifier:
    """Classify only explicit repository regions; unknown paths fail closed."""

    def classify(self, value: str) -> ClassifiedPath:
        path = normalize_repository_path(value)
        folded = path.casefold()
        if _matches_any(folded, _TRUSTED_CORE_TREES) or folded in _TRUSTED_CORE_FILES:
            return ClassifiedPath(path, IntegrityClass.TRUSTED_CORE, "trusted_core_manifest")
        if _control_file(PurePosixPath(folded).name):
            return ClassifiedPath(path, IntegrityClass.TRUSTED_CORE, "supply_chain_control")
        if _matches_any(folded, _INTEGRATION_TREES):
            if PurePosixPath(folded).suffix not in _INERT_ARTIFACT_SUFFIXES:
                raise IntegrityClassificationError(
                    "Integration artifacts must be inert in the v1 architecture"
                )
            return ClassifiedPath(path, IntegrityClass.INTEGRATION, "integration_tree")
        if _matches_any(folded, _GENERATED_TREES):
            if PurePosixPath(folded).suffix not in _INERT_ARTIFACT_SUFFIXES:
                raise IntegrityClassificationError("Generated artifacts must use an inert format")
            return ClassifiedPath(path, IntegrityClass.GENERATED, "non_executable_generated_tree")
        if folded in _USER_CONFIG_FILES or _matches_any(folded, _USER_CONFIG_TREES):
            return ClassifiedPath(path, IntegrityClass.USER_CONFIG, "operator_configuration")
        if _matches_any(folded, _DATA_TREES):
            return ClassifiedPath(path, IntegrityClass.DATA, "service_owned_data")
        if _matches_any(folded, _PRODUCTION_TREES) or folded in _PRODUCTION_FILES:
            return ClassifiedPath(path, IntegrityClass.PRODUCTION_CORE, "production_source")
        raise UnknownIntegrityPathError("Repository path is not in the integrity manifest")


class MutationAuthorizer:
    """Mint exact, expiring release records for one trusted composition instance."""

    def __init__(
        self,
        identity_id: str,
        source: MutationAuthorizationSource,
        *,
        ttl_seconds: int = 300,
        clock: Clock | None = None,
    ) -> None:
        if (
            type(identity_id) is not str
            or not identity_id
            or identity_id != identity_id.strip()
            or len(identity_id) > 256
            or not all(character.isprintable() for character in identity_id)
            or any(
                character in identity_id
                for character in (
                    "\u061c",
                    "\u200e",
                    "\u200f",
                    "\u202a",
                    "\u202b",
                    "\u202c",
                    "\u202d",
                    "\u202e",
                    "\u2066",
                    "\u2067",
                    "\u2068",
                    "\u2069",
                )
            )
            or not isinstance(source, MutationAuthorizationSource)
            or isinstance(ttl_seconds, bool)
            or not 1 <= ttl_seconds <= 600
        ):
            raise ValueError("Mutation authorizer identity and lifetime must be trusted")
        self._identity_id = identity_id
        self._source = source
        self._ttl_seconds = ttl_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._secret = secrets.token_bytes(32)
        self._issued: dict[UUID, MutationAuthorization] = {}

    def issue(
        self,
        *,
        authority: MutationAuthority,
        path: str,
        task_id: UUID,
        base_revision: str,
        candidate_revision: str,
        diff_digest: str,
        gate_report_digest: str,
    ) -> MutationAuthorization:
        classified = RepositoryIntegrityClassifier().classify(path)
        try:
            trust = ModificationTrustClassifier().classify((path,))
        except ModificationTrustError as error:
            raise ValueError(
                "Mutation authorization is outside the trusted release scope"
            ) from error
        if (
            authority is MutationAuthority.CONTROLLED_UPDATE
            and trust.level >= ModificationTrustLevel.PERMISSION_BROKER_SECURITY
        ):
            raise ValueError("Mutation authorization is outside the trusted release scope")
        if authority is MutationAuthority.OWNER_SECURITY_RELEASE:
            permitted = (
                self._source is MutationAuthorizationSource.OWNER_LOCAL_RELEASE
                and classified.integrity_class is IntegrityClass.TRUSTED_CORE
            )
        elif authority is MutationAuthority.CONTROLLED_UPDATE:
            permitted = classified.integrity_class in {
                IntegrityClass.PRODUCTION_CORE,
                IntegrityClass.INTEGRATION,
                IntegrityClass.GENERATED,
            }
        else:
            permitted = False
        if (
            not permitted
            or not isinstance(task_id, UUID)
            or not _revision(base_revision)
            or not _revision(candidate_revision)
            or not _digest(diff_digest)
            or not _digest(gate_report_digest)
        ):
            raise ValueError("Mutation authorization is outside the trusted release scope")
        issued_at = self._now()
        authorization_id = uuid4()
        expires_at = issued_at + timedelta(seconds=self._ttl_seconds)
        tag = self._tag(
            authorization_id,
            authority,
            classified.relative_path,
            task_id,
            base_revision,
            candidate_revision,
            diff_digest,
            gate_report_digest,
            issued_at,
            expires_at,
            self._identity_id,
            self._source,
        )
        authorization = MutationAuthorization(
            authorization_id=authorization_id,
            authority=authority,
            path=classified.relative_path,
            task_id=task_id,
            base_revision=base_revision,
            candidate_revision=candidate_revision,
            diff_digest=diff_digest,
            gate_report_digest=gate_report_digest,
            identity_id=self._identity_id,
            source=self._source,
            issued_at=issued_at,
            expires_at=expires_at,
            authentication_tag=tag,
        )
        self._issued[authorization_id] = authorization
        return authorization

    def consume(
        self,
        authorization: MutationAuthorization | None,
        context: MutationContext,
        path: str,
    ) -> bool:
        if (
            type(authorization) is not MutationAuthorization
            or type(context) is not MutationContext
            or type(path) is not str
            or self._issued.get(authorization.authorization_id) != authorization
        ):
            return False
        expected_tag = self._tag(
            authorization.authorization_id,
            authorization.authority,
            authorization.path,
            authorization.task_id,
            authorization.base_revision,
            authorization.candidate_revision,
            authorization.diff_digest,
            authorization.gate_report_digest,
            authorization.issued_at,
            authorization.expires_at,
            authorization.identity_id,
            authorization.source,
        )
        valid = (
            hmac.compare_digest(authorization.authentication_tag, expected_tag)
            and authorization.expires_at > self._now()
            and authorization.authority is context.authority
            and authorization.path == path
            and authorization.task_id == context.task_id
            and authorization.base_revision == context.base_revision
            and authorization.candidate_revision == context.candidate_revision
            and authorization.diff_digest == context.diff_digest
            and authorization.gate_report_digest == context.gate_report_digest
        )
        if not valid:
            return False
        del self._issued[authorization.authorization_id]
        return True

    def _tag(
        self,
        authorization_id: UUID,
        authority: MutationAuthority,
        path: str,
        task_id: UUID,
        base_revision: str,
        candidate_revision: str,
        diff_digest: str,
        gate_report_digest: str,
        issued_at: datetime,
        expires_at: datetime,
        identity_id: str,
        source: MutationAuthorizationSource,
    ) -> str:
        payload = json.dumps(
            {
                "authorization_id": str(authorization_id),
                "authority": authority.value,
                "base_revision": base_revision,
                "candidate_revision": candidate_revision,
                "diff_digest": diff_digest,
                "expires_at": expires_at.isoformat(),
                "gate_report_digest": gate_report_digest,
                "identity_id": identity_id,
                "issued_at": issued_at.isoformat(),
                "path": path,
                "source": source.value,
                "task_id": str(task_id),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("Mutation authorizer clock must be timezone-aware")
        return value.astimezone(UTC)


class MutationPolicy:
    """Authorize mutations independently of model risk labels and specifications."""

    def __init__(
        self,
        authorizer: MutationAuthorizer | None = None,
    ) -> None:
        if authorizer is not None and type(authorizer) is not MutationAuthorizer:
            raise ValueError("Mutation policy requires the exact trusted authorizer type")
        self._classifier = RepositoryIntegrityClassifier()
        self._authorizer = authorizer

    def evaluate(self, path: str, context: MutationContext | object) -> MutationDecision:
        try:
            classified = self._classifier.classify(path)
        except UnknownIntegrityPathError:
            return MutationDecision(False, MutationReason.UNKNOWN_PATH, None)
        except IntegrityClassificationError:
            return MutationDecision(False, MutationReason.MALFORMED_PATH, None)
        if (
            not isinstance(context, MutationContext)
            or not isinstance(context.authority, MutationAuthority)
            or not isinstance(context.stage, MutationStage)
            or not isinstance(context.full_gates_passed, bool)
            or context.authorization is not None
            and type(context.authorization) is not MutationAuthorization
        ):
            return MutationDecision(False, MutationReason.MALFORMED_CONTEXT, classified)

        try:
            trust = ModificationTrustClassifier().classify((classified.relative_path,))
        except ModificationTrustError:
            return MutationDecision(False, MutationReason.MALFORMED_PATH, classified)
        integrity_class = classified.integrity_class
        if (
            trust.level >= ModificationTrustLevel.PERMISSION_BROKER_SECURITY
            and integrity_class is not IntegrityClass.TRUSTED_CORE
        ):
            return MutationDecision(
                False,
                MutationReason.TRUSTED_CORE_OWNER_RELEASE_REQUIRED,
                classified,
            )
        if integrity_class is IntegrityClass.TRUSTED_CORE:
            if self._authorized_release(context, classified.relative_path):
                return MutationDecision(True, MutationReason.OWNER_RELEASE_ALLOWED, classified)
            return MutationDecision(
                False,
                MutationReason.TRUSTED_CORE_OWNER_RELEASE_REQUIRED,
                classified,
            )

        if context.stage is MutationStage.ISOLATED_PROPOSAL:
            if context.authorization is not None:
                return MutationDecision(False, MutationReason.MALFORMED_CONTEXT, classified)
            if integrity_class in {
                IntegrityClass.PRODUCTION_CORE,
                IntegrityClass.INTEGRATION,
                IntegrityClass.GENERATED,
            }:
                return MutationDecision(
                    True,
                    MutationReason.ISOLATED_CANDIDATE_ALLOWED,
                    classified,
                )
            return MutationDecision(False, MutationReason.CLASS_NOT_MUTABLE, classified)

        if context.authority is MutationAuthority.ROUTINE_IMPROVEMENT:
            return MutationDecision(False, MutationReason.ROUTINE_SCOPE_DENIED, classified)

        if context.authority is MutationAuthority.CONTROLLED_UPDATE:
            if integrity_class in {
                IntegrityClass.PRODUCTION_CORE,
                IntegrityClass.INTEGRATION,
                IntegrityClass.GENERATED,
            }:
                if self._authorized_release(context, classified.relative_path):
                    return MutationDecision(
                        True,
                        MutationReason.CONTROLLED_UPDATE_ALLOWED,
                        classified,
                    )
                if not context.full_gates_passed:
                    return MutationDecision(
                        False,
                        MutationReason.PRODUCTION_GATES_REQUIRED,
                        classified,
                    )
                return MutationDecision(
                    False,
                    MutationReason.OWNER_AUTHORIZATION_REQUIRED,
                    classified,
                )
        return MutationDecision(False, MutationReason.CLASS_NOT_MUTABLE, classified)

    def _authorized_release(self, context: MutationContext, path: str) -> bool:
        return bool(
            context.stage is MutationStage.PRODUCTION_APPLY
            and context.full_gates_passed
            and self._authorizer is not None
            and self._authorizer.consume(context.authorization, context, path)
        )


def _matches_any(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(f"{root}/") for root in roots)


def _control_file(filename: str) -> bool:
    return (
        filename in _CONTROL_FILENAMES
        or filename.startswith("requirements")
        and filename.endswith((".in", ".lock", ".txt"))
        or filename.startswith("constraints")
        and filename.endswith((".in", ".txt"))
    )


def _revision(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) in {40, 64}
        and all(character in "0123456789abcdef" for character in value)
    )


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
