"""Encrypted user-facing backup, export, restore, and migration contracts.

Backup is deliberately separate from ``jarvis.recovery``.  Recovery owns the
technical last-known-good startup point; this module owns portable, user-
selected data bundles and restore planning.  Component providers and appliers
remain owned by their domain services and are injected through this boundary.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import tempfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import cast
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class BackupError(RuntimeError):
    """Base class for safe backup/export/restore failures."""


class BackupIntegrityError(BackupError):
    """The bundle was tampered with, truncated, or decrypted with the wrong key."""


class BackupCompatibilityError(BackupError):
    """The bundle format is unsupported or from the future."""


class BackupReauthorizationRequired(BackupError):
    """A machine-bound or credential-referencing component needs reauthorization."""


class BackupRecertificationRequired(BackupError):
    """A generated integration cannot be activated without new certification."""


class BackupMigrationRequired(BackupError):
    """A component needs an explicit version migration before restore."""


class BackupRelinkRequired(BackupError):
    """An external knowledge or workspace path must be explicitly relinked."""


class BackupRestoreError(BackupError):
    """Restore failed; the attached report describes migration and rollback state."""

    def __init__(self, message: str, *, report: MigrationReport | None = None) -> None:
        super().__init__(message)
        self.report = report


class BackupComponentType(StrEnum):
    SETTINGS_PRIVACY = "settings_privacy"
    WORKSPACES = "workspaces"
    USER_MODEL_MEMORY = "user_model_memory"
    KNOWLEDGE_METADATA_INDEXES = "knowledge_metadata_indexes"
    SKILLS = "skills"
    WORKFLOW_TEMPLATES = "workflow_templates"
    AUTOMATIONS = "automations"
    ARTIFACTS = "artifacts"
    GENERATED_INTEGRATIONS = "generated_integrations"
    CERTIFICATIONS = "certifications"
    CAPABILITY_METADATA = "capability_metadata"
    UI = "ui"
    CONFIGURATION = "configuration"
    MODEL_FILES = "model_files"
    GENERATED_CACHES = "generated_caches"


class BackupClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    CONFIDENTIAL = "confidential"


class RestoreMode(StrEnum):
    SELECTIVE = "selective"
    FULL = "full"


CURRENT_BACKUP_FORMAT = 1
_MAX_TEXT = 512
_MAX_COMPONENT_BYTES = 64 * 1024 * 1024
_MAX_BUNDLE_BYTES = 128 * 1024 * 1024
_PBKDF2_ITERATIONS = 600_000
_SALT_BYTES = 16
_NONCE_BYTES = 12
_KEY_BYTES = 32
_DEFAULT_COMPONENTS = (
    BackupComponentType.SETTINGS_PRIVACY.value,
    BackupComponentType.WORKSPACES.value,
    BackupComponentType.USER_MODEL_MEMORY.value,
    BackupComponentType.KNOWLEDGE_METADATA_INDEXES.value,
    BackupComponentType.SKILLS.value,
    BackupComponentType.WORKFLOW_TEMPLATES.value,
    BackupComponentType.AUTOMATIONS.value,
    BackupComponentType.CAPABILITY_METADATA.value,
    BackupComponentType.UI.value,
    BackupComponentType.CONFIGURATION.value,
)
_FORBIDDEN_COMPONENT_IDS = frozenset({"credentials", "credential_vault", "raw_secrets", "secrets"})


@dataclass(frozen=True, slots=True)
class BackupComponent:
    """A selected, non-secret payload supplied by one authoritative domain."""

    component_id: str
    version: str
    payload: bytes
    source_reference: str = ""
    classification: BackupClassification = BackupClassification.INTERNAL
    external_paths: tuple[str, ...] = ()
    credential_references: tuple[str, ...] = ()
    machine_bound: bool = False
    requires_recertification: bool = False
    is_cache: bool = False
    is_model_file: bool = False

    def __post_init__(self) -> None:
        _text(self.component_id, "component_id")
        if self.component_id.casefold() in _FORBIDDEN_COMPONENT_IDS:
            raise BackupError("Credential secrets cannot be backup components")
        _text(self.version, "component version")
        if type(self.payload) is not bytes or len(self.payload) > _MAX_COMPONENT_BYTES:
            raise BackupError("Backup component payload is invalid or too large")
        _text(self.source_reference, "source_reference", allow_empty=True)
        if not isinstance(self.classification, BackupClassification):
            raise BackupError("Backup classification is invalid")
        if type(self.machine_bound) is not bool or type(self.requires_recertification) is not bool:
            raise BackupError("Backup component security metadata is invalid")
        if type(self.is_cache) is not bool or type(self.is_model_file) is not bool:
            raise BackupError("Backup component cache metadata is invalid")
        _text_sequence(self.external_paths, "external_paths", max_items=64)
        _text_sequence(self.credential_references, "credential_references", max_items=64)
        if self.classification.value.casefold() in {"credential_secret", "secret"}:
            raise BackupError("Credential secrets cannot be backup components")

    @property
    def requires_reauthorization(self) -> bool:
        return self.machine_bound or bool(self.credential_references)


@dataclass(frozen=True, slots=True)
class BackupComponentInfo:
    """Manifest metadata; payload bytes remain inside authenticated ciphertext."""

    component_id: str
    version: str
    size_bytes: int
    sha256: str
    source_reference: str
    classification: BackupClassification
    external_paths: tuple[str, ...]
    credential_references: tuple[str, ...]
    machine_bound: bool
    requires_reauthorization: bool
    requires_recertification: bool
    is_cache: bool
    is_model_file: bool


@dataclass(frozen=True, slots=True)
class BackupManifest:
    format_version: int
    bundle_id: UUID
    created_at: datetime
    source_installation_id: str | None
    components: tuple[BackupComponentInfo, ...]
    encrypted: bool = True

    def __post_init__(self) -> None:
        if type(self.format_version) is not int or self.format_version < 1:
            raise BackupCompatibilityError("Backup format version is invalid")
        if not isinstance(self.bundle_id, UUID):
            raise BackupError("Backup bundle ID is invalid")
        _utc(self.created_at, "Backup timestamp")
        if self.source_installation_id is not None:
            _text(self.source_installation_id, "source_installation_id")
        if type(self.encrypted) is not bool or not self.encrypted:
            raise BackupError("User-facing backups must be encrypted")
        if len(self.components) > 128 or not isinstance(self.components, tuple):
            raise BackupError("Backup component manifest is invalid")
        identifiers = [component.component_id for component in self.components]
        if len(identifiers) != len(set(identifiers)):
            raise BackupError("Backup component identifiers collide")


@dataclass(frozen=True, slots=True)
class MigrationReport:
    source_format_version: int
    target_format_version: int
    migrated_components: tuple[str, ...] = ()
    skipped_components: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    success: bool = True

    def __post_init__(self) -> None:
        for value, label in (
            (self.source_format_version, "source format version"),
            (self.target_format_version, "target format version"),
        ):
            if type(value) is not int or value < 0:
                raise BackupError(f"{label} is invalid")
        for values, label in (
            (self.migrated_components, "migrated_components"),
            (self.skipped_components, "skipped_components"),
            (self.warnings, "migration warnings"),
            (self.errors, "migration errors"),
        ):
            _text_sequence(values, label, max_items=128)


@dataclass(frozen=True, slots=True)
class BackupBundle:
    path: Path
    manifest: BackupManifest
    payloads: tuple[tuple[str, bytes], ...]
    migration_report: MigrationReport

    def payload(self, component_id: str) -> bytes:
        for identifier, payload in self.payloads:
            if identifier == component_id:
                return payload
        raise KeyError(component_id)


@dataclass(frozen=True, slots=True)
class BackupPolicy:
    """Explicit component selection; model files/caches are opt-in."""

    selected_components: tuple[str, ...] = _DEFAULT_COMPONENTS
    include_model_files: bool = False
    include_caches: bool = False
    max_component_bytes: int = _MAX_COMPONENT_BYTES
    max_bundle_bytes: int = _MAX_BUNDLE_BYTES

    def __post_init__(self) -> None:
        _text_sequence(self.selected_components, "selected_components", max_items=128)
        if len(set(self.selected_components)) != len(self.selected_components):
            raise BackupError("Backup component selection contains duplicates")
        if type(self.include_model_files) is not bool or type(self.include_caches) is not bool:
            raise BackupError("Backup policy flags are invalid")
        if not 1 <= self.max_component_bytes <= _MAX_COMPONENT_BYTES:
            raise BackupError("Backup component limit is invalid")
        if not 1 <= self.max_bundle_bytes <= _MAX_BUNDLE_BYTES:
            raise BackupError("Backup bundle limit is invalid")

    def selects(self, component: BackupComponent) -> bool:
        if component.component_id not in self.selected_components:
            return False
        if component.is_model_file and not self.include_model_files:
            return False
        if component.is_cache and not self.include_caches:
            return False
        return len(component.payload) <= self.max_component_bytes


@dataclass(frozen=True, slots=True)
class RestorePlan:
    bundle_id: UUID
    mode: RestoreMode
    selected_components: tuple[str, ...]
    conflicts: tuple[str, ...]
    reauthorization_required: tuple[str, ...]
    recertification_required: tuple[str, ...]
    relink_required: tuple[str, ...]
    migration_required: tuple[str, ...]
    destructive: bool
    requires_snapshot: bool
    compatible: bool
    source_installation_id: str | None
    target_installation_id: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.bundle_id, UUID) or not isinstance(self.mode, RestoreMode):
            raise BackupError("Restore plan identity is invalid")
        for values, label in (
            (self.selected_components, "selected_components"),
            (self.conflicts, "conflicts"),
            (self.reauthorization_required, "reauthorization_required"),
            (self.recertification_required, "recertification_required"),
            (self.relink_required, "relink_required"),
            (self.migration_required, "migration_required"),
        ):
            _text_sequence(values, label, max_items=128)
        if type(self.destructive) is not bool or type(self.requires_snapshot) is not bool:
            raise BackupError("Restore plan security flags are invalid")


ComponentProvider = Callable[[], BackupComponent]
ComponentApplier = Callable[[str, bytes], None]
SnapshotCallback = Callable[[RestorePlan], object]
RollbackCallback = Callable[[object], None]
AuthorizationCallback = Callable[[BackupComponentInfo], bool]
RelinkCallback = Callable[[BackupComponentInfo], bool]
MigrationCallback = Callable[[BackupComponentInfo, bytes], bytes]
ConflictCallback = Callable[[BackupComponentInfo], bool]


class BackupService:
    """Portable encrypted bundle owner with explicit domain callback boundaries."""

    def __init__(
        self,
        root: Path,
        *,
        installation_id: str | None = None,
        component_sources: Mapping[str, ComponentProvider] | None = None,
        component_appliers: Mapping[str, ComponentApplier] | None = None,
    ) -> None:
        self._root = _safe_directory(root)
        self._installation_id = (
            _text(installation_id, "installation_id")
            if installation_id is not None
            else _load_or_create_installation_id(self._root)
        )
        self._sources = dict(component_sources or {})
        self._appliers = dict(component_appliers or {})
        self._last_report: MigrationReport | None = None

    @property
    def installation_id(self) -> str:
        return self._installation_id

    @property
    def last_migration_report(self) -> MigrationReport | None:
        return self._last_report

    def register_component_source(self, component_id: str, provider: ComponentProvider) -> None:
        _text(component_id, "component_id")
        if not callable(provider):
            raise BackupError("Backup component provider is invalid")
        self._sources[component_id] = provider

    def register_component_applier(self, component_id: str, applier: ComponentApplier) -> None:
        _text(component_id, "component_id")
        if not callable(applier):
            raise BackupError("Backup component applier is invalid")
        self._appliers[component_id] = applier

    def collect(self, policy: BackupPolicy | None = None) -> tuple[BackupComponent, ...]:
        selected = policy or BackupPolicy()
        components: list[BackupComponent] = []
        for identifier, provider in self._sources.items():
            component = provider()
            if not isinstance(component, BackupComponent) or component.component_id != identifier:
                raise BackupError("Backup provider returned an invalid component")
            if selected.selects(component):
                components.append(component)
        return tuple(components)

    def create_bundle(
        self,
        path: Path,
        *,
        password: str,
        components: Iterable[BackupComponent] | None = None,
        policy: BackupPolicy | None = None,
        source_installation_id: str | None = None,
        overwrite: bool = False,
    ) -> BackupBundle:
        selected_policy = policy or BackupPolicy()
        source = tuple(components) if components is not None else self.collect(selected_policy)
        selected: list[BackupComponent] = []
        seen: set[str] = set()
        for component in source:
            if not isinstance(component, BackupComponent):
                raise BackupError("Backup component is invalid")
            if component.component_id in seen:
                raise BackupError("Backup component identifiers collide")
            seen.add(component.component_id)
            if selected_policy.selects(component):
                selected.append(component)
        if source_installation_id is None:
            source_installation_id = self._installation_id
        _text(source_installation_id, "source_installation_id")
        manifest = BackupManifest(
            CURRENT_BACKUP_FORMAT,
            uuid4(),
            datetime.now(UTC),
            source_installation_id,
            tuple(_component_info(component) for component in selected),
        )
        payloads = tuple((component.component_id, component.payload) for component in selected)
        encoded = _encode_bundle(manifest, payloads, password)
        if len(encoded) > selected_policy.max_bundle_bytes:
            raise BackupError("Backup bundle exceeds the configured size limit")
        destination = _safe_destination(path, overwrite=overwrite)
        _atomic_write(destination, encoded)
        report = MigrationReport(CURRENT_BACKUP_FORMAT, CURRENT_BACKUP_FORMAT)
        bundle = BackupBundle(destination, manifest, payloads, report)
        self._last_report = report
        return bundle

    export = create_bundle

    def open_bundle(self, path: Path, *, password: str) -> BackupBundle:
        source = path.expanduser()
        try:
            _assert_no_reparse_path(source)
        except BackupError as error:
            raise BackupIntegrityError("Backup bundle path is unsafe or unavailable") from error
        if source.is_symlink() or source.is_junction() or not source.is_file():
            raise BackupIntegrityError("Backup bundle path is unsafe or unavailable")
        if source.stat().st_size > _MAX_BUNDLE_BYTES:
            raise BackupIntegrityError("Backup bundle exceeds the size limit")
        try:
            envelope = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise BackupIntegrityError("Backup bundle envelope is malformed") from error
        plaintext, envelope_version = _decrypt_envelope(envelope, password)
        manifest_raw, payload_raw = _decode_inner(plaintext)
        manifest, report = _manifest_from_raw(manifest_raw, envelope_version)
        payloads = _payloads_from_raw(manifest, payload_raw)
        bundle = BackupBundle(source.resolve(), manifest, payloads, report)
        self._last_report = report
        return bundle

    import_bundle = open_bundle

    def preview_restore(
        self,
        bundle: BackupBundle,
        *,
        selected_components: Iterable[str] | None = None,
        current_installation_id: str | None = None,
        existing_components: Mapping[str, BackupComponentInfo | BackupComponent] | None = None,
        path_exists: Callable[[str], bool] | None = None,
    ) -> RestorePlan:
        if not isinstance(bundle, BackupBundle):
            raise BackupError("Restore requires an authenticated BackupBundle")
        target_id = current_installation_id or self._installation_id
        _text(target_id, "target_installation_id")
        available = {item.component_id: item for item in bundle.manifest.components}
        requested = (
            tuple(selected_components) if selected_components is not None else tuple(available)
        )
        _text_sequence(requested, "selected_components", max_items=128)
        if any(identifier not in available for identifier in requested):
            raise BackupError("Restore selected an unknown component")
        existing = existing_components or {}
        conflicts: list[str] = []
        reauthorization: list[str] = []
        recertification: list[str] = []
        relink: list[str] = []
        migration: list[str] = []
        for identifier in requested:
            info = available[identifier]
            current = existing.get(identifier)
            if current is not None:
                current_version = current.version
                current_hash = (
                    hashlib.sha256(current.payload).hexdigest()
                    if isinstance(current, BackupComponent)
                    else current.sha256
                )
                if current_version != info.version or current_hash != info.sha256:
                    conflicts.append(identifier)
                if current_version != info.version:
                    migration.append(identifier)
            if (
                info.requires_reauthorization
                or info.machine_bound
                or bool(info.credential_references)
            ) and bundle.manifest.source_installation_id != target_id:
                reauthorization.append(identifier)
            if (
                info.requires_recertification
                or info.component_id == BackupComponentType.GENERATED_INTEGRATIONS.value
            ) and bundle.manifest.source_installation_id != target_id:
                recertification.append(identifier)
            if info.external_paths:
                if path_exists is None or any(
                    not path_exists(value) for value in info.external_paths
                ):
                    relink.append(identifier)
        mode = RestoreMode.FULL if len(requested) == len(available) else RestoreMode.SELECTIVE
        destructive = bool(existing) or bool(conflicts)
        return RestorePlan(
            bundle.manifest.bundle_id,
            mode,
            requested,
            tuple(conflicts),
            tuple(reauthorization),
            tuple(recertification),
            tuple(relink),
            tuple(migration),
            destructive,
            destructive,
            True,
            bundle.manifest.source_installation_id,
            target_id,
        )

    def restore(
        self,
        bundle: BackupBundle,
        *,
        selected_components: Iterable[str] | None = None,
        current_installation_id: str | None = None,
        existing_components: Mapping[str, BackupComponentInfo | BackupComponent] | None = None,
        path_exists: Callable[[str], bool] | None = None,
        reauthorize: AuthorizationCallback | None = None,
        recertify: AuthorizationCallback | None = None,
        relink: RelinkCallback | None = None,
        migrate: MigrationCallback | None = None,
        resolve_conflict: ConflictCallback | None = None,
        snapshot: SnapshotCallback | None = None,
        rollback: RollbackCallback | None = None,
        apply: ComponentApplier | None = None,
    ) -> tuple[RestorePlan, MigrationReport]:
        plan = self.preview_restore(
            bundle,
            selected_components=selected_components,
            current_installation_id=current_installation_id,
            existing_components=existing_components,
            path_exists=path_exists,
        )
        infos = {item.component_id: item for item in bundle.manifest.components}
        for identifier in plan.reauthorization_required:
            if reauthorize is None or not reauthorize(infos[identifier]):
                raise BackupReauthorizationRequired(f"Reauthorization required for {identifier}")
        for identifier in plan.recertification_required:
            if recertify is None or not recertify(infos[identifier]):
                raise BackupRecertificationRequired(f"Recertification required for {identifier}")
        for identifier in plan.relink_required:
            if relink is None or not relink(infos[identifier]):
                raise BackupRelinkRequired(f"External source relink required for {identifier}")
        for identifier in plan.conflicts:
            if resolve_conflict is None or not resolve_conflict(infos[identifier]):
                raise BackupError(f"Restore conflict was not explicitly resolved for {identifier}")
        report = bundle.migration_report
        migrated: list[str] = list(report.migrated_components)
        applier = apply
        snapshot_token: object | None = None
        if plan.requires_snapshot:
            if snapshot is None or rollback is None:
                raise BackupRestoreError(
                    "Destructive restore requires technical snapshot and rollback callbacks",
                    report=report,
                )
            snapshot_token = snapshot(plan)
        try:
            for identifier in plan.selected_components:
                payload = bundle.payload(identifier)
                info = infos[identifier]
                if identifier in plan.migration_required:
                    if migrate is None:
                        raise BackupMigrationRequired(
                            f"Migration required before restoring {identifier}"
                        )
                    payload = migrate(info, payload)
                    if type(payload) is not bytes or len(payload) > _MAX_COMPONENT_BYTES:
                        raise BackupError("Migrated component payload is invalid")
                    migrated.append(identifier)
                handler = applier or self._appliers.get(identifier)
                if handler is None:
                    raise BackupError(f"No trusted applier registered for {identifier}")
                handler(identifier, payload)
        except BackupError as error:
            failed = MigrationReport(
                report.source_format_version,
                CURRENT_BACKUP_FORMAT,
                tuple(dict.fromkeys(migrated)),
                report.skipped_components,
                report.warnings,
                (*report.errors, str(error)),
                False,
            )
            self._last_report = failed
            if snapshot_token is not None and rollback is not None:
                try:
                    rollback(snapshot_token)
                except Exception as rollback_error:
                    raise BackupRestoreError(
                        "Restore failed and technical rollback also failed", report=failed
                    ) from rollback_error
            raise BackupRestoreError(
                "Restore failed; rollback completed where available", report=failed
            ) from error
        except Exception as error:
            failed = MigrationReport(
                report.source_format_version,
                CURRENT_BACKUP_FORMAT,
                tuple(dict.fromkeys(migrated)),
                report.skipped_components,
                report.warnings,
                (*report.errors, type(error).__name__),
                False,
            )
            self._last_report = failed
            if snapshot_token is not None and rollback is not None:
                try:
                    rollback(snapshot_token)
                except Exception as rollback_error:
                    raise BackupRestoreError(
                        "Restore failed and technical rollback also failed", report=failed
                    ) from rollback_error
            raise BackupRestoreError(
                "Restore failed; rollback completed where available", report=failed
            ) from error
        success = MigrationReport(
            report.source_format_version,
            CURRENT_BACKUP_FORMAT,
            tuple(dict.fromkeys(migrated)),
            report.skipped_components,
            report.warnings,
            report.errors,
            True,
        )
        self._last_report = success
        return plan, success


def _component_info(component: BackupComponent) -> BackupComponentInfo:
    return BackupComponentInfo(
        component.component_id,
        component.version,
        len(component.payload),
        hashlib.sha256(component.payload).hexdigest(),
        component.source_reference,
        component.classification,
        component.external_paths,
        component.credential_references,
        component.machine_bound,
        component.requires_reauthorization,
        component.requires_recertification,
        component.is_cache,
        component.is_model_file,
    )


def _encode_bundle(
    manifest: BackupManifest, payloads: tuple[tuple[str, bytes], ...], password: str
) -> bytes:
    plaintext = json.dumps(
        {
            "manifest": _manifest_dict(manifest),
            "payloads": {
                identifier: base64.b64encode(payload).decode("ascii")
                for identifier, payload in payloads
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    salt = secrets.token_bytes(_SALT_BYTES)
    nonce = secrets.token_bytes(_NONCE_BYTES)
    header: dict[str, object] = {
        "format": "jarvis-backup",
        "format_version": CURRENT_BACKUP_FORMAT,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": _PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "cipher": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    aad = _canonical(header)
    ciphertext = AESGCM(_derive_key(password, salt)).encrypt(nonce, plaintext, aad)
    envelope = {**header, "ciphertext": base64.b64encode(ciphertext).decode("ascii")}
    return _canonical(envelope)


def _decrypt_envelope(envelope: object, password: str) -> tuple[bytes, int]:
    if not isinstance(envelope, dict):
        raise BackupIntegrityError("Backup envelope is malformed")
    version = envelope.get("format_version")
    if envelope.get("format") != "jarvis-backup" or type(version) is not int:
        raise BackupIntegrityError("Backup envelope is malformed")
    if version > CURRENT_BACKUP_FORMAT or version < 1:
        raise BackupCompatibilityError("Backup envelope format is unsupported")
    if envelope.get("kdf") != "PBKDF2-HMAC-SHA256" or envelope.get("cipher") != "AES-256-GCM":
        raise BackupCompatibilityError("Backup encryption parameters are unsupported")
    iterations = envelope.get("iterations")
    if type(iterations) is not int or iterations != _PBKDF2_ITERATIONS:
        raise BackupCompatibilityError("Backup KDF parameters are unsupported")
    try:
        salt = base64.b64decode(str(envelope["salt"]), validate=True)
        nonce = base64.b64decode(str(envelope["nonce"]), validate=True)
        ciphertext = base64.b64decode(str(envelope["ciphertext"]), validate=True)
    except (KeyError, ValueError, binascii.Error, TypeError) as error:
        raise BackupIntegrityError("Backup envelope encoding is malformed") from error
    if len(salt) != _SALT_BYTES or len(nonce) != _NONCE_BYTES or not ciphertext:
        raise BackupIntegrityError("Backup envelope encoding is malformed")
    header = {key: value for key, value in envelope.items() if key != "ciphertext"}
    try:
        return AESGCM(_derive_key(password, salt)).decrypt(
            nonce, ciphertext, _canonical(header)
        ), version
    except (InvalidTag, ValueError) as error:
        raise BackupIntegrityError("Backup authentication failed") from error


def _decode_inner(plaintext: bytes) -> tuple[dict[str, object], dict[str, object]]:
    if len(plaintext) > _MAX_BUNDLE_BYTES:
        raise BackupIntegrityError("Backup plaintext exceeds the size limit")
    try:
        raw = json.loads(plaintext.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BackupIntegrityError("Backup contents are malformed") from error
    if not isinstance(raw, dict) or not isinstance(raw.get("manifest"), dict):
        raise BackupIntegrityError("Backup contents are malformed")
    payloads = raw.get("payloads")
    if not isinstance(payloads, dict):
        raise BackupIntegrityError("Backup payload map is malformed")
    return cast(dict[str, object], raw["manifest"]), cast(dict[str, object], payloads)


def _manifest_from_raw(
    raw: dict[str, object], envelope_version: int
) -> tuple[BackupManifest, MigrationReport]:
    source_version = raw.get("format_version")
    if type(source_version) is not int:
        raise BackupIntegrityError("Backup manifest version is malformed")
    if source_version > CURRENT_BACKUP_FORMAT:
        raise BackupCompatibilityError("Backup manifest is from the future")
    migrated: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    if source_version < CURRENT_BACKUP_FORMAT:
        if source_version != 0:
            raise BackupCompatibilityError("Backup manifest schema is unsupported")
        raw = dict(raw)
        raw["format_version"] = CURRENT_BACKUP_FORMAT
        raw.setdefault("source_installation_id", None)
        raw.setdefault("components", [])
        migrated = tuple(
            str(item.get("component_id"))
            for item in cast(list[object], raw["components"])
            if isinstance(item, dict) and isinstance(item.get("component_id"), str)
        )
        warnings = ("Legacy backup manifest migrated to the current format",)
    components_raw = raw.get("components")
    if not isinstance(components_raw, list) or len(components_raw) > 128:
        raise BackupIntegrityError("Backup component manifest is malformed")
    components = tuple(_component_info_from_raw(item) for item in components_raw)
    source_id = raw.get("source_installation_id")
    if source_id is not None and not isinstance(source_id, str):
        raise BackupIntegrityError("Backup source installation identity is malformed")
    if raw.get("encrypted", True) is not True:
        raise BackupIntegrityError("Backup manifest is not encrypted")
    try:
        created_at = datetime.fromisoformat(str(raw["created_at"]))
        bundle_id = UUID(str(raw["bundle_id"]))
    except (KeyError, TypeError, ValueError) as error:
        raise BackupIntegrityError("Backup manifest identity is malformed") from error
    normalized_version = raw.get("format_version")
    if type(normalized_version) is not int:
        raise BackupIntegrityError("Backup manifest version is malformed")
    manifest = BackupManifest(normalized_version, bundle_id, created_at, source_id, components)
    report = MigrationReport(
        source_version,
        CURRENT_BACKUP_FORMAT,
        migrated,
        (),
        warnings
        + (
            (f"Envelope format {envelope_version} accepted",)
            if envelope_version != source_version
            else ()
        ),
    )
    return manifest, report


def _component_info_from_raw(raw: object) -> BackupComponentInfo:
    if not isinstance(raw, dict):
        raise BackupIntegrityError("Backup component metadata is malformed")
    try:
        values = (
            raw["component_id"],
            raw["version"],
            raw["size_bytes"],
            raw["sha256"],
            raw.get("source_reference", ""),
            BackupClassification(str(raw["classification"])),
            tuple(raw.get("external_paths", ())),
            tuple(raw.get("credential_references", ())),
            raw.get("machine_bound", False),
            raw.get("requires_reauthorization", False),
            raw.get("requires_recertification", False),
            raw.get("is_cache", False),
            raw.get("is_model_file", False),
        )
        info = BackupComponentInfo(*values)
    except (BackupError, KeyError, TypeError, ValueError) as error:
        raise BackupIntegrityError("Backup component metadata is malformed") from error
    _text(info.component_id, "component_id")
    if info.component_id.casefold() in _FORBIDDEN_COMPONENT_IDS:
        raise BackupIntegrityError("Credential secrets cannot be restored")
    _text(info.version, "component version")
    if type(info.size_bytes) is not int or not 0 <= info.size_bytes <= _MAX_COMPONENT_BYTES:
        raise BackupIntegrityError("Backup component size is invalid")
    if len(info.sha256) != 64 or any(
        character not in "0123456789abcdef" for character in info.sha256
    ):
        raise BackupIntegrityError("Backup component hash is invalid")
    _text(info.source_reference, "source_reference", allow_empty=True)
    _text_sequence(info.external_paths, "external_paths", max_items=64)
    _text_sequence(info.credential_references, "credential_references", max_items=64)
    if not all(
        type(value) is bool
        for value in (
            info.machine_bound,
            info.requires_reauthorization,
            info.requires_recertification,
            info.is_cache,
            info.is_model_file,
        )
    ):
        raise BackupIntegrityError("Backup component security metadata is invalid")
    return info


def _payloads_from_raw(manifest: BackupManifest, raw: object) -> tuple[tuple[str, bytes], ...]:
    if not isinstance(raw, dict) or set(raw) != {item.component_id for item in manifest.components}:
        raise BackupIntegrityError("Backup payload map does not match the manifest")
    result: list[tuple[str, bytes]] = []
    for info in manifest.components:
        value = raw.get(info.component_id)
        if not isinstance(value, str):
            raise BackupIntegrityError("Backup payload encoding is malformed")
        try:
            payload = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as error:
            raise BackupIntegrityError("Backup payload encoding is malformed") from error
        if len(payload) != info.size_bytes or hashlib.sha256(payload).hexdigest() != info.sha256:
            raise BackupIntegrityError("Backup component integrity check failed")
        result.append((info.component_id, payload))
    return tuple(result)


def _manifest_dict(manifest: BackupManifest) -> dict[str, object]:
    return {
        "format_version": manifest.format_version,
        "bundle_id": str(manifest.bundle_id),
        "created_at": _utc(manifest.created_at, "Backup timestamp").isoformat(),
        "source_installation_id": manifest.source_installation_id,
        "encrypted": True,
        "components": [
            {
                "component_id": item.component_id,
                "version": item.version,
                "size_bytes": item.size_bytes,
                "sha256": item.sha256,
                "source_reference": item.source_reference,
                "classification": item.classification.value,
                "external_paths": list(item.external_paths),
                "credential_references": list(item.credential_references),
                "machine_bound": item.machine_bound,
                "requires_reauthorization": item.requires_reauthorization,
                "requires_recertification": item.requires_recertification,
                "is_cache": item.is_cache,
                "is_model_file": item.is_model_file,
            }
            for item in manifest.components
        ],
    }


def _derive_key(password: str, salt: bytes) -> bytes:
    if type(password) is not str or not password or len(password) > 1024:
        raise BackupError("A non-empty backup password is required")
    try:
        password_bytes = password.encode("utf-8")
    except UnicodeError as error:
        raise BackupError("Backup password is invalid") from error
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    ).derive(password_bytes)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or (not allow_empty and not value.strip())
        or len(value) > _MAX_TEXT
        or any(not character.isprintable() for character in value)
    ):
        raise BackupError(f"{label} is invalid")
    return value


def _text_sequence(values: object, label: str, *, max_items: int) -> None:
    if isinstance(values, str | bytes) or not isinstance(values, tuple) or len(values) > max_items:
        raise BackupError(f"{label} is invalid")
    for value in values:
        _text(value, label)


def _utc(value: datetime, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise BackupError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _safe_directory(root: Path) -> Path:
    path = root.expanduser()
    _assert_no_reparse_path(path)
    if path.exists() and not path.is_dir():
        raise BackupError("Backup directory is unsafe")
    path.mkdir(parents=True, exist_ok=True)
    _assert_no_reparse_path(path)
    return path.resolve(strict=False)


def _safe_destination(path: Path, *, overwrite: bool) -> Path:
    destination = path.expanduser()
    _assert_no_reparse_path(destination)
    if destination.exists():
        if not destination.is_file():
            raise BackupError("Backup destination is unsafe")
        if not overwrite:
            raise BackupError("Backup destination already exists")
    parent = destination.parent
    if not parent.exists() or not parent.is_dir() or parent.is_symlink() or parent.is_junction():
        raise BackupError("Backup destination directory is unsafe or unavailable")
    return destination.resolve(strict=False)


def _assert_no_reparse_path(path: Path) -> None:
    """Reject symlink/junction components before any path is resolved."""

    current = path
    while True:
        if current.is_symlink() or current.is_junction():
            raise BackupError("Backup path contains a symlink or junction")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _load_or_create_installation_id(root: Path) -> str:
    identity_path = root / "installation-id"
    _assert_no_reparse_path(identity_path)
    if identity_path.exists() or identity_path.is_symlink() or identity_path.is_junction():
        if identity_path.is_symlink() or identity_path.is_junction() or not identity_path.is_file():
            raise BackupError("Backup installation identity is unsafe")
        try:
            identity = identity_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as error:
            raise BackupError("Backup installation identity is unavailable") from error
        return _text(identity, "installation_id")
    identity = f"installation-{uuid4().hex}"
    _atomic_write(identity_path, identity.encode("ascii"))
    return identity


def _atomic_write(destination: Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


__all__ = [
    "BackupBundle",
    "BackupClassification",
    "BackupCompatibilityError",
    "BackupComponent",
    "BackupComponentInfo",
    "BackupComponentType",
    "BackupError",
    "BackupIntegrityError",
    "BackupMigrationRequired",
    "BackupPolicy",
    "BackupRecertificationRequired",
    "BackupRelinkRequired",
    "BackupReauthorizationRequired",
    "BackupRestoreError",
    "BackupService",
    "CURRENT_BACKUP_FORMAT",
    "MigrationReport",
    "RestoreMode",
    "RestorePlan",
]
