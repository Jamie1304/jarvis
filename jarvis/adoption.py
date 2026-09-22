"""Trusted identity and provenance evidence for adopting existing capabilities.

This module deliberately produces evidence, not permission.  A path, display
name, registry record, or candidate assertion is never sufficient to adopt an
executable.  Production callers must obtain a bounded observation through
``AdoptionIdentityInspector`` and then bind the resulting evidence to an
attestation before setup can use it.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import stat
from collections.abc import Mapping
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import uuid4


class AdoptionIdentityError(RuntimeError):
    """A candidate could not be inspected safely."""


class AdoptionValidationError(AdoptionIdentityError, ValueError):
    """Adoption metadata is malformed."""


class SignerStatus(StrEnum):
    VALID_TRUSTED_SIGNATURE = "VALID_TRUSTED_SIGNATURE"
    VALID_SIGNATURE_UNTRUSTED_CHAIN = "VALID_SIGNATURE_UNTRUSTED_CHAIN"
    UNSIGNED = "UNSIGNED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    REVOKED_OR_INVALID = "REVOKED_OR_INVALID"
    VERIFICATION_UNAVAILABLE = "VERIFICATION_UNAVAILABLE"
    ERROR = "ERROR"


class EvidenceAuthority(StrEnum):
    WINDOWS_API = "WINDOWS_API"
    PACKAGE_RECEIPT = "PACKAGE_RECEIPT"
    INSTALLER_RECEIPT = "INSTALLER_RECEIPT"
    LOCK_MANIFEST = "LOCK_MANIFEST"
    APPLICATION_INSPECTION = "APPLICATION_INSPECTION"


class EvidenceConfidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class AdoptionOutcome(StrEnum):
    ADOPT_VERIFIED = "ADOPT_VERIFIED"
    ADOPT_WITH_RESTRICTIONS = "ADOPT_WITH_RESTRICTIONS"
    REQUIRES_USER_CONFIRMATION = "REQUIRES_USER_CONFIRMATION"
    REQUIRES_REVALIDATION = "REQUIRES_REVALIDATION"
    INCOMPATIBLE = "INCOMPATIBLE"
    REJECTED = "REJECTED"


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 512
_MAX_HASH_BYTES = 256 * 1024 * 1024
_REPARSE_POINT = 0x400


def _text(value: object, name: str, limit: int = _MAX_TEXT) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or len(value) > limit
        or any(ord(char) < 32 for char in value)
    ):
        raise AdoptionValidationError(f"{name} is malformed")
    return value


def _sha(value: object, name: str) -> str:
    value = _text(value, name, 64).lower()
    if _SHA256.fullmatch(value) is None:
        raise AdoptionValidationError(f"{name} is malformed")
    return value


def _safe_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AdoptionValidationError("Adoption metadata must be an object")
    if len(value) > 128:
        raise AdoptionValidationError("Adoption metadata is too large")
    result: dict[str, object] = {}
    for key, item in value.items():
        key_text = _text(key, "Adoption field", 128)
        if key_text.casefold() in {"secret", "password", "token", "private_key"}:
            raise AdoptionValidationError("Raw secret material is not adoption evidence")
        if type(item) not in {type(None), bool, int, str}:
            raise AdoptionValidationError("Adoption metadata contains an unsupported value")
        if isinstance(item, str) and len(item) > _MAX_TEXT:
            raise AdoptionValidationError("Adoption metadata is too large")
        result[key_text] = item
    return result


def _digest(value: object) -> str:
    import json

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class WindowsFileIdentity:
    """A bounded observation of a regular Windows file.

    ``volume_serial`` and ``file_id`` come from the file handle where the
    native provider is available.  ``canonical_path`` is retained for
    diagnostics only; it is never the sole security identity.
    """

    canonical_path: str
    volume_serial: int | None
    file_id: str
    size: int
    content_hash: str
    file_type: str
    is_reparse: bool
    modified_at: datetime

    def __post_init__(self) -> None:
        _text(self.canonical_path, "Canonical path", 4_096)
        if self.volume_serial is not None and (
            type(self.volume_serial) is not int or self.volume_serial < 0
        ):
            raise AdoptionValidationError("Volume serial is malformed")
        _text(self.file_id, "File ID", 256)
        if type(self.size) is not int or self.size < 0 or self.size > _MAX_HASH_BYTES:
            raise AdoptionValidationError("File size is malformed or exceeds the bound")
        _sha(self.content_hash, "Content hash")
        _text(self.file_type, "File type", 64)
        if type(self.is_reparse) is not bool or self.modified_at.tzinfo is None:
            raise AdoptionValidationError("File identity metadata is malformed")

    @property
    def fingerprint(self) -> str:
        return _digest(
            {
                "volume_serial": self.volume_serial,
                "file_id": self.file_id,
                "size": self.size,
                "content_hash": self.content_hash,
                "file_type": self.file_type,
                "is_reparse": self.is_reparse,
            }
        )


@dataclass(frozen=True, slots=True)
class SignerEvidence:
    status: SignerStatus
    subject: str = ""
    thumbprint: str = ""
    chain_result: str = ""
    verifier: str = ""
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not isinstance(self.status, SignerStatus):
            raise AdoptionValidationError("Signer status is malformed")
        for name, value in (
            ("Signer subject", self.subject),
            ("Signer thumbprint", self.thumbprint),
            ("Signer chain result", self.chain_result),
            ("Signer verifier", self.verifier),
        ):
            if value:
                _text(value, name)
        if self.thumbprint and re.fullmatch(r"[0-9A-Fa-f]{8,128}", self.thumbprint) is None:
            raise AdoptionValidationError("Signer thumbprint is malformed")
        if self.observed_at.tzinfo is None:
            raise AdoptionValidationError("Signer observation time is malformed")

    @property
    def fingerprint(self) -> str:
        return _digest(
            {
                "status": self.status.value,
                "subject": self.subject,
                "thumbprint": self.thumbprint.lower(),
                "chain_result": self.chain_result,
                "verifier": self.verifier,
            }
        )


@dataclass(frozen=True, slots=True)
class DependencyEvidence:
    name: str
    source: str
    reference: str
    content_hash: str | None
    authority: EvidenceAuthority
    confidence: EvidenceConfidence
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _text(self.name, "Dependency name", 256)
        _text(self.source, "Dependency source", 256)
        _text(self.reference, "Dependency reference", 1_024)
        if self.content_hash is not None:
            _sha(self.content_hash, "Dependency hash")
        if not isinstance(self.authority, EvidenceAuthority) or not isinstance(
            self.confidence, EvidenceConfidence
        ):
            raise AdoptionValidationError("Dependency evidence classification is malformed")
        if self.observed_at.tzinfo is None:
            raise AdoptionValidationError("Dependency observation time is malformed")

    @property
    def fingerprint(self) -> str:
        return _digest(
            {
                "name": self.name,
                "source": self.source,
                "reference": self.reference,
                "content_hash": self.content_hash,
                "authority": self.authority.value,
                "confidence": self.confidence.value,
            }
        )


@dataclass(frozen=True, slots=True)
class DependencyProvenance:
    source: str
    authority: EvidenceAuthority
    confidence: EvidenceConfidence
    dependencies: tuple[DependencyEvidence, ...] = ()
    available: bool = True
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        _text(self.source, "Dependency provenance source", 256)
        if not isinstance(self.authority, EvidenceAuthority) or not isinstance(
            self.confidence, EvidenceConfidence
        ):
            raise AdoptionValidationError("Dependency provenance classification is malformed")
        if type(self.dependencies) is not tuple or any(
            not isinstance(item, DependencyEvidence) for item in self.dependencies
        ):
            raise AdoptionValidationError("Dependency evidence is malformed")
        if type(self.available) is not bool or self.observed_at.tzinfo is None:
            raise AdoptionValidationError("Dependency provenance metadata is malformed")

    @property
    def fingerprint(self) -> str:
        return _digest(
            {
                "source": self.source,
                "authority": self.authority.value,
                "confidence": self.confidence.value,
                "available": self.available,
                "dependencies": [item.fingerprint for item in self.dependencies],
            }
        )

    @property
    def independent(self) -> bool:
        return (
            self.available
            and bool(self.dependencies)
            and self.authority is not EvidenceAuthority.APPLICATION_INSPECTION
        )


@dataclass(frozen=True, slots=True)
class AdoptionIdentityEvidence:
    file: WindowsFileIdentity
    signer: SignerEvidence
    dependencies: DependencyProvenance
    captured_at: datetime
    inspector: str = "jarvis.trusted-adoption-inspector"
    _issuer_token: object = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.file, WindowsFileIdentity) or not isinstance(
            self.signer, SignerEvidence
        ):
            raise AdoptionValidationError("Adoption file or signer evidence is malformed")
        if (
            not isinstance(self.dependencies, DependencyProvenance)
            or self.captured_at.tzinfo is None
        ):
            raise AdoptionValidationError("Adoption evidence metadata is malformed")
        _text(self.inspector, "Adoption inspector", 128)

    @property
    def fingerprint(self) -> str:
        return _digest(
            {
                "file": self.file.fingerprint,
                "signer": self.signer.fingerprint,
                "dependencies": self.dependencies.fingerprint,
            }
        )


@dataclass(frozen=True, slots=True)
class AdoptionAttestation:
    """A durable evidence binding; it does not grant permission or trust."""

    attestation_id: str
    candidate_id: str
    identity_fingerprint: str
    content_hash: str
    file_id: str
    signer_fingerprint: str
    dependency_fingerprint: str
    compatibility_fingerprint: str
    policy_outcome: AdoptionOutcome
    version: str | None
    workspace_scope: str
    setup_run_id: str
    acquisition_id: str
    created_at: datetime
    expires_at: datetime
    policy_fingerprint: str
    _issuer_token: object = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        for name, value in (
            ("Attestation ID", self.attestation_id),
            ("Candidate ID", self.candidate_id),
            ("Workspace scope", self.workspace_scope),
            ("Setup run ID", self.setup_run_id),
            ("Acquisition ID", self.acquisition_id),
        ):
            _text(value, name, 256)
        for name, value in (
            ("Identity fingerprint", self.identity_fingerprint),
            ("Content hash", self.content_hash),
            ("Signer fingerprint", self.signer_fingerprint),
            ("Dependency fingerprint", self.dependency_fingerprint),
            ("Compatibility fingerprint", self.compatibility_fingerprint),
            ("Policy fingerprint", self.policy_fingerprint),
        ):
            _sha(value, name)
        _text(self.file_id, "Attested file ID", 256)
        if (
            not isinstance(self.policy_outcome, AdoptionOutcome)
            or self.version is not None
            and not isinstance(self.version, str)
        ):
            raise AdoptionValidationError("Attestation classification is malformed")
        if (
            self.created_at.tzinfo is None
            or self.expires_at.tzinfo is None
            or self.expires_at <= self.created_at
        ):
            raise AdoptionValidationError("Attestation lifetime is malformed")

    @property
    def fingerprint(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "attestation_id": self.attestation_id,
            "candidate_id": self.candidate_id,
            "identity_fingerprint": self.identity_fingerprint,
            "content_hash": self.content_hash,
            "file_id": self.file_id,
            "signer_fingerprint": self.signer_fingerprint,
            "dependency_fingerprint": self.dependency_fingerprint,
            "compatibility_fingerprint": self.compatibility_fingerprint,
            "policy_outcome": self.policy_outcome.value,
            "version": self.version,
            "workspace_scope": self.workspace_scope,
            "setup_run_id": self.setup_run_id,
            "acquisition_id": self.acquisition_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "policy_fingerprint": self.policy_fingerprint,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> AdoptionAttestation:
        try:
            return cls(
                str(value["attestation_id"]),
                str(value["candidate_id"]),
                str(value["identity_fingerprint"]),
                str(value["content_hash"]),
                str(value["file_id"]),
                str(value["signer_fingerprint"]),
                str(value["dependency_fingerprint"]),
                str(value["compatibility_fingerprint"]),
                AdoptionOutcome(str(value["policy_outcome"])),
                str(value["version"]) if value.get("version") is not None else None,
                str(value["workspace_scope"]),
                str(value["setup_run_id"]),
                str(value["acquisition_id"]),
                datetime.fromisoformat(str(value["created_at"])),
                datetime.fromisoformat(str(value["expires_at"])),
                str(value["policy_fingerprint"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise AdoptionValidationError("Persisted adoption attestation is malformed") from error


class FileIdentityProvider(Protocol):
    def inspect(self, path: str) -> WindowsFileIdentity: ...


class SignerVerifier(Protocol):
    def verify(self, path: str) -> SignerEvidence: ...


class DependencyProvenanceProvider(Protocol):
    def inspect(self, path: str) -> DependencyProvenance: ...


class WindowsFileIdentityProvider:
    """Handle-based Windows identity and bounded content hashing."""

    def __init__(self, *, max_bytes: int = _MAX_HASH_BYTES) -> None:
        if type(max_bytes) is not int or max_bytes <= 0 or max_bytes > _MAX_HASH_BYTES:
            raise AdoptionValidationError("File identity hash bound is malformed")
        self._max_bytes = max_bytes

    def inspect(self, path: str) -> WindowsFileIdentity:
        candidate = Path(_text(path, "Adoption path", 4_096))
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise AdoptionIdentityError("Adoption path cannot be resolved") from error
        if not resolved.is_file() or resolved.is_symlink():
            raise AdoptionIdentityError("Adoption target is not a regular file")
        if os.name == "nt":
            self._reject_reparse_chain(resolved)
            return self._inspect_windows(resolved)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > self._max_bytes:
            raise AdoptionIdentityError("Adoption target is not a bounded regular file")
        return WindowsFileIdentity(
            str(resolved),
            int(info.st_dev),
            f"{info.st_ino:x}",
            int(info.st_size),
            self._hash_path(resolved),
            "executable" if resolved.suffix.casefold() in {".exe", ".dll", ".com"} else "file",
            False,
            datetime.fromtimestamp(info.st_mtime, UTC),
        )

    def _hash_path(self, path: Path) -> str:
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                if total > self._max_bytes:
                    raise AdoptionIdentityError("Adoption target exceeds the hash bound")
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _reject_reparse_chain(path: Path) -> None:
        for parent in (path, *path.parents):
            try:
                attributes = ctypes.windll.kernel32.GetFileAttributesW(str(parent))
            except AttributeError as error:
                raise AdoptionIdentityError(
                    "Windows file attribute inspection is unavailable"
                ) from error
            if attributes == 0xFFFFFFFF:
                raise AdoptionIdentityError("Windows file attribute inspection failed")
            if attributes & _REPARSE_POINT:
                raise AdoptionIdentityError("Reparse-point adoption is rejected")
            if parent.parent == parent:
                break

    def _inspect_windows(self, path: Path) -> WindowsFileIdentity:
        class _FileInformation(ctypes.Structure):
            _fields_ = [
                ("file_attributes", wintypes.DWORD),
                ("creation_time", wintypes.FILETIME),
                ("last_access_time", wintypes.FILETIME),
                ("last_write_time", wintypes.FILETIME),
                ("volume_serial_number", wintypes.DWORD),
                ("file_size_high", wintypes.DWORD),
                ("file_size_low", wintypes.DWORD),
                ("number_of_links", wintypes.DWORD),
                ("file_index_high", wintypes.DWORD),
                ("file_index_low", wintypes.DWORD),
            ]

        try:
            import msvcrt

            with path.open("rb") as stream:
                handle = wintypes.HANDLE(msvcrt.get_osfhandle(stream.fileno()))
                information = _FileInformation()
                if not ctypes.windll.kernel32.GetFileInformationByHandle(
                    handle, ctypes.byref(information)
                ):
                    raise AdoptionIdentityError("Windows file identity inspection failed")
                size = (int(information.file_size_high) << 32) | int(information.file_size_low)
                if size > self._max_bytes:
                    raise AdoptionIdentityError("Adoption target exceeds the hash bound")
                digest = hashlib.sha256()
                total = 0
                while chunk := stream.read(1024 * 1024):
                    total += len(chunk)
                    if total > self._max_bytes:
                        raise AdoptionIdentityError("Adoption target exceeds the hash bound")
                    digest.update(chunk)
                if total != size:
                    raise AdoptionIdentityError("Adoption target changed during hashing")
                file_id = (
                    f"{int(information.file_index_high):08x}{int(information.file_index_low):08x}"
                )
                return WindowsFileIdentity(
                    str(path),
                    int(information.volume_serial_number),
                    file_id,
                    size,
                    digest.hexdigest(),
                    "executable" if path.suffix.casefold() in {".exe", ".dll", ".com"} else "file",
                    bool(information.file_attributes & _REPARSE_POINT),
                    datetime.now(UTC),
                )
        except (OSError, ValueError) as error:
            if isinstance(error, AdoptionIdentityError):
                raise
            raise AdoptionIdentityError("Windows file identity inspection failed") from error


class WindowsSignerVerifier:
    """Minimal Authenticode status verifier; metadata is never inferred."""

    def verify(self, path: str) -> SignerEvidence:
        observed = datetime.now(UTC)
        if os.name != "nt":
            return SignerEvidence(
                SignerStatus.VERIFICATION_UNAVAILABLE,
                verifier="wintrust-unavailable",
                observed_at=observed,
            )
        try:
            return self._verify_wintrust(_text(path, "Signer path", 4_096), observed)
        except (OSError, TypeError, ValueError, AttributeError):
            return SignerEvidence(
                SignerStatus.ERROR, verifier="wintrust-error", observed_at=observed
            )

    @staticmethod
    def _verify_wintrust(path: str, observed: datetime) -> SignerEvidence:
        class _Guid(ctypes.Structure):
            _fields_ = [
                ("data1", wintypes.DWORD),
                ("data2", wintypes.WORD),
                ("data3", wintypes.WORD),
                ("data4", ctypes.c_ubyte * 8),
            ]

        class _FileInfo(ctypes.Structure):
            _fields_ = [
                ("cb_struct", wintypes.DWORD),
                ("file_path", wintypes.LPCWSTR),
                ("file_handle", wintypes.HANDLE),
                ("known_subject", ctypes.c_void_p),
            ]

        class _TrustData(ctypes.Structure):
            _fields_ = [
                ("cb_struct", wintypes.DWORD),
                ("policy_callback_data", ctypes.c_void_p),
                ("sip_client_data", ctypes.c_void_p),
                ("ui_choice", wintypes.DWORD),
                ("revocation_checks", wintypes.DWORD),
                ("union_choice", wintypes.DWORD),
                ("file_info", ctypes.POINTER(_FileInfo)),
                ("state_action", wintypes.DWORD),
                ("state_data", ctypes.c_void_p),
                ("url_reference", wintypes.LPCWSTR),
                ("provider_flags", wintypes.DWORD),
                ("ui_context", wintypes.DWORD),
                ("signature_settings", ctypes.c_void_p),
            ]

        guid = _Guid(
            0x00AAC56B,
            0xCD44,
            0x11D0,
            (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
        )
        file_info = _FileInfo(ctypes.sizeof(_FileInfo), path, None, None)
        trust_data = _TrustData(
            ctypes.sizeof(_TrustData),
            None,
            None,
            2,
            0,
            1,
            ctypes.pointer(file_info),
            0,
            None,
            None,
            0x00001000,
            0,
            None,
        )
        wintrust = ctypes.WinDLL("wintrust")
        verify = wintrust.WinVerifyTrust
        verify.restype = wintypes.LONG
        result = int(verify(None, ctypes.byref(guid), ctypes.byref(trust_data)))
        if result == 0:
            return SignerEvidence(
                SignerStatus.VALID_TRUSTED_SIGNATURE,
                verifier="WinVerifyTrust",
                observed_at=observed,
            )
        if result in {0x800B010C, 0x80096010, 0x800B0100}:
            return SignerEvidence(
                SignerStatus.REVOKED_OR_INVALID, verifier="WinVerifyTrust", observed_at=observed
            )
        return SignerEvidence(
            SignerStatus.INVALID_SIGNATURE, verifier="WinVerifyTrust", observed_at=observed
        )


class LocalDependencyProvenanceProvider:
    """Bounded, read-only provenance lookup; absence is explicit."""

    def inspect(self, path: str) -> DependencyProvenance:
        candidate = Path(_text(path, "Dependency path", 4_096))
        for name, authority in (
            ("package-receipt.json", EvidenceAuthority.PACKAGE_RECEIPT),
            ("install.lock", EvidenceAuthority.LOCK_MANIFEST),
        ):
            receipt = candidate.parent / name
            if receipt.is_file() and receipt.stat().st_size <= 64 * 1024:
                digest = hashlib.sha256(receipt.read_bytes()).hexdigest()
                item = DependencyEvidence(
                    candidate.name,
                    str(receipt),
                    str(receipt),
                    digest,
                    authority,
                    EvidenceConfidence.MEDIUM,
                )
                return DependencyProvenance(
                    str(receipt), authority, EvidenceConfidence.MEDIUM, (item,)
                )
        return DependencyProvenance(
            "unavailable",
            EvidenceAuthority.APPLICATION_INSPECTION,
            EvidenceConfidence.UNKNOWN,
            (),
            False,
        )


class AdoptionIdentityInspector:
    def __init__(
        self,
        file_identity: FileIdentityProvider,
        signer: SignerVerifier,
        dependencies: DependencyProvenanceProvider,
    ) -> None:
        self._file_identity = file_identity
        self._signer = signer
        self._dependencies = dependencies
        self._token = object()

    @property
    def token(self) -> object:
        return self._token

    def inspect(self, path: str) -> AdoptionIdentityEvidence:
        before = self._file_identity.inspect(path)
        if before.is_reparse:
            raise AdoptionIdentityError("Reparse-point adoption is rejected")
        signer = self._signer.verify(before.canonical_path)
        dependencies = self._dependencies.inspect(before.canonical_path)
        after = self._file_identity.inspect(path)
        if before.fingerprint != after.fingerprint or before.canonical_path != after.canonical_path:
            raise AdoptionIdentityError("Adoption target changed during inspection")
        evidence = AdoptionIdentityEvidence(before, signer, dependencies, datetime.now(UTC))
        object.__setattr__(evidence, "_issuer_token", self._token)
        return evidence


class StaticFileIdentityProvider:
    """Deterministic injected provider for repository-owned tests only."""

    def __init__(self, identities: Mapping[str, WindowsFileIdentity]) -> None:
        self._identities = dict(identities)

    def inspect(self, path: str) -> WindowsFileIdentity:
        try:
            return self._identities[path]
        except KeyError as error:
            raise AdoptionIdentityError("Synthetic file identity is unavailable") from error


class StaticSignerVerifier:
    def __init__(self, evidence: Mapping[str, SignerEvidence]) -> None:
        self._evidence = dict(evidence)

    def verify(self, path: str) -> SignerEvidence:
        try:
            return self._evidence[path]
        except KeyError as error:
            raise AdoptionIdentityError("Synthetic signer evidence is unavailable") from error


class StaticDependencyProvenanceProvider:
    def __init__(self, evidence: Mapping[str, DependencyProvenance]) -> None:
        self._evidence = dict(evidence)

    def inspect(self, path: str) -> DependencyProvenance:
        try:
            return self._evidence[path]
        except KeyError as error:
            raise AdoptionIdentityError("Synthetic dependency provenance is unavailable") from error


class AdoptionPolicy:
    """Trusted policy for adoption; it never approves later real-world effects."""

    def __init__(
        self, inspector: AdoptionIdentityInspector, *, max_age: timedelta = timedelta(minutes=10)
    ) -> None:
        if not isinstance(inspector, AdoptionIdentityInspector) or max_age <= timedelta(0):
            raise AdoptionValidationError("Adoption policy is malformed")
        self._inspector = inspector
        self._max_age = max_age
        self._token = object()

    def inspect(self, path: str) -> AdoptionIdentityEvidence:
        """Run the trusted two-observation inspection for a setup candidate."""

        return self._inspector.inspect(path)

    def evaluate(
        self,
        evidence: AdoptionIdentityEvidence,
        *,
        compatible: bool,
        read_only: bool,
        user_confirmed: bool,
        requires_privilege: bool = False,
        now: datetime | None = None,
    ) -> AdoptionOutcome:
        if (
            not isinstance(evidence, AdoptionIdentityEvidence)
            or evidence._issuer_token is not self._inspector.token
        ):
            return AdoptionOutcome.REJECTED
        if not compatible:
            return AdoptionOutcome.INCOMPATIBLE
        current = now or datetime.now(UTC)
        if current.tzinfo is None or current - evidence.captured_at > self._max_age:
            return AdoptionOutcome.REQUIRES_REVALIDATION
        if evidence.file.is_reparse:
            return AdoptionOutcome.REJECTED
        if evidence.signer.status in {
            SignerStatus.INVALID_SIGNATURE,
            SignerStatus.REVOKED_OR_INVALID,
            SignerStatus.ERROR,
        }:
            return AdoptionOutcome.REJECTED
        if requires_privilege:
            return (
                AdoptionOutcome.REQUIRES_USER_CONFIRMATION
                if user_confirmed is False
                else AdoptionOutcome.ADOPT_WITH_RESTRICTIONS
                if evidence.signer.status is SignerStatus.VALID_TRUSTED_SIGNATURE
                and evidence.dependencies.independent
                else AdoptionOutcome.REJECTED
            )
        if (
            evidence.signer.status is SignerStatus.VALID_TRUSTED_SIGNATURE
            and evidence.dependencies.independent
        ):
            return AdoptionOutcome.ADOPT_VERIFIED
        if not user_confirmed:
            return AdoptionOutcome.REQUIRES_USER_CONFIRMATION
        return (
            AdoptionOutcome.ADOPT_WITH_RESTRICTIONS
            if read_only
            else AdoptionOutcome.REQUIRES_REVALIDATION
        )

    def attest(
        self,
        candidate_id: str,
        evidence: AdoptionIdentityEvidence,
        *,
        version: str | None,
        compatibility_fingerprint: str,
        workspace_scope: str,
        setup_run_id: str,
        acquisition_id: str,
        compatible: bool,
        read_only: bool,
        user_confirmed: bool,
        requires_privilege: bool = False,
        now: datetime | None = None,
    ) -> AdoptionAttestation:
        outcome = self.evaluate(
            evidence,
            compatible=compatible,
            read_only=read_only,
            user_confirmed=user_confirmed,
            requires_privilege=requires_privilege,
            now=now,
        )
        if outcome not in {AdoptionOutcome.ADOPT_VERIFIED, AdoptionOutcome.ADOPT_WITH_RESTRICTIONS}:
            raise AdoptionIdentityError(f"Adoption is not permitted by policy: {outcome.value}")
        created = now or datetime.now(UTC)
        attestation = AdoptionAttestation(
            str(uuid4()),
            _text(candidate_id, "Candidate ID", 128),
            evidence.fingerprint,
            evidence.file.content_hash,
            evidence.file.file_id,
            evidence.signer.fingerprint,
            evidence.dependencies.fingerprint,
            _sha(compatibility_fingerprint, "Compatibility fingerprint"),
            outcome,
            version,
            _text(workspace_scope, "Workspace scope", 256),
            _text(setup_run_id, "Setup run ID", 256),
            _text(acquisition_id, "Acquisition ID", 256),
            created,
            created + self._max_age,
            _digest(
                {
                    "outcome": outcome.value,
                    "read_only": read_only,
                    "requires_privilege": requires_privilege,
                }
            ),
        )
        object.__setattr__(attestation, "_issuer_token", self._token)
        return attestation

    def validate(
        self,
        candidate_id: str,
        evidence: AdoptionIdentityEvidence,
        attestation: AdoptionAttestation,
        *,
        version: str | None,
        now: datetime | None = None,
    ) -> None:
        if (
            not isinstance(attestation, AdoptionAttestation)
            or attestation._issuer_token is not self._token
        ):
            raise AdoptionIdentityError("Adoption attestation was not issued by the trusted policy")
        current = now or datetime.now(UTC)
        if (
            attestation.expires_at <= current
            or attestation.candidate_id != candidate_id
            or attestation.version != version
        ):
            raise AdoptionIdentityError("Adoption attestation is stale or mismatched")
        if (
            attestation.identity_fingerprint != evidence.fingerprint
            or attestation.content_hash != evidence.file.content_hash
            or attestation.file_id != evidence.file.file_id
            or attestation.signer_fingerprint != evidence.signer.fingerprint
            or attestation.dependency_fingerprint != evidence.dependencies.fingerprint
        ):
            raise AdoptionIdentityError("Adoption attestation does not bind current evidence")


__all__ = [
    "AdoptionAttestation",
    "AdoptionIdentityError",
    "AdoptionIdentityEvidence",
    "AdoptionIdentityInspector",
    "AdoptionOutcome",
    "AdoptionPolicy",
    "AdoptionValidationError",
    "DependencyEvidence",
    "DependencyProvenance",
    "EvidenceAuthority",
    "EvidenceConfidence",
    "LocalDependencyProvenanceProvider",
    "SignerEvidence",
    "SignerStatus",
    "StaticDependencyProvenanceProvider",
    "StaticFileIdentityProvider",
    "StaticSignerVerifier",
    "WindowsFileIdentity",
    "WindowsFileIdentityProvider",
    "WindowsSignerVerifier",
]
