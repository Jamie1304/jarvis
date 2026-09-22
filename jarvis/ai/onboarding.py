"""Application-owned provider onboarding/control service."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from jarvis.ai.governance import PolicyStore
from jarvis.ai.providers.base import IntelligenceProvider
from jarvis.ai.providers.catalog import provider_manifest
from jarvis.ai.providers.discovery import ModelDiscoveryService
from jarvis.ai.providers.intelligence import (
    AuthenticationType,
    ProviderPackageManifest,
    ProviderPolicy,
)
from jarvis.ai.providers.registry import ProviderRegistry
from jarvis.credentials import (
    AuthenticationMethod,
    CredentialStatus,
    CredentialVault,
)


@dataclass(frozen=True, slots=True)
class ProviderConnection:
    provider_id: str
    credential_id: UUID | None
    configuration: tuple[tuple[str, str], ...]
    status: str
    routing_policy: ProviderPolicy
    connected_at: datetime
    authentication_state: str = "unknown"
    discovery_state: str = "unknown"
    usable: bool | None = None


class ProviderOnboardingService:
    """Connect providers through manifests and the authoritative CredentialVault."""

    def __init__(
        self,
        vault: CredentialVault,
        *,
        registry: ProviderRegistry | None = None,
        policies: PolicyStore | None = None,
        path: Path | None = None,
        discovery: ModelDiscoveryService | None = None,
    ) -> None:
        if type(vault) is not CredentialVault:
            raise ValueError("Onboarding requires the authoritative CredentialVault")
        self._vault = vault
        self._registry = registry
        self._policies = policies or PolicyStore()
        if discovery is not None and not isinstance(discovery, ModelDiscoveryService):
            raise ValueError("Onboarding discovery service is malformed")
        self._discovery = discovery
        self._path = path
        self._connections: dict[str, ProviderConnection] = {}
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(path) as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS provider_connections ("
                    "provider_id TEXT PRIMARY KEY, credential_id TEXT, "
                    "configuration_json TEXT NOT NULL, status TEXT NOT NULL, "
                    "routing_policy TEXT NOT NULL, connected_at TEXT NOT NULL, "
                    "authentication_state TEXT NOT NULL, discovery_state TEXT NOT NULL, "
                    "usable INTEGER)"
                )
                for row in connection.execute("SELECT * FROM provider_connections"):
                    self._connections[str(row[0])] = ProviderConnection(
                        str(row[0]),
                        UUID(str(row[1])) if row[1] else None,
                        tuple((str(k), str(v)) for k, v in json.loads(str(row[2]))),
                        str(row[3]),
                        ProviderPolicy(str(row[4])),
                        datetime.fromisoformat(str(row[5])),
                        str(row[6]),
                        str(row[7]),
                        None if row[8] is None else bool(row[8]),
                    )

    def _persist(self, connection: ProviderConnection) -> None:
        if self._path is None:
            return
        with sqlite3.connect(self._path) as database:
            database.execute(
                "INSERT OR REPLACE INTO provider_connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    connection.provider_id,
                    str(connection.credential_id) if connection.credential_id else None,
                    json.dumps(connection.configuration, separators=(",", ":")),
                    connection.status,
                    connection.routing_policy.value,
                    connection.connected_at.isoformat(),
                    connection.authentication_state,
                    connection.discovery_state,
                    None if connection.usable is None else int(connection.usable),
                ),
            )

    def catalog(self) -> tuple[ProviderPackageManifest, ...]:
        from jarvis.ai.providers.catalog import standard_provider_catalog

        return standard_provider_catalog()

    def help(self, provider_id: str) -> ProviderPackageManifest:
        return provider_manifest(provider_id)

    def validate_configuration(
        self,
        provider_id: str,
        configuration: Mapping[str, object],
        *,
        secret_provided: bool = False,
    ) -> tuple[str, ...]:
        manifest = self.help(provider_id)
        missing = tuple(
            field.name
            for field in manifest.required_fields
            if (
                (not field.secret or not secret_provided)
                and (field.name not in configuration or not str(configuration[field.name]).strip())
            )
        )
        unknown = set(configuration) - {
            field.name for field in (*manifest.required_fields, *manifest.optional_fields)
        }
        if unknown:
            raise ValueError("Provider configuration contains unknown fields")
        if any(
            field.secret and field.name in configuration
            for field in (*manifest.required_fields, *manifest.optional_fields)
        ):
            raise ValueError("Provider secrets must be supplied through CredentialVault")
        for field in (*manifest.required_fields, *manifest.optional_fields):
            if field.name not in configuration or field.secret:
                continue
            value = configuration[field.name]
            if type(value) is not str or len(value) > 2_048 or "\x00" in value:
                raise ValueError(f"Provider configuration field is invalid: {field.name}")
            if field.value_kind == "url" and not value.startswith(("https://", "http://")):
                raise ValueError(f"Provider configuration URL is invalid: {field.name}")
        return missing

    def connect(
        self,
        provider_id: str,
        *,
        configuration: Mapping[str, object],
        secret: str | bytes | None = None,
        label: str | None = None,
    ) -> ProviderConnection:
        manifest = self.help(provider_id)
        from jarvis.ai.providers.intelligence import PackageSupportStatus

        if manifest.support_status is not PackageSupportStatus.CONTROLLED_PROTOCOL_TESTED:
            raise ValueError(
                f"Provider package is not connectable: {manifest.support_status.value}"
            )
        missing = self.validate_configuration(
            provider_id, configuration, secret_provided=secret is not None
        )
        if missing:
            raise ValueError(f"Provider configuration is missing: {', '.join(missing)}")
        credential_id: UUID | None = None
        auth_method = _authentication_method(manifest.authentication)
        if auth_method is not None:
            if secret is None:
                raise ValueError("Provider credential is required")
            metadata = self._vault.create(
                label=label or f"{manifest.display_name} credential",
                association=manifest.provider_id,
                scope=("model_discovery", "usability_probe", "inference"),
                auth_method=auth_method,
                secret=secret,
            )
            credential_id = metadata.credential_id
        safe_configuration = tuple(
            sorted(
                (str(key), str(value))
                for key, value in configuration.items()
                if not next(
                    (
                        field.secret
                        for field in (*manifest.required_fields, *manifest.optional_fields)
                        if field.name == key
                    ),
                    False,
                )
            )
        )
        connection = ProviderConnection(
            manifest.provider_id,
            credential_id,
            safe_configuration,
            "configured",
            ProviderPolicy.ENABLED,
            datetime.now(UTC),
            "credential_stored" if credential_id is not None else "not_required",
            "not_started",
            None,
        )
        self._connections[manifest.provider_id] = connection
        self._persist(connection)
        return connection

    def set_routing_policy(self, provider_id: str, policy: ProviderPolicy) -> ProviderConnection:
        key = provider_manifest(provider_id).provider_id
        current = self._connections[key]
        if not isinstance(policy, ProviderPolicy):
            raise ValueError("Provider policy is invalid")
        self._policies.set_provider_policy(key, policy)
        updated = ProviderConnection(
            current.provider_id,
            current.credential_id,
            current.configuration,
            current.status,
            policy,
            current.connected_at,
            current.authentication_state,
            current.discovery_state,
            current.usable,
        )
        self._connections[key] = updated
        self._persist(updated)
        return updated

    def connection(self, provider_id: str) -> ProviderConnection | None:
        return self._connections.get(provider_manifest(provider_id).provider_id)

    def disconnect(self, provider_id: str) -> ProviderConnection:
        current = self.connection(provider_id)
        if current is None:
            raise KeyError(provider_id)
        if current.credential_id is not None:
            self._vault.revoke(current.credential_id)
        updated = ProviderConnection(
            current.provider_id,
            current.credential_id,
            current.configuration,
            "disconnected",
            ProviderPolicy.ROUTING_DISABLED,
            current.connected_at,
            "revoked" if current.credential_id is not None else "unavailable",
            current.discovery_state,
            False,
        )
        self._connections[current.provider_id] = updated
        self._persist(updated)
        return updated

    def delete_credential(self, provider_id: str) -> ProviderConnection:
        """Delete the Vault secret and leave only non-secret provider metadata."""

        current = self.connection(provider_id)
        if current is None:
            raise KeyError(provider_id)
        if current.credential_id is not None:
            self._vault.delete(current.credential_id)
        updated = ProviderConnection(
            current.provider_id,
            None,
            current.configuration,
            "credential_deleted",
            ProviderPolicy.ROUTING_DISABLED,
            current.connected_at,
            "unavailable",
            current.discovery_state,
            False,
        )
        self._connections[current.provider_id] = updated
        self._persist(updated)
        return updated

    def record_authentication(
        self, provider_id: str, *, authenticated: bool, detail: str = ""
    ) -> ProviderConnection:
        del detail
        current = self.connection(provider_id)
        if current is None:
            raise KeyError(provider_id)
        updated = ProviderConnection(
            current.provider_id,
            current.credential_id,
            current.configuration,
            "authenticated" if authenticated else "authentication_failed",
            current.routing_policy,
            current.connected_at,
            "authenticated" if authenticated else "failed",
            current.discovery_state,
            current.usable if authenticated else False,
        )
        self._connections[current.provider_id] = updated
        self._persist(updated)
        return updated

    def record_discovery(
        self, provider_id: str, *, usable: bool | None = None
    ) -> ProviderConnection:
        current = self.connection(provider_id)
        if current is None:
            raise KeyError(provider_id)
        updated = ProviderConnection(
            current.provider_id,
            current.credential_id,
            current.configuration,
            "discovered",
            current.routing_policy,
            current.connected_at,
            current.authentication_state,
            "discovered",
            usable,
        )
        self._connections[current.provider_id] = updated
        self._persist(updated)
        return updated

    def credential_status(self, provider_id: str) -> CredentialStatus | None:
        current = self.connection(provider_id)
        if current is None or current.credential_id is None:
            return None
        return self._vault.status(current.credential_id)

    async def probe(self, provider_id: str, provider: IntelligenceProvider) -> ProviderConnection:
        """Run health, discovery, and usability through application-owned seams."""

        current = self.connection(provider_id)
        if current is None:
            raise KeyError(provider_id)
        health_check = getattr(provider, "health_check", None)
        if not callable(health_check):
            raise ValueError("Provider does not expose a health probe")
        try:
            health = await health_check()
            available = bool(getattr(health, "available", False))
        except Exception:
            available = False
        updated = self.record_authentication(current.provider_id, authenticated=available)
        if not available:
            return updated
        discover = getattr(provider, "discover_models", None)
        if callable(discover) and self._discovery is not None:
            try:
                await self._discovery.discover(current.provider_id, provider)
                return self.record_discovery(current.provider_id, usable=True)
            except Exception:
                return self.record_discovery(current.provider_id, usable=False)
        return self.record_discovery(current.provider_id, usable=None)


def _authentication_method(value: AuthenticationType) -> AuthenticationMethod | None:
    return {
        AuthenticationType.API_KEY: AuthenticationMethod.API_KEY,
        AuthenticationType.API_TOKEN: AuthenticationMethod.API_TOKEN,
        AuthenticationType.OAUTH: AuthenticationMethod.OAUTH_AUTHORIZATION_CODE,
        AuthenticationType.SERVICE_ACCOUNT: AuthenticationMethod.API_TOKEN,
    }.get(value)
