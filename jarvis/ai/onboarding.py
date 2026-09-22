"""Application-owned provider onboarding/control service."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from jarvis.ai.governance import PolicyStore
from jarvis.ai.providers.catalog import provider_manifest
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


class ProviderOnboardingService:
    """Connect providers through manifests and the authoritative CredentialVault."""

    def __init__(
        self,
        vault: CredentialVault,
        *,
        registry: ProviderRegistry | None = None,
        policies: PolicyStore | None = None,
    ) -> None:
        if type(vault) is not CredentialVault:
            raise ValueError("Onboarding requires the authoritative CredentialVault")
        self._vault = vault
        self._registry = registry
        self._policies = policies or PolicyStore()
        self._connections: dict[str, ProviderConnection] = {}

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
        )
        self._connections[manifest.provider_id] = connection
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
        )
        self._connections[key] = updated
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
        )
        self._connections[current.provider_id] = updated
        return updated

    def credential_status(self, provider_id: str) -> CredentialStatus | None:
        current = self.connection(provider_id)
        if current is None or current.credential_id is None:
            return None
        return self._vault.status(current.credential_id)


def _authentication_method(value: AuthenticationType) -> AuthenticationMethod | None:
    return {
        AuthenticationType.API_KEY: AuthenticationMethod.API_KEY,
        AuthenticationType.API_TOKEN: AuthenticationMethod.API_TOKEN,
        AuthenticationType.OAUTH: AuthenticationMethod.OAUTH_AUTHORIZATION_CODE,
        AuthenticationType.SERVICE_ACCOUNT: AuthenticationMethod.API_TOKEN,
    }.get(value)
