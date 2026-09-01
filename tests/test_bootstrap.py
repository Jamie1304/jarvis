import pytest
from jarvis.bootstrap import create_ai_provider
from jarvis.core.config import Settings
from jarvis.core.errors import ConfigurationError


def test_invalid_provider_configuration_is_rejected() -> None:
    settings = Settings(ai_provider="unsupported", _env_file=None)

    with pytest.raises(ConfigurationError, match="Unsupported AI provider"):
        create_ai_provider(settings)


@pytest.mark.parametrize(
    "endpoint",
    (
        "https://127.0.0.1:11434",
        "http://localhost:11434",
        "http://example.com:11434",
        "http://user:password@127.0.0.1:11434",
    ),
)
def test_ai_provider_rejects_endpoints_outside_literal_loopback(endpoint: str) -> None:
    settings = Settings(ai_endpoint=endpoint, _env_file=None)

    with pytest.raises(ConfigurationError, match="literal local loopback"):
        create_ai_provider(settings)
