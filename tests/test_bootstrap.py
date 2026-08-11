import pytest
from jarvis.bootstrap import create_ai_provider
from jarvis.core.config import Settings
from jarvis.core.errors import ConfigurationError


def test_invalid_provider_configuration_is_rejected() -> None:
    settings = Settings(ai_provider="unsupported", _env_file=None)

    with pytest.raises(ConfigurationError, match="Unsupported AI provider"):
        create_ai_provider(settings)
