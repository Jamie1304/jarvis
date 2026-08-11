"""Stable application error types."""


class JarvisError(Exception):
    """Base class for expected application errors."""

    code = "jarvis_error"


class ConfigurationError(JarvisError):
    """Raised when application configuration is invalid."""

    code = "configuration_error"


class ServiceUnavailableError(JarvisError):
    """Raised when a required internal service is unavailable."""

    code = "service_unavailable"


class ProviderError(JarvisError):
    """Base class for AI and speech provider failures."""

    code = "provider_error"


class ProviderUnavailableError(ProviderError):
    """Raised when a configured provider cannot be reached."""

    code = "provider_unavailable"


class ProviderTimeoutError(ProviderError):
    """Raised when a provider does not respond before its deadline."""

    code = "provider_timeout"


class ModelUnavailableError(ProviderError):
    """Raised when the configured model is not installed or available."""

    code = "model_unavailable"


class StreamingInterruptedError(ProviderError):
    """Raised when a provider ends a response stream unexpectedly."""

    code = "streaming_interrupted"


class ConversationError(JarvisError):
    """Base class for conversational application failures."""

    code = "conversation_error"


class ConversationCancelledError(ConversationError):
    """Raised when a caller cancels an active response stream."""

    code = "conversation_cancelled"


class SpeechError(ProviderError):
    """Base class for local speech input/output failures."""

    code = "speech_error"


class SpeechDisabledError(SpeechError):
    """Raised when an explicitly disabled speech capability is requested."""

    code = "speech_disabled"


class RecordingStateError(SpeechError):
    """Raised for invalid microphone recording lifecycle transitions."""

    code = "recording_state_error"


class TaskError(JarvisError):
    """Base class for orchestrated task failures."""

    code = "task_error"


class TaskCancelledError(TaskError):
    """Raised when an in-progress task is cancelled."""

    code = "task_cancelled"


class TaskTimeoutError(TaskError):
    """Raised when a task exceeds its configured execution budget."""

    code = "task_timeout"


class PlanningError(TaskError):
    """Raised when a plan cannot be created or validated."""

    code = "planning_error"


class MalformedPlanError(PlanningError):
    """Raised when untrusted planning output fails schema validation."""

    code = "malformed_plan"


class CapabilityUnavailableError(TaskError):
    """Raised when a plan names a capability that is not available."""

    code = "capability_unavailable"


class ToolRegistrationError(JarvisError):
    """Raised when a trusted tool cannot be registered deterministically."""

    code = "tool_registration_error"


class DuplicateToolError(ToolRegistrationError):
    """Raised when registration would replace an existing tool ID."""

    code = "duplicate_tool"


class ToolExecutionError(TaskError):
    """Raised when a tool cannot complete its requested operation."""

    code = "tool_execution_error"


class VerificationFailedError(TaskError):
    """Raised when explicit evidence contradicts a step's expected outcome."""

    code = "verification_failed"


class VerificationUnverifiableError(TaskError):
    """Raised when no sufficient evidence exists to verify a step."""

    code = "verification_unverifiable"
