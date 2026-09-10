# Local-private text inference boundary

Every provider-neutral text inference request crosses `PrivacyGuardedProvider`.
The application supplies trusted provider metadata; only metadata explicitly
marked local may pass through without cloud sanitization. Provider names,
endpoints, model names, prompts, and responses never establish locality.

The remote path is:

`local context -> PrivacyContext -> PrivacyBoundary -> CloudTaskEnvelope /
exact outbound validation -> remote provider -> inbound validation -> local
placeholder restoration -> ordinary untrusted result`

`ConversationService` selects only the current user message for a remote
conversation request, so process-local history is not automatically disclosed.
`ContextManager` marks selected memory, knowledge, evidence, tool outputs, and
security-context values as local known-private inputs. The boundary performs
bounded deterministic substitution and validates the exact serialized request
immediately before provider invocation. Unknown privacy classification,
local-only required context, malformed envelopes, and detected secrets fail
closed with `CLOUD_ROUTE_BLOCKED_PRIVACY`.

Memory, UserModel retrieval, credentials, and tool authority remain local.
Remote inference receives no retrieval API and no authority object. Credentials
are never ordinary model context, including for a local provider. Privacy
metadata describes policy input; it grants no permission or host authority.

Only request-local placeholder mappings exist, and they are never placed in the
outbound request or operational evidence. The inbound boundary rejects bounded
overflow, known private-value leakage, and secret-like remote output. It
restores only exact placeholders issued for that request; invented placeholders
cannot retrieve or substitute local values. `LOCAL_ONLY` remains independent of
cloud availability, and provider routing eligibility does not itself approve
privacy.
