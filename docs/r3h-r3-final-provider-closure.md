# V1-I-R3H-R3 final provider closure

R3H-R3 closes the two remaining standard-provider source gaps from the exact
R3H-R2 candidate. It does not add a provider, change the qualified remote, or
claim real account validation.

## TypeSafe / Jev

The `typesafe-jev` package is a typed `DecisionProvider`, not a chat provider.
Its fixed production endpoint is `https://api.typesafe.ai`; credentials are
resolved through `CredentialVault` and sent only as a Bearer header. The adapter
implements the official `POST /v1/systemone` contract, maps bounded JARVIS
`DecisionRequest` values to Choice, Score, or Noul questions, validates the
typed response without coercion, rejects malformed or authority-asserting
output, and normalizes remote failures to the existing fallback boundary.

Official protocol sources:

- `https://api.typesafe.ai/docs`
- `https://api.typesafe.ai/openapi.json`
- `https://typesafe.ai/blog/introducing-system-one-models-and-jev`

`GET /v1/models` is bounded and dynamic. Returned model metadata is projected
with `inference_kind=decision` and the existing exact route identity, including
the fixed endpoint and supplied model/version facts. No Core allow-list is
introduced. The remote privacy gateway remains the only route from application
decision input to Jev; a concrete Jev outage still falls through to the local
deterministic decision provider.

## MiniMax

MiniMax uses the existing `OpenAICompatibleProvider` through a fixed standard
preset at `https://api.minimax.io/v1`. The production paths are `/models` and
`/chat/completions`, with Bearer credentials resolved from the Vault. The
official model inventory is dynamic; the package does not ask users for a
custom base URL or invent a model alias. Current model IDs are provider
observations, including the documented M3 and M2.x families.

Official protocol sources:

- `https://platform.minimax.io/docs/api-reference/text-openai-api.md`
- `https://platform.minimax.io/docs/api-reference/models/openai/list-models.md`
- `https://platform.minimax.io/docs/api-reference/text/api/openapi-chat-openai.json`

The shared adapter retains bounded discovery, exact routes, redirect blocking,
error normalization, secret isolation, and the common policy/routing path.

## Evidence boundary

The controlled R3H-R3 tests prove adapter protocol shapes, dynamic discovery,
typed Jev validation, Jev privacy and authority isolation, MiniMax onboarding,
all 28 support/execution rows, and the retained R3H H-matrix. They do not
prove real credentials, account entitlement, billing, quota, regional service
behavior, physical UI/accessibility, or hosted CI.

Evidence is persisted at
`artifacts/development/v1-i-r3h-r3-final-provider-closure.json`.
The canonical full-quality gate is intentionally not run:
`CANONICAL_FULL_QUALITY: NOT_EXECUTED_BY_FINAL_SOURCE_CLOSURE_POLICY`.
