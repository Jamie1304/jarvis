# Language and localization

The Human Adaptation Layer owns typed language context and Core-owned
presentation. It does not own actor identity, permissions, provider authority,
verification, or effect state.

## Scopes

`LanguageTag` normalizes standards-style identifiers such as `en`, `en-GB`,
`nl`, and `nl-NL`. `LanguagePreferences` keeps interface language, locale,
conversation preference, fallback, STT language, TTS language, and voice
preference separate. A `LanguageContext` carries the resolved conversation and
output languages for one turn.

Resolution is deterministic: requested output, task override, conversation
override, fixed user preference, application default, then safe fallback. A
temporary output override never mutates the persisted preference. Automatic
detection is local and bounded, with confidence and provenance; ambiguous
short text remains unknown.

English and Dutch are first-class text/localization targets. Model-language
capabilities are declarations on the specific model metadata: the native
default declares English only, and Dutch is not inferred from provider
transport or an arbitrary model identifier. The default catalog truthfully
reports `TEXT_ONLY` until measured STT/TTS capability is registered.
`VoiceLanguageCapability` records provider language metadata separately from
physical microphone or speaker evidence.

## Runtime and routing

`ConversationService` accepts a per-turn `LanguageContext`, projects only
bounded language instructions into the provider request, and adds a language
capability to the existing `RouteRequest.required_capabilities` gate. The
existing ProviderRouter remains the only model router. No provider is selected
by a Dutch/English special case.

The application runtime constructs `HumanAdaptationStore` and
`HumanAdaptationService` beside the existing UserModel, conversation, routing,
and permission owners. `CurrentContextSnapshot` exposes only current language,
locale, personalization mode, and pause state; it does not expose a behavioral
history.

## Localization and trusted approvals

`jarvis/locales/en.json` and `jarvis/locales/nl.json` are data-only,
versionable resource bundles. `Localizer` uses bounded named scalar
interpolation and falls back to English. Missing IDs remain visibly marked.
Canonical enum and machine state values are never replaced with translated
strings.

Declarative capability metadata can provide localized names and descriptions.
It remains presentation-only and cannot execute code or change permissions.

Approval localization calls the existing `TrustedActionNarrator` and retains
the same request ID, target, scope, risk, actor/authority inputs, and argument
and action fingerprints. Language changes only the text rendered to a user.

## Privacy and physical qualification

The existing `PrivacyBoundary` remains the sole provider disclosure boundary.
Language does not change classification or cloud eligibility. R3F tests cover
equivalent English/Dutch canaries, sanitized remote requests, and least-context
language projection. Microphone Dutch recognition, speaker pronunciation,
physical code switching, and visual high-DPI localization remain later manual
qualification evidence; this development state does not claim them.
