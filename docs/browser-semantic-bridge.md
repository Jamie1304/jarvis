# Generic browser semantic bridge

The native browser boundary is provider-neutral. A configured browser backend
may use an API or protocol first, then semantic DOM/accessibility, OS
accessibility, vision, and coordinates only as progressively weaker fallbacks.
No external
agent-browser runtime is required or imported by JARVIS.

`BrowserSemanticBridge` accepts the canonical application-owned
`BrowserBrokerAdapter` when the capability is configured. The default gate
denies every operation. The bridge does not instantiate a browser, discover
credentials, or decide policy. The composition root connects the adapter to
the normal `ToolRegistry -> PermissionBroker -> Policy -> approval` path before
registering a browser capability; an arbitrary low-level adapter is not a
production authorization path.

The exposed scope is bounded to a tab, URL/origin, title, same-origin semantic
structure, forms, roles, labels, stable per-document semantic IDs, and bounded
untrusted page text. Supported brokered operations are inspect, navigate,
semantic click, normal-field fill, select, submit, scroll/find, wait for state,
and Vault-reference-only credential filling.

Every semantic reference binds to `tab_id`, `document_generation`, and `origin`.
Navigation, mutation, origin changes, and tab close invalidate old references.
The adapter must return a newer document generation after a mutation; stale or
ambiguous snapshots fail closed. The bridge emits observational browser
navigation, mutation, and tab-closed events. Events never grant permission or
replace an authoritative owner.

Page text, titles, labels, URLs, frame metadata, and form metadata are external
data. Prompt-like page content cannot authorize an operation. Password values
are discarded at the model boundary and never appear in output, audit, or event
payloads. Normal fill rejects password controls; credential filling accepts only
a Vault reference and remains separately brokered.

Cross-origin frames are represented only by bounded frame metadata. Their
semantic nodes and form controls are removed. Cookies, password stores, saved
passwords, session secrets, browser internals, and cross-origin hidden data are
outside this contract.
