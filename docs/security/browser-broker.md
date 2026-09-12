# Browser broker security contract

Status: the previous R2A-H07 canonical Browser Broker finding is fixed for the
supported, explicitly configured runtime path. Browser actions remain
unavailable when no trusted backend/companion is configured. No external
browser or hardware test was performed in this review.

## Trust boundary

`BrowserSemanticBridge` is an observation and stale-reference layer. It is not
an authority. The production composition root creates
`BrowserBrokerAdapter`, which registers one strict typed tool per browser
operation in the canonical `ToolRegistry`. Each invocation therefore follows:

```text
BrowserSemanticBridge
  -> BrowserBrokerAdapter
  -> registered typed browser Tool
  -> PermissionBroker / Policy / approval
  -> trusted browser execution adapter
```

The bridge's default `DenyBrowserPermissionGate` keeps an uncomposed bridge
closed. A package, agent, page, or companion cannot obtain the low-level
backend from the application service.

## Typed binding and authorization

Every request carries bounded, strict fields for:

- action and fixed registered tool identity;
- tab identity and the adapter-bound browser service;
- document generation and origin;
- semantic element reference when an action targets a page element;
- exact action arguments, including the navigation URL or form value;
- the adapter task/correlation context.

The bridge rejects stale tab/document/origin references before dispatch. The
typed tool includes the same values in its trusted action descriptor and
argument fingerprint. The PermissionBroker evaluates that descriptor and the
registered policy; no caller-supplied approval receipt or page assertion is
accepted as authority.

Read-only observation (`inspect`, `scroll_find`, and `wait_for_state`) is
separated from effect-capable actions (`navigate`, click, fill, select,
submit, and credential fill). The latter use effect-capable permissions and
never call the backend before the brokered tool invocation is authorized.

## Data and credentials

Page text, labels, URLs, semantic IDs, and form metadata are untrusted data.
Password values are redacted by `BrowserSemanticBridge`. Ordinary fill rejects
password controls. Credential fill accepts only an opaque `vault:<UUID>`
reference and requires a configured trusted `CredentialVault`; the adapter
validates metadata without exposing secret bytes to the model, page data,
logs, events, or artifacts. With no vault, credential fill fails before the
backend is called. The backend contract is trusted application code and must
perform any actual credential resolution through its own trusted side.

Cookies, saved passwords, browser session secrets, browser internals, and
cross-origin hidden data are not in the bridge contract. Cross-origin semantic
content is removed. Page instructions cannot grant permission.

## Failure and fallback

An unsupported backend, missing companion, failed health check, invalid result,
malformed request, stale reference, denied permission, or missing vault fails
closed. Runtime composition reports the browser capability as unavailable
instead of selecting an uncontrolled browser path. Vision/OS automation is a
separate capability with its own normal permission policy; it is not an
implicit browser-broker fallback.

The adapter validates returned documents as the exact typed
`BrowserDocument`. This is application validation, not an assertion that the
browser process itself is an OS security boundary.

## Evidence and tests

The local deterministic suite covers:

- observation and effect dispatch through registered tools;
- permission denial preventing backend calls;
- stale document and changed-origin references;
- password redaction and prompt-injection-as-data behavior;
- opaque credential references and fail-closed missing-vault behavior;
- direct unsupported-backend rejection;
- runtime composition only with an explicit backend;
- default-deny behavior without trusted composition.

Relevant implementation is in `jarvis/browser.py`,
`jarvis/browser_broker.py`, and `jarvis/runtime.py`; tests are in
`tests/test_browser.py` and `tests/test_runtime.py`.

## Residual limits

| Property | Classification |
| --- | --- |
| ToolRegistry/PermissionBroker is required for supported browser effects | `GUARANTEED_BY_JARVIS_BROKER` |
| Strict request, stale-reference, origin, and password-redaction checks | `ENFORCED_BY_JARVIS_BROKER` |
| Low-level browser backend's own process/browser isolation | `NOT_GUARANTEED` |
| Real browser companion availability and behavior on a host | `BEST_EFFORT` until an integration supplies a tested backend |
| Vision/coordinate automation safety | `NOT_GUARANTEED_BY_THIS_BRIDGE`; separate capability boundary |

The implementation does not claim that Python protocol privacy or a same-user
browser process provides OS isolation. Generated integrations remain outside
Trusted Core and cannot register or invoke this backend without the normal
trusted application composition and broker boundaries.
