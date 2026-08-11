# Visual observation, grounding, and verification

## Protocol

Phase 7 requires this loop for every visual computer interaction:

`OBSERVE -> UNDERSTAND -> GROUND -> ACT -> OBSERVE AGAIN -> VERIFY`

1. **Observe**: invoke brokered screen-read tools to capture a screenshot reference,
   discover windows, and, where configured, collect a bounded accessibility tree.
2. **Understand**: send the reference, task objective, optional semantic tree, and
   previous observation to an injected `VisionProvider`. Provider output is structured
   advice, not authority.
3. **Ground**: trusted code fuses accessibility nodes before visual candidates,
   assigns stable target IDs, and validates normalized bounds against current screenshot
   dimensions and trusted DPI/physical display geometry.
4. **Act**: re-observe immediately before action. If the state fingerprint, dimensions,
   active window, or target changed, reject the request as stale. Map the grounded
   intent only to an existing registered computer tool, which obtains its own broker
   authorization.
5. **Observe again and verify**: capture a fresh state and compare it against an
   explicit semantic/visual expectation. Return `SUCCESS`, `FAILURE`, or `UNCERTAIN`.

Tool success is not verification success.

## Provider contract

`VisionProvider.observe(VisionRequest)` accepts a screenshot reference and metadata,
task objective, optional accessibility tree, and previous observation. It returns
visible elements, candidate bounds, roles/labels, and confidence. It deliberately has
no computer adapter, `PermissionBroker`, approval API, tool registry, or raw action
handle. A production provider that needs image bytes must receive a separately trusted
screenshot-store reader; application composition is responsible for its privacy and
network policy.

## Grounded targets and coordinates

Only trusted fusion generates a `CandidateTarget.target_id`. An action proposal must
reference that ID; it cannot supply arbitrary coordinates, a window handle, or a tool
ID. Semantic focus/text actions require a current accessibility-backed window/control
target. The coordinate fallback uses the target's normalized bounds and the current
trusted `DisplayGeometry`, which validates screenshot dimensions and DPI scaling before
calculating a physical point.

Screenshot artifact metadata includes a content fingerprint. This participates in the
observation state fingerprint so the system detects a material screen change even if
window IDs, labels, and dimensions happen to remain the same.

## Verification and retries

Verification can require target visibility, active-window identity, or an accessibility
control/value fingerprint. Missing semantic evidence or insufficient confidence is
`UNCERTAIN`; it is not success. A retry is limited to one through three attempts, must
begin with a fresh observation, and requires a `RetryAdvisor` to return a materially
different action. The service refuses a same-action retry, preventing blind repeated
clicks.

## Sensitive controls

Seeing a `Send` button proves neither recipient intent nor permission. The visual
layer maps it to a normal computer action tool, whose declared permission, policy,
trusted-user approval, cancellation, audit, and hard-safety rules still decide whether
anything occurs. No visual provider, planner, target ID, confidence score, or
verification expectation can grant or widen authority.
