# Trusted human update preview

`UpdatePreview` is the application-owned explanation boundary for a controlled
update. It is a read-only projection of facts collected by trusted update,
package, migration, gate, and recovery services. It is not an update executor,
planner, certification authority, or permission bypass.

## Facts shown

`ControlledSelfUpdate.prepare_preview()` accepts the inspected base and
candidate version/revisions, the exact candidate SHA-256, normalized changed
paths and diff digest, package/dependency/data metadata, migration metadata,
gate evidence, and rollback/LKG state. It reruns the checked-in
`ModificationTrustClassifier`; callers cannot provide a lower trust level or a
model-authored security classification.

The resulting preview contains:

- identity: current/candidate version and revision plus exact candidate hash;
- changes: changed paths/subsystems, package/dependency, user-data, and
  integration changes;
- security impact: Trusted Core, PermissionBroker, CredentialVault,
  recovery/updater, sandbox/broker, and permission-surface flags;
- migration: schema, user-data, integration-data, IDs, and reversibility;
- gates: quality, security, Golden Workflow, and applicable Windows acceptance;
- recovery: snapshot, rollback target, LKG, restart, and rollback availability;
- deterministic risk level and machine-readable reasons.

The risk classification is trusted policy. A failed or missing required gate,
an unavailable rollback path, a migration, dependency change, or protected
security surface raises the corresponding risk. A root-of-trust/updater change
is critical. Human presentation may add bounded model context as an explicitly
untrusted explanation, but that text is not rendered as authoritative facts,
does not affect risk, and is excluded from the preview fingerprint.

## Exact approval binding

If a preview is eligible for approval, the trusted approval surface receives an
`UpdateApprovalBinding` containing:

`candidate_hash + preview_fingerprint + approval_reference + expiry`

`ControlledSelfUpdate.validate_approval()` checks the same binding, current
candidate hash, expiry, and all required gate results immediately before the
trusted release owner can act. A changed candidate, changed preview, expired
approval, or failed Golden Workflow is rejected. The preview does not itself
authenticate the owner; the normal trusted approval authenticator and
`PermissionBroker` remain responsible for that authority.

## UI boundary and limitations

The desktop/update surface must render this typed object through trusted
application code. `UpdatePreview.render_trusted()` emits the bounded
`UpdatePreviewView` used by that surface; it contains no model explanation.
Generated package UI, provider output, and model prose cannot replace or imitate
it. No arbitrary HTML, script, or package-provided summary is accepted as the
update explanation.

`ControlledSelfUpdate` deliberately stops at preview and exact approval
validation. Applying a candidate, creating a recovery point, performing
migrations, and committing an LKG remain separate trusted operations. The
existing recovery authentication limitation therefore still blocks enabling
untrusted autonomous self-update; this change closes the missing human-preview
assurance gap without claiming a complete update authority.

Regression coverage is in `tests/test_update_preview.py` and includes low-risk,
dependency, migration, PermissionBroker/Trusted Core, rollback, stale
candidate, misleading model explanation, exact approval, expiry, malformed
gate, and failed Golden Workflow cases.
