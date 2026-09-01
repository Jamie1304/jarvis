# JARVIS self-modification policy

Status: **authoritative modification contract**. The security constitution and
trusted application code remain the authority; this document explains how the
authority classifies patches produced by improvement, setup, update, or future
self-expansion workflows.

## Trust levels

Every proposed patch is classified from its complete normalized path set by the
application-owned `ModificationTrustClassifier`. A model, worker, integration,
or user-facing prompt cannot provide a lower replacement classification. The
highest applicable level is the classification for the whole patch.

| Level | Surface | Minimum gate posture | Agent-authored patch? |
| --- | --- | --- | --- |
| 1 | Generated Integration | static security, sandbox tests, package certification | Yes, in an isolated/certification flow |
| 2 | User-space JARVIS | quality, integration tests, protected regression, trusted approval | Yes, in an isolated proposal flow |
| 3 | Core Agent Runtime | Level 2 plus startup health and security review | Yes, only as a tested isolated proposal |
| 4 | PermissionBroker, CredentialVault, and security services | Trusted Core security, permission-policy review, independent security review, trusted approval, recovery point, change-control record | No; trusted release only |
| 5 | Updater, recovery, security constitution, classifier, and root of trust | Level 4 plus recovery/update gate, dual-control approval, and root-of-trust review | No; separately held trusted release only |

The gate catalog is monotonic: each higher level carries every applicable
baseline control plus additional controls. Level 4 and Level 5 changes cannot
be authorized by the routine improvement or controlled-update identity. Existing
owner-security-release controls remain required for current Trusted Core paths.

## Classification and anti-evasion rules

- Classification runs on every path in one `ProposedChangeSet`, before any write.
- A mixed patch uses the maximum level; splitting a patch into smaller requests
  cannot reduce its required gates.
- A rename is represented by its old and new typed file changes. The protected
  old path remains in the classification. Protected directory and filename
  tokens also classify renamed Broker, Vault, policy, recovery, updater, and
  classifier modules conservatively.
- The classifier and this policy are themselves Level 5. A candidate cannot edit
  the classifier, security constitution, or mutation policy to make a later
  patch appear safer. The trusted workspace applier and mutation policy use the
  checked-in implementation, not model-authored labels.
- Approval is not a classification mechanism. An approval for a lower-level
  patch cannot authorize changed paths, a different diff, or a higher-level
  surface.
- Malformed, ambiguous, traversal, absolute, alternate-stream, device, or
  otherwise unsafe paths fail closed before classification.

## Enforcement points

`TrustedWorkspaceChangeApplier` classifies the complete typed change set before
writing an isolated worktree. `MutationPolicy` independently checks the path at
the mutation boundary, and `MutationAuthorizer` refuses to mint a routine
controlled-update record for Level 4 or Level 5 paths. These are defense-in-depth
checks, not separate authorities. The PermissionBroker remains mandatory for any
future privileged operation.

The current Phase 11 engine has no merge, deployment, updater, or approval port.
It can produce only an expiring, evidence-bound proposal. A future trusted
release service must recompute the exact classification, re-run the required
gates, create a restore point where applicable, and obtain the appropriate
trusted authority immediately before mutation.

## Scope and limits

The policy protects typed repository changes and current known protected surfaces.
It is not a proof that arbitrary same-process Python is isolated, nor does a
filename heuristic prove the semantics of an unknown rewrite. Static analysis,
independent tests, security review, provenance, and the existing process
boundary remain required. Generated code never executes in the Trusted Core.

Regression coverage is in `tests/trusted_core/test_modification_trust.py` and
the existing security-constitution and improvement suites. It covers integration,
user-space, runtime, Broker/Vault, updater/recovery, renamed protected modules,
mixed patches, malformed metadata, and classifier-policy tampering.
