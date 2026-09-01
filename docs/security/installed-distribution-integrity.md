# Installed-distribution integrity boundary

JARVIS has two explicit startup evidence contexts. They share the
`RepositoryIntegrityClassifier` policy vocabulary, but they do not assume that
one filesystem layout exists in both contexts.

## Source checkout

`SourceCheckoutIntegrityEvidenceProvider` is used by local/test composition and
source-oriented validation. It validates the actual checkout root and requires
these trusted-core evidence files to exist and be regular, non-reparse files:

- the trusted runtime/security modules;
- `docs/security-constitution.md`;
- `scripts/quality.py`; and
- `pyproject.toml`.

The provider then classifies each path with the canonical classifier. This
keeps source/CI integrity checks meaningful without making them a runtime
dependency of an installed package.

## Installed distribution

Production composition uses `InstalledDistributionIntegrityEvidenceProvider`.
It uses only evidence available from the installed `jarvis` distribution, and
does not consult a source checkout, source resources, or an editable-install
fallback.

The provider resolves one physical site-packages root from package metadata and
requires exactly one safe `jarvis/` directory and one matching `*.dist-info/`
directory whose `METADATA` declares `Name: jarvis` and the installed package
version. It then reads `RECORD` directly from that dist-info directory and
independently enumerates both trees. Package metadata is not accepted as a
substitute for that filesystem inventory.

For every normal member, the canonical `RECORD` path must be safe, unique after
Windows separator/case normalization, confined to `jarvis/` or the exact
matching dist-info tree, and carry both an SHA-256 digest and a decimal byte
size. The actual regular file must exist under that same tree and match both.
Conversely, every actual normal file in those trees must be represented in
`RECORD`; therefore this includes package modules, non-critical support
modules, `METADATA`, `WHEEL`, `top_level.txt`, `INSTALLER`, `REQUESTED`, legal
metadata files, and other installed dist-info members. Missing rows, fake rows,
extra files, duplicate/case-colliding rows, malformed digests/sizes, traversal,
absolute/UNC/drive/reserved-device paths, and reparse points fail closed.

`RECORD` itself is the deliberately narrow self-hash exception: it must have
one exact blank hash/size row. Python bytecode is also deliberately bounded:
only `jarvis/**/__pycache__/<recorded-source-stem>.*.pyc` is allowed without a
normal file row, because installers may create or omit that cache after wheel
installation. It cannot authorize arbitrary unrecorded files, paths outside
JARVIS, or a source fallback.

The explicit Trusted Core subset remains a minimum-presence assertion on top
of the full inventory; it is no longer the completeness boundary. In
particular, mutating only the `INSTALLER` hash in `RECORD` is rejected even
when no Trusted Core source file changes.

This proves installer-recorded installed-file consistency, not publisher
identity or immutable authenticity. An attacker able to coherently replace a
member *and* rewrite `RECORD` is outside the protection provided by the wheel
format alone. Release signing, authenticated update/recovery authority,
filesystem ACLs, and the Trusted Core mutation gates remain separate controls.

Missing, malformed, inconsistent, or future/unsupported evidence fails closed
with `POLICY_CLASSIFICATION_INVALID`. No model output, generated package, or
filesystem existence heuristic can turn an integrity failure into trust.

## Optional project knowledge

The generated project knowledge index is external optional data. A source or
installed runtime may load it when the validated path is present. An absent
index produces an empty knowledge projection so a fresh installation does not
require a developer checkout. A present index still goes through its existing
strict schema, path, and reparse validation; malformed data fails startup.

The runtime therefore does not package `docs/`, `scripts/`, `tests/`, or the
repository `pyproject.toml` merely to satisfy startup. The artifact-only
regression runs from an unrelated working directory with no source checkout
on `PYTHONPATH`.

The smoke uses the existing explicit `TestOnlyInMemorySecretBackend` only for
the recovery-key seam so the packaging test remains deterministic on hosts where
Windows Credential Manager is unavailable. It still uses `environment="production"`
and the normal production composition path. The production default remains
Windows Credential Manager and fails closed when that backend cannot be used.

## Classification

| Evidence | Classification |
|---|---|
| Source checkout files and source policy | Source/CI evidence |
| Full `jarvis/` and matching dist-info inventory | Installed runtime evidence |
| Wheel `RECORD` hashes and sizes | Installed-file consistency, not publisher authenticity |
| Project knowledge index | Optional external generated data |
| Release signing and recovery authority | Separate authenticated release/recovery controls |

The owner has selected a custom commercial/proprietary license model. The
first-party `LICENSE.txt`, `EULA.txt`, and `PRIVACY_POLICY.txt` are packaged.
The software is identified by the custom SPDX expression
`LicenseRef-JARVIS-Proprietary`; the privacy policy is a separate notice and
is not the license expression. Owner identity, governing law, and the current
private-use address policy are recorded in those documents. Commercial
publication remains a separate legal-readiness decision because the geographic
business address and launch-specific disclosures are intentionally deferred.
