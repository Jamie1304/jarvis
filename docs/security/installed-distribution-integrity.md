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
It uses only evidence available from the installed `jarvis` distribution:

- the installed distribution version must equal `jarvis.__version__`;
- package-local trusted runtime/security files must exist;
- the distribution file inventory must contain `RECORD`; and
- `RECORD` SHA-256 and size entries must match the package-local files used by
  the trusted startup path.

This proves installed-file consistency and completeness for the checked
members. `RECORD` is not a publisher signature and does not authenticate who
produced the distribution. Release signing, recovery authentication, and
update authority remain separate controls.

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
| Package-local trusted modules | Installed runtime evidence |
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
