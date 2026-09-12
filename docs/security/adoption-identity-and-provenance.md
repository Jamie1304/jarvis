# Existing-capability adoption: identity and provenance boundary

## Contract

Discovery is evidence only. A Windows display name, registry entry, install
folder, filename, version string, publisher string, or candidate-provided hash
does not establish identity or trust.

The trusted adoption path is:

```text
bounded discovery
  -> WindowsFileIdentityProvider (handle identity + bounded SHA-256)
  -> WindowsSignerVerifier (Authenticode/WinVerifyTrust status)
  -> independent dependency provenance
  -> AdoptionPolicy
  -> exact AdoptionAttestation
  -> SetupConductor reinspection immediately before use
```

`WindowsFileIdentity` binds the stable volume/file identity where the native
API is available, content hash, size, type, and reparse status. The canonical
path and timestamps are diagnostic metadata; a path is never sufficient. The
native provider hashes through an opened file handle and rechecks the bounded
observation. Reparse-point targets are rejected. A changed file ID, canonical
path, hash, or reparse state fails closed.

`SignerEvidence` is an application-owned status from Authenticode verification
(`WinVerifyTrust` on Windows). JARVIS does not infer a signer from a filename,
publisher string, or candidate metadata. A valid signature is evidence only;
it does not certify the code, grant authority, or bypass package review,
PermissionBroker policy, sandboxing, or VerificationEngine.

Dependency provenance is separately observed from package/installer receipts or
bounded lock manifests. Missing provenance is explicit. Candidate self-reports
and one unverified source cannot manufacture provenance.

## Policy outcomes

`AdoptionPolicy` returns exactly one of:

- `ADOPT_VERIFIED`: trusted signature plus independent provenance and compatible
  identity evidence.
- `ADOPT_WITH_RESTRICTIONS`: explicit confirmation for a legitimate unsigned or
  weaker-chain read-only candidate; normal effect permissions remain required.
- `REQUIRES_USER_CONFIRMATION`: evidence is insufficient for silent adoption.
- `REQUIRES_REVALIDATION`: evidence is stale or no longer bound to the current
  candidate.
- `INCOMPATIBLE`: the capability contract does not fit the requested scope.
- `REJECTED`: malformed, reparse, invalid/revoked, or otherwise unsafe evidence.

Unsigned local tools are not impossible to adopt, but they cannot be silently
adopted and privileged use is not implied. Adoption is not an approval.

## Attestation and ownership

`AdoptionAttestation` is issued by trusted application code and binds:

- candidate ID and exact version
- stable file identity and content hash
- signer evidence fingerprint
- dependency provenance fingerprint
- compatibility/policy fingerprint
- workspace/setup/acquisition scope
- creation and expiry

The attestation is stored as setup-run evidence in the existing
`SQLiteSetupStore`; there is no second adoption database. It is also exposed as
a reference in the acquisition run/Trace. If an adopted executable participates
in a package lifecycle, its attestation reference belongs in that lifecycle
record's existing provenance references. The evidence never grants a
PermissionBroker decision and contains no raw credentials.

On restart, setup reloads the durable attestation reference but re-inspects the
current target before use. Expired, changed, or mismatched evidence requires
revalidation; it is not replayed blindly. A fresh setup decision is required
when the exact identity or scope changes.

## Windows limits

`WindowsFileIdentityProvider` and `WindowsSignerVerifier` are native Windows
observations, not a claim that signed code is safe. Authenticode chain policy,
revocation availability, installer provenance, dependency behavior, and the
security of the adopted program itself remain separate concerns. Adopted code
still runs only through the ordinary capability, sandbox, ToolRegistry,
PermissionBroker, and verification boundaries.

The real Windows identity check is opt-in via
`JARVIS_RUN_WINDOWS_IDENTITY_TESTS=1`; it observes the harmless configured
Python executable and performs no privileged action. Synthetic tests use only
repository-controlled injected providers.

## Current verification

The current deterministic run passed quality (1,351 tests, 6 skipped, 90%
coverage), deterministic workflows (26), deterministic permissions (72 passed,
1 skipped), v1 acceptance (19), and the opt-in native identity test (1 passed,
13 deselected). The native identity test is observation-only. On this developer
machine the default local Windows Credential Manager write used by trusted
recovery is unavailable; the runtime reports `RecoveryAuthorityUnavailable`
and fails closed. No plaintext or test backend is used in local production
mode.

**ADOPTION_IDENTITY_PROVENANCE: RESOLVED** for the declared generic adoption
contract. This does not claim that every third-party executable is safe or that
optional Windows dependencies, voice, browser, or hardware are available.
