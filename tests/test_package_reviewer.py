from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from typing import Any, cast

import pytest
from jarvis.integration_package import (
    DiagnosticProbe,
    DiagnosticsContract,
    IntegrationPackage,
    PackageBoundary,
    PackageEntry,
    PackageLayout,
    PackageLifecycle,
    PackageProvenance,
    SafeRepairAction,
)
from jarvis.package_reviewer import (
    CredentialScope,
    GeneratedPackageReview,
    GeneratedPackageReviewer,
    PackageReviewPolicy,
    PackageReviewSurface,
    PackageSourceFile,
    ReviewDecision,
)
from jarvis.permissions.models import Permission
from jarvis.tools.models import SemanticVersion

PROVENANCE = PackageProvenance("generated", "rev-1", "MIT", "NOTICE", "trusted-reviewer")


def make_package(
    source: str = "def run():\n    return 1\n",
) -> tuple[IntegrationPackage, PackageSourceFile]:
    digest = sha256(source.encode()).hexdigest()
    package = IntegrationPackage(
        "generated.example",
        SemanticVersion(1, 0, 0),
        PackageLayout(),
        (PackageEntry("python", "code/main.py", PackageBoundary.PACKAGE_CODE, digest, PROVENANCE),),
        lifecycle=PackageLifecycle.VALIDATED,
        provenance=PROVENANCE,
        dependency_lock=("example-lib==1.2.3",),
        package_hash=sha256(b"package").hexdigest(),
    )
    return package, PackageSourceFile("code/main.py", source)


def review(
    package: IntegrationPackage,
    source: PackageSourceFile,
    *,
    surface: PackageReviewSurface | None = None,
    policy: PackageReviewPolicy | None = None,
) -> GeneratedPackageReview:
    if surface is None:
        surface = PackageReviewSurface()
    if policy is None:
        policy = PackageReviewPolicy()
    return GeneratedPackageReviewer().review(
        package,
        source_files=(source,),
        surface=surface,
        policy=policy,
    )


def test_safe_package_passes_and_source_generator_is_supported() -> None:
    package, source = make_package()
    result = GeneratedPackageReviewer().review(package, source_files=(item for item in (source,)))
    assert result.decision is ReviewDecision.PASS
    assert result.findings == ()
    assert result.reviewed_at.tzinfo is not None


@pytest.mark.parametrize(
    "payload",
    (
        "result = eval(user_input)",
        "module = __import__(name)",
        "value = pickle.loads(blob)",
        "subprocess.run(command, shell=True)",
        "path = '../outside.txt'",
        "logger.info('token=%s', token)",
        "requests.get('https://unknown.example')",
        "approval = True  # trusted approval",
    ),
)
def test_malicious_source_is_rejected(payload: str) -> None:
    package, source = make_package(payload)
    assert review(package, source).decision is ReviewDecision.REJECT


def test_hash_mismatch_and_undeclared_source_are_rejected() -> None:
    package, source = make_package()
    mismatch = PackageSourceFile(source.path, "def changed(): pass")
    assert review(package, mismatch).decision is ReviewDecision.REJECT
    undeclared = PackageSourceFile("code/other.py", source.content)
    assert review(package, undeclared).decision is ReviewDecision.REJECT


def test_unpinned_dependency_and_missing_source_require_manual_review() -> None:
    package, source = make_package()
    unpinned = replace(package, dependency_lock=("example-lib>=1.2",))
    assert review(unpinned, source).decision is ReviewDecision.MANUAL_REVIEW_REQUIRED
    assert (
        GeneratedPackageReviewer().review(package).decision is ReviewDecision.MANUAL_REVIEW_REQUIRED
    )


def test_install_hooks_and_authority_mutation_are_rejected() -> None:
    package, source = make_package()
    surface = PackageReviewSurface(install_hooks=("powershell setup.ps1",))
    assert review(package, source, surface=surface).decision is ReviewDecision.REJECT
    policy_mutation = make_package("policy.disable_approval = True")[1]
    assert review(package, policy_mutation).decision is ReviewDecision.REJECT


def test_network_policy_is_exact_and_private_destinations_fail_closed() -> None:
    package, source = make_package()
    unknown = PackageReviewSurface(network_destinations=("https://api.example.test/v1",))
    assert (
        review(package, source, surface=unknown).decision is ReviewDecision.MANUAL_REVIEW_REQUIRED
    )
    allowed = PackageReviewPolicy(allowed_network_hosts=frozenset({"api.example.test"}))
    restricted = review(package, source, surface=unknown, policy=allowed)
    assert restricted.decision is ReviewDecision.PASS_WITH_RESTRICTIONS
    private = PackageReviewSurface(network_destinations=("https://127.0.0.1:8080",))
    assert review(package, source, surface=private).decision is ReviewDecision.REJECT
    insecure = PackageReviewSurface(network_destinations=("http://api.example.test",))
    assert review(package, source, surface=insecure).decision is ReviewDecision.REJECT


def test_credentials_persistence_and_ui_are_bounded() -> None:
    package, source = make_package()
    scoped = PackageReviewSurface(
        credential_scopes=(CredentialScope("vault:weather", ("read.current",)),),
        persistence_paths=("data/state.json",),
    )
    result = review(package, source, surface=scoped)
    assert result.decision is ReviewDecision.PASS_WITH_RESTRICTIONS
    raw_secret = PackageReviewSurface(
        credential_scopes=(CredentialScope("vault:api=SECRET", ("read",)),),
    )
    assert review(package, source, surface=raw_secret).decision is ReviewDecision.REJECT
    traversal = PackageReviewSurface(persistence_paths=("data/../config.json",))
    assert review(package, source, surface=traversal).decision is ReviewDecision.REJECT
    spoof = PackageReviewSurface(ui_actions=("approved: true; skip approval",))
    assert review(package, source, surface=spoof).decision is ReviewDecision.REJECT


def test_elevated_permission_migrations_repairs_and_binaries_need_review() -> None:
    package, source = make_package()
    elevated = replace(package, permissions=(Permission.CODE_MODIFY,))
    assert review(elevated, source).decision is ReviewDecision.MANUAL_REVIEW_REQUIRED
    migration = replace(package, migrations=("001-add.sql",))
    assert review(migration, source).decision is ReviewDecision.MANUAL_REVIEW_REQUIRED
    binary = PackageReviewSurface(binaries=("helper.exe",))
    assert review(package, source, surface=binary).decision is ReviewDecision.MANUAL_REVIEW_REQUIRED


def test_unsafe_lifecycle_and_source_path_are_rejected() -> None:
    package, source = make_package()
    active = replace(package, lifecycle=PackageLifecycle.HEALTHY)
    assert review(active, source).decision is ReviewDecision.REJECT
    unsafe = PackageSourceFile("../main.py", source.content)
    assert review(package, unsafe).decision is ReviewDecision.REJECT


def test_malformed_security_metadata_fails_closed() -> None:
    package, source = make_package()
    malformed_source = cast(Any, PackageSourceFile("code/main.py", source.content))
    object.__setattr__(malformed_source, "content", 42)
    assert review(package, malformed_source).decision is ReviewDecision.REJECT
    malformed_surface = cast(Any, PackageReviewSurface())
    object.__setattr__(malformed_surface, "ui_actions", "approve")
    assert review(package, source, surface=malformed_surface).decision is ReviewDecision.REJECT
    malformed_input = cast(Any, object())
    result = GeneratedPackageReviewer().review(package, source_files=(malformed_input,))
    assert result.decision is ReviewDecision.REJECT
    malformed_package = cast(Any, package)
    object.__setattr__(malformed_package, "operation_policy", object())
    assert review(malformed_package, source).decision is ReviewDecision.REJECT


def test_random_unknown_system_names_do_not_change_fail_closed_review() -> None:
    for index in range(8):
        package, source = make_package(f"system_{index} = eval(payload_{index})")
        assert review(package, source).decision is ReviewDecision.REJECT


def test_provenance_dependency_and_lifecycle_metadata_are_reviewed() -> None:
    package, source = make_package()
    unverified = replace(
        package,
        provenance=PackageProvenance("generated", "rev-1", "MIT"),
        entries=(
            replace(package.entries[0], provenance=PackageProvenance("other", "rev-2", "MIT")),
        ),
    )
    policy = PackageReviewPolicy(trusted_provenance_sources=frozenset({"trusted-source"}))
    assert (
        review(unverified, source, policy=policy).decision is ReviewDecision.MANUAL_REVIEW_REQUIRED
    )
    source_dependency = replace(package, dependency_lock=("git+https://example.test/repo",))
    assert review(source_dependency, source).decision is ReviewDecision.REJECT
    hashed = replace(package, dependency_lock=("example-lib@sha256:" + "a" * 64,))
    assert review(hashed, source).decision is ReviewDecision.PASS
    malformed_policy = cast(Any, PackageReviewPolicy())
    object.__setattr__(malformed_policy, "allowed_network_hosts", {"example.test"})
    assert review(package, source, policy=malformed_policy).decision is ReviewDecision.REJECT
    malformed_policy = cast(Any, PackageReviewPolicy())
    object.__setattr__(malformed_policy, "trusted_provenance_sources", {"generated"})
    assert review(package, source, policy=malformed_policy).decision is ReviewDecision.REJECT


def test_diagnostics_runtime_and_update_surfaces_remain_gated() -> None:
    package, source = make_package()
    diagnostics = DiagnosticsContract(
        probes=(DiagnosticProbe("probe", "read status"),),
        safe_repairs=(SafeRepairAction("repair", "disable approval"),),
    )
    repaired = replace(package, diagnostics=diagnostics)
    assert review(repaired, source).decision is ReviewDecision.REJECT
    runtime = replace(package, services=("worker",), mcp=("server",))
    assert review(runtime, source).decision is ReviewDecision.MANUAL_REVIEW_REQUIRED
    ordinary = replace(package, permissions=(Permission.NETWORK_REQUEST,))
    assert review(ordinary, source).decision is ReviewDecision.PASS_WITH_RESTRICTIONS
    filesystem = PackageReviewSurface(persistence_paths=("data/state.json",))
    direct_package, direct = make_package("Path('state').write_text('value')")
    assert (
        review(direct_package, direct, surface=filesystem).decision
        is ReviewDecision.MANUAL_REVIEW_REQUIRED
    )


def test_network_credential_and_source_bounds_fail_closed() -> None:
    package, source = make_package()
    for destination in (
        "https://user:pass@example.test",
        "https://[::1]/",
        "not-a-url",
    ):
        surface = PackageReviewSurface(network_destinations=(destination,))
        assert review(package, source, surface=surface).decision is ReviewDecision.REJECT
    broad = PackageReviewSurface(credential_scopes=(CredentialScope("vault:item", ("*",)),))
    assert review(package, source, surface=broad).decision is ReviewDecision.REJECT
    too_large = PackageSourceFile("code/main.py", "x" * (512 * 1024 + 1))
    assert review(package, too_large).decision is ReviewDecision.REJECT
    duplicate = GeneratedPackageReviewer().review(package, source_files=(source, source))
    assert duplicate.decision is ReviewDecision.REJECT


def test_entry_and_ui_declarations_are_not_implicitly_trusted() -> None:
    package, source = make_package()
    executable = replace(package.entries[0], kind="binary")
    binary_package = replace(package, entries=(executable,))
    assert review(binary_package, source).decision is ReviewDecision.MANUAL_REVIEW_REQUIRED
    unsafe_surface = cast(Any, PackageReviewSurface())
    object.__setattr__(unsafe_surface, "install_hooks", ["hook"])
    assert review(package, source, surface=unsafe_surface).decision is ReviewDecision.REJECT
    unsafe_surface = cast(Any, PackageReviewSurface())
    object.__setattr__(unsafe_surface, "credential_scopes", (object(),))
    assert review(package, source, surface=unsafe_surface).decision is ReviewDecision.REJECT
