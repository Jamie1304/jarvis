"""Canonical 115-test registry. The tuples are intentionally data, not executable claims."""

from __future__ import annotations

from typing import Final, cast

from jarvis.acceptance.models import AutomationLevel, TestClassification, TestSpec

_PHASES: Final[tuple[tuple[str, str, int, int], ...]] = (
    ("A", "Basal Product", 1, 3),
    ("B", "UI Blueprint", 4, 7),
    ("C", "Home + Chat", 8, 12),
    ("D", "Personality", 13, 15),
    ("E", "Tasks + Planning", 16, 20),
    ("F", "Permissions", 21, 25),
    ("G", "Memory", 26, 30),
    ("H", "Voice", 31, 35),
    ("I", "Camera + Computer Control", 36, 40),
    ("J", "Browser + Research", 41, 44),
    ("K", "Unknown Capability", 45, 55),
    ("L", "Google Home / TV Case", 56, 59),
    ("M", "Home Assistant / VM", 60, 63),
    ("N", "iPhone / Remote", 64, 64),
    ("O", "MCP", 65, 65),
    ("P", "Credentials", 66, 67),
    ("Q", "Proactive Autonomy", 68, 69),
    ("R", "Procedure Learning", 70, 71),
    ("S", "Scheduler + Automations", 72, 74),
    ("T", "Notifications", 75, 76),
    ("U", "Models", 77, 79),
    ("V", "Resources", 80, 81),
    ("W", "System Health", 82, 83),
    ("X", "Safe Mode", 84, 85),
    ("Y", "Self-Update", 86, 87),
    ("Z", "Backup + Restore", 88, 89),
    ("AA", "Self-Improvement", 90, 90),
    ("AB", "Settings", 91, 92),
    ("AC", "Control Center / Navigation", 93, 93),
    ("AD", "Generated UI", 94, 95),
    ("AE", "Activity / Trace", 96, 96),
    ("AF", "Knowledge", 97, 99),
    ("AG", "Effect Preview / Undo", 100, 101),
    ("AH", "Installer", 102, 104),
    ("AI", "First Run", 105, 108),
    ("AJ", "Golden Workflows", 109, 110),
    ("AK", "Long-Run Product Use", 111, 112),
    ("AL", "Final Unknown Goal", 113, 115),
)

_TITLES: Final[tuple[str, ...]] = (
    "Clean startup",
    "Startup without Ollama",
    "Forced termination",
    "UI blueprint comparison",
    "Resizing",
    "High DPI",
    "Color semantics",
    "Home idle clarity",
    "Simple chat",
    "Long inspect-only request",
    "Mid-conversation correction",
    "Stop/cancel",
    "Dutch interaction quality",
    "English ↔ Dutch language switching",
    "Personality/verbosity/style feedback capture",
    "Simple filesystem task with real verification",
    "Multi-step read-only analysis",
    "Pause/resume without duplicated effect",
    "Restart during task without duplicate effect",
    "Modify plan before authorization",
    "File read scope",
    "File write scope distinct from read",
    "Permission denial produces no action",
    "Changed arguments invalidate prior approval",
    "Expired/stale approval cannot authorize",
    "Learn explicit preference and persist across restart",
    "Inspect memory provenance/confidence/state",
    "Correct memory and supersede conflicting prior inference",
    "Delete memory and prove removal",
    "Pause learning and prove no normal persistent memory",
    "Push-to-talk reliability",
    "Wake-word behavior",
    "Barge-in / stop speaking",
    "Microphone disappears/recovery",
    "TTS quality across Dutch/English/technical/path content",
    "Camera observation and visible privacy state",
    "Camera busy/unavailable recovery",
    "Notepad controlled E2E",
    "Clipboard read/write",
    "Fresh screenshot/screen-state observation",
    "Browser navigation using actual page state",
    "Fill web form without submitting",
    "Web prompt-injection resistance",
    "Research quality/current-source evaluation",
    "Select unknown safe service",
    "Give only end goal; no implementation hints",
    "Capability gap detected semantically",
    "Research official/current reusable solution first",
    "Traceable design",
    "JARVIS generates Integration Package",
    "Sandbox + static review",
    "Exact minimal approval",
    "Activation into dynamic Capability Registry",
    "Perform real safe external action",
    "Restart and reuse capability",
    "High-level Google Home/TV objective",
    "Trusted authentication/credential flow",
    "Real TV state/read/action/physical verification",
    "Generated dynamic TV UI",
    "Install Home Assistant in isolated environment",
    "Inspect provisioning plan",
    "Approval and incremental approval",
    "Concrete health verification",
    "Safe iPhone/remote-control capability",
    "Real MCP lifecycle",
    "API credential without raw-token leakage",
    "Revoke credential and prove failure",
    "Detect repeated workflow/opportunity",
    "Decline + cooldown",
    "Measure first execution",
    "Repeat identical goal and reuse procedure",
    "One-time future task/reminder",
    "Recurring automation lifecycle",
    "Overlap control",
    "Low-priority completion no spam",
    "Approval outranks normal info",
    "Adopt existing Ollama",
    "Model/provider outage + recovery",
    "Correct routing",
    "Idle CPU/RAM/GPU observations",
    "Heavy local-model load",
    "Diagnose + safely repair stopped Ollama",
    "Capability defect diagnose before rebuild",
    "Safe Mode restricts privileged automation",
    "Safe Mode explanation",
    "Update preview",
    "Controlled failed update",
    "Backup normal product state",
    "Restore into test installation",
    "Real small non-security bug candidate",
    "Every setting persists",
    "Invalid setting input",
    "Control-center surfaces clarity",
    "Generated capability controls",
    "Generated UI inherits design system",
    "Activity explains trusted execution",
    "Add and retrieve unique fact",
    "Modify document and reindex",
    "Knowledge prompt injection",
    "Reversible action + undo",
    "Irreversible preview is truthful",
    "Clean Windows environment",
    "Product UI installation",
    "Uninstall semantics",
    "Clean-profile onboarding",
    "Hardware detection",
    "Privacy/routing choice",
    "Controlled first-run Test Drive",
    "Define owner's stable workflows",
    "Persist exact workflow prompts",
    "One complete day of ordinary use",
    "One complete week of ordinary use",
    "Genuinely unknown useful end goal",
    "Complete adaptive chain",
    "Final user-vs-implementation score",
)


def _phase(test_number: int) -> str:
    for code, name, start, end in _PHASES:
        if start <= test_number <= end:
            return f"{code} — {name}"
    raise AssertionError(test_number)


def _defaults(number: int) -> dict[str, object]:
    if number in (111, 112):
        return {
            "classification": TestClassification.LONG_RUNNING,
            "automation_level": AutomationLevel.LONG_RUNNING,
            "required_environment": "campaign_store",
        }
    if number in (4, 5, 6, 7, 93, 94, 95):
        return {
            "classification": TestClassification.REAL_WINDOWS,
            "automation_level": AutomationLevel.AUTOMATABLE_WITH_REAL_WINDOWS,
            "required_environment": "native_windows_desktop",
        }
    if number in (31, 32, 33, 34, 35, 36, 37, 39, 40, 106):
        return {
            "classification": TestClassification.SYNTHETIC_HARDWARE,
            "automation_level": AutomationLevel.AUTOMATABLE_WITH_SYNTHETIC_FIXTURE,
            "required_environment": "synthetic_device_fixture",
        }
    if number in (
        45,
        48,
        49,
        50,
        51,
        53,
        54,
        55,
        56,
        57,
        58,
        59,
        64,
        65,
        77,
        78,
        82,
        83,
        97,
        98,
        99,
        113,
        114,
    ):
        return {
            "classification": TestClassification.VM,
            "automation_level": AutomationLevel.AUTOMATABLE_WITH_VM,
            "required_environment": "workbench_vm_or_disposable_test_vm",
        }
    if number in (102, 103, 104):
        return {
            "classification": TestClassification.REAL_WINDOWS,
            "automation_level": AutomationLevel.AUTOMATABLE_WITH_REAL_WINDOWS,
            "required_environment": "clean_windows_vm_required",
        }
    if number in (13, 15, 85, 109, 110, 115):
        return {
            "classification": TestClassification.HUMAN_JUDGMENT,
            "automation_level": AutomationLevel.HUMAN_JUDGMENT_REQUIRED,
            "required_environment": "owner_or_reviewer",
        }
    if number in (44, 66, 67, 68, 69, 70, 71):
        return {
            "classification": TestClassification.EXTERNAL_TEST_SERVICE,
            "automation_level": AutomationLevel.AUTOMATABLE_WITH_EXTERNAL_TEST_SERVICE,
            "required_environment": "synthetic_external_service",
        }
    if number in (43, 60, 61, 62, 63, 86, 87, 88, 89, 90, 91, 92, 100, 101, 105, 107, 108):
        return {
            "classification": TestClassification.VM,
            "automation_level": AutomationLevel.AUTOMATABLE_WITH_VM,
            "required_environment": "disposable_test_vm",
        }
    if number in (1, 2, 3, 16, 17, 18, 19, 20, 38, 41, 42, 46, 47, 52, 79, 80, 81, 84, 96):
        return {
            "classification": TestClassification.AUTO,
            "automation_level": AutomationLevel.FULLY_AUTOMATED_NOW,
            "required_environment": "local_test_harness",
        }
    return {
        "classification": TestClassification.AUTO,
        "automation_level": AutomationLevel.FUTURE_PRODUCT_FEATURE_REQUIRED,
        "required_environment": "product_runtime",
    }


def build_specs() -> tuple[TestSpec, ...]:
    specs: list[TestSpec] = []
    for number, title in enumerate(_TITLES, 1):
        defaults = _defaults(number)
        classification = cast(TestClassification, defaults["classification"])
        automation_level = cast(AutomationLevel, defaults["automation_level"])
        environment = cast(str, defaults["required_environment"])
        specs.append(
            TestSpec(
                test_id=f"{number:03}",
                title=title,
                phase=_phase(number),
                objective=title,
                tags=(f"phase-{_phase(number).split(' ')[0].lower()}",),
                risk="medium",
                mutation_level="read_only",
                required_capabilities=(),
                prerequisites=(),
                execution_contract="Run the declared objective and collect independent evidence.",
                expected_outcomes=("objective outcome is observed",),
                assertions=("declared outcome is true",),
                evidence_requirements=("machine-readable result",),
                cleanup="release owned resources",
                timeout_seconds=60,
                retry_policy="never_after_unknown_effect",
                human_requirement=None,
                owner_approval_required=False,
                host_access_required=classification is TestClassification.REAL_WINDOWS,
                vm_policy="prefer_workbench_then_disposable"
                if classification is TestClassification.VM
                else "not_applicable",
                security_relevance="review_required"
                if number in (21, 22, 23, 24, 25, 66, 67, 84, 86, 87, 90, 94, 95, 99, 101)
                else "normal",
                failure_severity="RELEASE_BLOCKER"
                if number in (23, 24, 25, 43, 51, 52, 57, 66, 67, 84, 86, 87, 90, 94, 95, 99, 101)
                else "MEDIUM",
                classification=classification,
                automation_level=automation_level,
                required_environment=environment,
            )
        )
    return tuple(specs)


SPECS: Final[tuple[TestSpec, ...]] = build_specs()


def validate_specs(specs: tuple[TestSpec, ...] = SPECS) -> None:
    ids = [item.test_id for item in specs]
    expected = [f"{number:03}" for number in range(1, 116)]
    if ids != expected:
        raise ValueError(
            "canonical IDs must be exactly 001..115; "
            f"missing={sorted(set(expected) - set(ids))}; "
            f"duplicate={len(ids) != len(set(ids))}"
        )
