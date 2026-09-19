"""Conservative diagnosis derived from structured evidence, not raw process logs."""

from __future__ import annotations

from jarvis.testing.models import TestDiagnosis, TestRun, TestRunStatus


class TestFailureDiagnoser:
    """Classify failures without reading or rewriting the authoritative log artifacts."""

    def diagnose(self, run: TestRun) -> TestDiagnosis:
        """Return an advisory summary that remains separate from raw evidence."""

        codes = tuple(item.code for item in run.failure_evidence)
        if run.status is TestRunStatus.PASSED:
            return TestDiagnosis(run.run_id, run.status, "Suite passed", None, codes)
        if run.status is TestRunStatus.TIMED_OUT:
            summary, layer = "Suite exceeded its deadline", "runner_or_test_deadlock"
        elif run.status is TestRunStatus.CANCELLED:
            summary, layer = "Suite was intentionally cancelled", "orchestration"
        elif run.status is TestRunStatus.MALFORMED:
            summary, layer = (
                "Suite did not produce its required machine-readable output",
                "test_adapter",
            )
        elif run.status is TestRunStatus.CRASHED:
            summary, layer = "Test process did not start or crashed", "process_environment"
        elif run.status is TestRunStatus.REJECTED:
            summary, layer = (
                "Test request was rejected by the trusted catalog boundary",
                "test_policy",
            )
        elif run.status is TestRunStatus.SKIPPED:
            summary, layer = "Suite is hardware/manual gated", "hardware"
        else:
            summary, layer = "Suite reported one or more failed checks", run.suite.category.value
        return TestDiagnosis(run.run_id, run.status, summary, layer, codes)
