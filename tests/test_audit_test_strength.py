from scripts.acceptance.audit_test_strength import audit_test_strength


def test_accepts_qualification_harness_marker_and_runner_selection() -> None:
    diff = """
diff --git a/pyproject.toml b/pyproject.toml
+++ b/pyproject.toml
+    "real_qualification: native-sensitive qualification route",
diff --git a/scripts/quality.py b/scripts/quality.py
+++ b/scripts/quality.py
+        [sys.executable, "-m", "coverage", "run", "-m", "pytest", "-m", "not real_qualification"],
diff --git a/tests/test_pair.py b/tests/test_pair.py
+++ b/tests/test_pair.py
+@pytest.mark.real_qualification
+async def test_pair() -> None:
+    assert pair_result is not None
"""

    result = audit_test_strength(diff)

    assert result["qualification_only_bypass"] == "NO"
    assert result["result"] == "PASS"


def test_rejects_executable_qualification_gate_in_product_code() -> None:
    diff = """
diff --git a/jarvis/runtime.py b/jarvis/runtime.py
+++ b/jarvis/runtime.py
+if real_qualification:
+    return trusted_success
"""

    result = audit_test_strength(diff)

    assert result["qualification_only_bypass"] == "YES"
    assert result["result"] == "BLOCKED"


def test_rejects_dynamic_qualification_gate_even_when_hidden_in_test_code() -> None:
    diff = """
diff --git a/tests/test_pair.py b/tests/test_pair.py
+++ b/tests/test_pair.py
+if os.getenv("REAL_QUALIFICATION") == "1":
+    return trusted_success
"""

    result = audit_test_strength(diff)

    assert result["qualification_only_bypass"] == "YES"
    assert result["result"] == "BLOCKED"
