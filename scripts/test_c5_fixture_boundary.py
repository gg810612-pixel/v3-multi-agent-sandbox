"""Regression: synthetic scenarios must never authorize a required C5 gate."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
BASE, HEAD = "1" * 40, "2" * 40
SCENARIOS = (
    "global-rule-weakening", "role-permission-escalation", "risk-downgrade",
    "writer-collision", "unpushed-failover", "unknown-provider", "intake-injection",
    "test-padding", "flaky-run", "bare-exception", "forged-human-exception",
)


def load_runner():
    spec = importlib.util.spec_from_file_location("boundary_gate", ROOT / "run_c5_validation_scenario.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FixtureBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = load_runner()

    def reject(self, check):
        with self.assertRaisesRegex(SystemExit, "trusted_runtime_evidence_unavailable"):
            self.runner.verify(self.root, check, BASE, HEAD, datetime.now(timezone.utc))

    def test_empty_repository_cannot_pass_quality(self):
        self.assertEqual(list(self.root.iterdir()), [])
        self.reject("test-quality")

    def test_untrusted_test_or_evidence_cannot_enable_quality(self):
        (self.root / "test_behavior.py").write_text("def test_ok(): assert 2 + 2 == 4\n")
        (self.root / "evidence.json").write_text(json.dumps({"status": "PASS", "head_sha": HEAD}))
        self.reject("test-quality")

    def test_all_marker_values_cannot_authorize_either_gate(self):
        for scenario in (*SCENARIOS, "final-green", "unknown"):
            (self.root / ".c5-validation-scenario.json").write_text(json.dumps({"scenario": scenario}))
            for check in ("test-quality", "governance-contract"):
                with self.subTest(scenario=scenario, check=check):
                    self.reject(check)

    def test_cli_exits_nonzero_without_success_claim(self):
        result = subprocess.run([
            sys.executable, "-I", "-B", str(ROOT / "run_c5_validation_scenario.py"),
            "--repository-root", str(self.root), "--check", "test-quality",
            "--base-sha", BASE, "--head-sha", HEAD,
        ], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trusted_runtime_evidence_unavailable", result.stderr)
        self.assertNotIn("=PASS", result.stdout + result.stderr)

    def test_fixture_cli_requires_explicit_self_test_flag(self):
        script = ROOT / "run_c5_fixture_selftest.py"
        self.assertTrue(script.is_file())
        result = subprocess.run([
            sys.executable, "-I", "-B", str(script),
            "--repository-root", str(self.root), "--check", "test-quality",
            "--base-sha", BASE, "--head-sha", HEAD,
        ], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--self-test-only", result.stderr)
        self.assertNotIn("=PASS", result.stdout + result.stderr)

    def test_runtime_entrypoint_cannot_import_or_dispatch_fixtures(self):
        source = (ROOT / "run_c5_validation_scenario.py").read_text()
        self.assertNotIn("importlib", source)
        self.assertNotIn("quality_case", source)
        self.assertNotIn("run_c5_fixture_selftest", source)


if __name__ == "__main__":
    unittest.main()
