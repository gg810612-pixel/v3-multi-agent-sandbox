#!/usr/bin/env python3
"""Tests for the C5 Global / Project Rules precedence contract."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
REMOTE_ROOT = ROOT / "c5-remote"
MODULE_PATH = REMOTE_ROOT / "scripts" / "verify_rules_precedence.py"
GLOBAL_PATH = REMOTE_ROOT / "governance" / "global-rules.yaml"
PROJECT_PATH = REMOTE_ROOT / "governance" / "project-rules.yaml"
RISK_PATH = REMOTE_ROOT / "governance" / "risk-paths.yaml"
EXPECTED_REPOSITORY = "gg810612-pixel/v3-multi-agent-sandbox"


def load_verifier():
    spec = importlib.util.spec_from_file_location("c5_rules", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load C5 rules verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class C5RulesPrecedenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = load_verifier()

    def setUp(self) -> None:
        self.global_rules = read_json(GLOBAL_PATH)
        self.project_rules = read_json(PROJECT_PATH)
        self.risk_map = read_json(RISK_PATH)

    def test_policy_is_versioned(self) -> None:
        self.assertEqual(
            self.verifier.POLICY_ID,
            "V3.2.1-C5-RULES-PRECEDENCE-R1",
        )

    def test_repository_rules_resolve_without_weakening(self) -> None:
        result = self.verifier.resolve_rules(
            self.global_rules,
            self.project_rules,
        )
        self.assertEqual(result["repository"], EXPECTED_REPOSITORY)
        self.assertIn("agent-no-merge", result["deny"])
        self.assertIn("credential-boundary", result["required"])
        self.assertNotIn("administer-repository", result["allow"])

    def test_project_cannot_remove_global_deny(self) -> None:
        project = copy.deepcopy(self.project_rules)
        project["rules"]["deny"].remove("agent-no-merge")
        with self.assertRaisesRegex(SystemExit, "global_deny_removed"):
            self.verifier.resolve_rules(self.global_rules, project)

    def test_project_cannot_remove_global_required_rule(self) -> None:
        project = copy.deepcopy(self.project_rules)
        project["rules"]["required"].remove("fail-closed")
        with self.assertRaisesRegex(SystemExit, "global_required_removed"):
            self.verifier.resolve_rules(self.global_rules, project)

    def test_project_cannot_expand_allow(self) -> None:
        project = copy.deepcopy(self.project_rules)
        project["rules"]["allow"].append("administer-repository")
        with self.assertRaisesRegex(SystemExit, "project_allow_expands_global"):
            self.verifier.resolve_rules(self.global_rules, project)

    def test_both_layers_cannot_delete_immutable_no_merge_baseline(self) -> None:
        global_rules = copy.deepcopy(self.global_rules)
        project_rules = copy.deepcopy(self.project_rules)
        global_rules["rules"]["deny"].remove("agent-no-merge")
        project_rules["rules"]["deny"].remove("agent-no-merge")
        with self.assertRaisesRegex(SystemExit, "baseline_global_deny_missing_agent-no-merge"):
            self.verifier.resolve_rules(global_rules, project_rules)

    def test_both_layers_cannot_delete_c4_required_control(self) -> None:
        global_rules = copy.deepcopy(self.global_rules)
        project_rules = copy.deepcopy(self.project_rules)
        global_rules["rules"]["required"].remove("credential-boundary")
        project_rules["rules"]["required"].remove("credential-boundary")
        with self.assertRaisesRegex(SystemExit, "baseline_global_required_missing_credential-boundary"):
            self.verifier.resolve_rules(global_rules, project_rules)

    def test_global_allow_cannot_grant_merge(self) -> None:
        global_rules = copy.deepcopy(self.global_rules)
        global_rules["rules"]["allow"].append("merge-pull-request")
        with self.assertRaisesRegex(SystemExit, "forbidden_global_allow_merge-pull-request"):
            self.verifier.resolve_rules(global_rules, self.project_rules)

    def test_unknown_rule_key_fails_closed(self) -> None:
        project = copy.deepcopy(self.project_rules)
        project["rules"]["override"] = ["agent-no-merge"]
        with self.assertRaisesRegex(SystemExit, "unknown_rules_key_override"):
            self.verifier.resolve_rules(self.global_rules, project)

    def test_wrong_repository_fails_closed(self) -> None:
        project = copy.deepcopy(self.project_rules)
        project["repository"] = "attacker/fork"
        with self.assertRaisesRegex(SystemExit, "project_repository_mismatch"):
            self.verifier.resolve_rules(self.global_rules, project)

    def test_duplicate_rule_id_fails_closed(self) -> None:
        project = copy.deepcopy(self.project_rules)
        project["rules"]["deny"].append(project["rules"]["deny"][0])
        with self.assertRaisesRegex(SystemExit, "duplicate_project_deny"):
            self.verifier.resolve_rules(self.global_rules, project)

    def test_sensitive_paths_are_l3(self) -> None:
        for path in (
            ".github/workflows/gate.yml",
            ".agents/manifest.yaml",
            "AGENTS.md",
            "governance/project-rules.yaml",
            "src/auth/token.py",
            "src/payments/charge.py",
            "infra/service.tf",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    self.verifier.classify_paths([path], self.risk_map),
                    "L3",
                )

    def test_sensitive_filename_tokens_are_l3(self) -> None:
        for path in ("src/auth.py", "src/delete_user.py", "src/permissions.ts"):
            with self.subTest(path=path):
                self.assertEqual(
                    self.verifier.classify_paths([path], self.risk_map),
                    "L3",
                )

    def test_known_source_path_is_l2(self) -> None:
        self.assertEqual(
            self.verifier.classify_paths(["src/widgets/render.py"], self.risk_map),
            "L2",
        )

    def test_non_sensitive_docs_path_is_l1(self) -> None:
        self.assertEqual(
            self.verifier.classify_paths(["docs/operator-guide.md"], self.risk_map),
            "L1",
        )

    def test_mixed_paths_take_highest_risk(self) -> None:
        self.assertEqual(
            self.verifier.classify_paths(
                ["docs/operator-guide.md", ".github/workflows/gate.yml"],
                self.risk_map,
            ),
            "L3",
        )

    def test_unknown_path_defaults_l3(self) -> None:
        self.assertEqual(
            self.verifier.classify_paths(["mystery.bin"], self.risk_map),
            "L3",
        )

    def test_unsafe_relative_path_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "unsafe_changed_path"):
            self.verifier.classify_paths(["../outside.txt"], self.risk_map)

    def test_invalid_default_risk_fails_closed(self) -> None:
        risk_map = copy.deepcopy(self.risk_map)
        risk_map["default_risk"] = "L1"
        with self.assertRaisesRegex(SystemExit, "default_risk_must_be_l3"):
            self.verifier.classify_paths(["docs/readme.md"], risk_map)

    def test_json_schema_rejects_unknown_properties(self) -> None:
        schema = read_json(
            REMOTE_ROOT / ".agents" / "schemas" / "rules.schema.json"
        )
        self.assertIs(schema["additionalProperties"], False)
        self.assertIs(
            schema["properties"]["rules"]["additionalProperties"],
            False,
        )


if __name__ == "__main__":
    unittest.main()
