#!/usr/bin/env python3
"""Tests for deterministic C5 role and risk routing."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
REMOTE_ROOT = ROOT / "c5-remote"
MODULE_PATH = REMOTE_ROOT / "scripts" / "verify_role_routing.py"
ROUTING_PATH = REMOTE_ROOT / ".agents" / "role-routing.yaml"
ALL_SIX_ROLES = {
    "planner", "architect", "developer", "qa", "security-specialist", "integration"
}


def load_verifier():
    spec = importlib.util.spec_from_file_location("c5_role_routing", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load C5 role-routing verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class C5RoleRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = load_verifier()

    def test_governance_files_are_l3_and_all_roles(self) -> None:
        result = self.verifier.route_roles(
            [".agents/manifest.yaml"], "governance", "L3"
        )
        self.assertEqual(result["risk_level"], "L3")
        self.assertEqual(set(result["roles"]), ALL_SIX_ROLES)

    def test_agent_cannot_downgrade_security_path(self) -> None:
        with self.assertRaisesRegex(SystemExit, "risk_downgrade_attempt"):
            self.verifier.route_roles(["src/auth/token.py"], "feature", "L1")

    def test_agent_cannot_remove_required_security_role(self) -> None:
        with self.assertRaisesRegex(SystemExit, "required_role_removed_security-specialist"):
            self.verifier.route_roles(
                [".github/workflows/gate.yml"],
                "governance",
                "L3",
                requested_roles=["planner", "architect", "developer", "qa", "integration"],
            )

    def test_unknown_path_defaults_l3(self) -> None:
        result = self.verifier.route_roles(["mystery.bin"], "unknown", "L3")
        self.assertEqual(result["risk_level"], "L3")
        self.assertEqual(set(result["roles"]), ALL_SIX_ROLES)

    def test_docs_only_is_l1_with_default_roles(self) -> None:
        result = self.verifier.route_roles(["docs/guide.md"], "docs", "L1")
        self.assertEqual(result["risk_level"], "L1")
        self.assertEqual(
            result["roles"], ["planner", "developer", "qa", "integration"]
        )

    def test_mixed_paths_escalate_to_l3(self) -> None:
        result = self.verifier.route_roles(
            ["docs/guide.md", ".github/workflows/gate.yml"],
            "docs",
            "L3",
        )
        self.assertEqual(result["risk_level"], "L3")
        self.assertEqual(set(result["roles"]), ALL_SIX_ROLES)

    def test_agent_may_raise_risk(self) -> None:
        result = self.verifier.route_roles(["docs/guide.md"], "docs", "L3")
        self.assertEqual(result["risk_level"], "L3")
        self.assertEqual(set(result["roles"]), ALL_SIX_ROLES)

    def test_role_definition_cannot_claim_permissions(self) -> None:
        routing = read_json(ROUTING_PATH)
        routing["roles"][0]["permissions"] = ["administration:write"]
        with self.assertRaisesRegex(SystemExit, "role_permission_claim"):
            self.verifier.route_roles(
                ["docs/guide.md"], "docs", "L1", routing=routing
            )

    def test_unknown_role_fails_closed(self) -> None:
        routing = read_json(ROUTING_PATH)
        routing["defaults"]["roles"].append("release-manager")
        with self.assertRaisesRegex(SystemExit, "unknown_default_role_release-manager"):
            self.verifier.route_roles(
                ["docs/guide.md"], "docs", "L1", routing=routing
            )

    def test_duplicate_rule_id_fails_closed(self) -> None:
        routing = read_json(ROUTING_PATH)
        routing["rules"].append(copy.deepcopy(routing["rules"][0]))
        with self.assertRaisesRegex(SystemExit, "duplicate_routing_rule"):
            self.verifier.route_roles(
                ["docs/guide.md"], "docs", "L1", routing=routing
            )

    def test_schema_is_strict(self) -> None:
        schema = read_json(
            REMOTE_ROOT / ".agents" / "schemas" / "role-routing.schema.json"
        )
        self.assertIs(schema["additionalProperties"], False)
        self.assertIs(schema["$defs"]["role"]["additionalProperties"], False)
        self.assertIs(schema["$defs"]["rule"]["additionalProperties"], False)


if __name__ == "__main__":
    unittest.main()
