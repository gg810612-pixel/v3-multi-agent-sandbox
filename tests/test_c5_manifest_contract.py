#!/usr/bin/env python3
"""Tests for the C5 manifest and Builder contract."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
REMOTE_ROOT = ROOT / "c5-remote"
MODULE_PATH = REMOTE_ROOT / "scripts" / "verify_governance_contract.py"
BASE_INVARIANTS = {
    "base-checks",
    "human-approval-only",
    "provenance-device",
    "credential-boundary",
}


def load_verifier():
    spec = importlib.util.spec_from_file_location("c5_manifest", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load C5 manifest verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class C5ManifestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = load_verifier()

    def copy_remote_root(self, temporary_directory: str) -> Path:
        target = Path(temporary_directory) / "repository"
        shutil.copytree(REMOTE_ROOT, target)
        return target

    def write_manifest(self, root: Path, manifest: dict) -> None:
        (root / ".agents" / "manifest.yaml").write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_valid_manifest_and_contract_pass(self) -> None:
        result = self.verifier.verify_manifest(REMOTE_ROOT, BASE_INVARIANTS)
        self.assertEqual(result["repository"], "gg810612-pixel/v3-multi-agent-sandbox")
        self.assertEqual(result["primary_provider"], "codex")
        self.assertEqual(result["enabled_providers"], ["codex"])
        self.assertEqual(set(result["preserved_checks"]), BASE_INVARIANTS)

    def test_manifest_digest_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.copy_remote_root(temporary_directory)
            path = root / "governance" / "global-rules.yaml"
            path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "manifest_digest_mismatch_global"):
                self.verifier.verify_manifest(root, BASE_INVARIANTS)

    def test_manifest_cannot_drop_c4_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.copy_remote_root(temporary_directory)
            manifest = read_json(root / ".agents" / "manifest.yaml")
            manifest["required_checks"]["preserve"].remove("credential-boundary")
            self.write_manifest(root, manifest)
            with self.assertRaisesRegex(SystemExit, "required_control_removed_credential-boundary"):
                self.verifier.verify_manifest(root, BASE_INVARIANTS)

    def test_role_permission_claim_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.copy_remote_root(temporary_directory)
            manifest = read_json(root / ".agents" / "manifest.yaml")
            manifest["roles"]["permissions"] = ["administration:write"]
            self.write_manifest(root, manifest)
            with self.assertRaisesRegex(SystemExit, "role_permission_escalation"):
                self.verifier.verify_manifest(root, BASE_INVARIANTS)

    def test_provider_permission_claim_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.copy_remote_root(temporary_directory)
            manifest = read_json(root / ".agents" / "manifest.yaml")
            manifest["providers"]["adapters"][0]["permissions"] = ["contents:write"]
            self.write_manifest(root, manifest)
            with self.assertRaisesRegex(SystemExit, "provider_permission_escalation"):
                self.verifier.verify_manifest(root, BASE_INVARIANTS)

    def test_manifest_path_traversal_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.copy_remote_root(temporary_directory)
            manifest = read_json(root / ".agents" / "manifest.yaml")
            manifest["rules"]["global"]["path"] = "../global-rules.yaml"
            self.write_manifest(root, manifest)
            with self.assertRaisesRegex(SystemExit, "unsafe_manifest_path_global"):
                self.verifier.verify_manifest(root, BASE_INVARIANTS)

    def test_symlink_escape_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.copy_remote_root(temporary_directory)
            outside = Path(temporary_directory) / "outside.json"
            outside.write_text("{}\n", encoding="utf-8")
            link = root / "governance" / "escaped.json"
            link.symlink_to(outside)
            manifest = read_json(root / ".agents" / "manifest.yaml")
            manifest["rules"]["global"]["path"] = "governance/escaped.json"
            self.write_manifest(root, manifest)
            with self.assertRaisesRegex(SystemExit, "manifest_path_escape_global"):
                self.verifier.verify_manifest(root, BASE_INVARIANTS)

    def test_unknown_top_level_key_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.copy_remote_root(temporary_directory)
            manifest = read_json(root / ".agents" / "manifest.yaml")
            manifest["override"] = {"merge_allowed": True}
            self.write_manifest(root, manifest)
            with self.assertRaisesRegex(SystemExit, "unknown_manifest_key_override"):
                self.verifier.verify_manifest(root, BASE_INVARIANTS)

    def test_missing_builder_contract_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = self.copy_remote_root(temporary_directory)
            contract = root / ".agents" / "builder-contract.md"
            contract.write_text(
                contract.read_text(encoding="utf-8").replace(
                    "AGENT_MERGE=DENY", "AGENT_MERGE=ALLOW"
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SystemExit, "builder_contract_marker_missing_AGENT_MERGE=DENY"):
                self.verifier.verify_manifest(root, BASE_INVARIANTS)

    def test_planned_providers_remain_disabled(self) -> None:
        manifest = read_json(REMOTE_ROOT / ".agents" / "manifest.yaml")
        statuses = {
            adapter["provider_id"]: adapter["status"]
            for adapter in manifest["providers"]["adapters"]
        }
        self.assertEqual(
            statuses,
            {"codex": "enabled", "cursor": "planned", "deepseek-harness": "planned"},
        )

    def test_schema_is_strict(self) -> None:
        schema = read_json(REMOTE_ROOT / ".agents" / "schemas" / "manifest.schema.json")
        self.assertIs(schema["additionalProperties"], False)
        self.assertIs(schema["properties"]["builder"]["additionalProperties"], False)
        self.assertIs(schema["$defs"]["providerAdapter"]["additionalProperties"], False)


if __name__ == "__main__":
    unittest.main()
