#!/usr/bin/env python3
"""Tests for the C5 vendor-neutral Provider contract."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
REMOTE_ROOT = ROOT / "c5-remote"
MODULE_PATH = REMOTE_ROOT / "scripts" / "verify_provider_contract.py"
MANIFEST = json.loads((REMOTE_ROOT / ".agents" / "manifest.yaml").read_text(encoding="utf-8"))
CODEX = {
    "schema_version": "V3.2.1-C5-PROVIDER-R1",
    "provider_id": "codex",
    "adapter_version": "1.0.0",
    "operation": "start",
    "health": "available",
    "capabilities": ["identify", "health", "start", "checkpoint", "stop", "resume"],
    "requested_permissions": [],
}


def load_verifier():
    spec = importlib.util.spec_from_file_location("c5_provider", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load provider verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class C5ProviderContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = load_verifier()

    def test_enabled_primary_provider_passes(self) -> None:
        result = self.verifier.verify_provider(CODEX, MANIFEST)
        self.assertEqual(result["provider_id"], "codex")
        self.assertEqual(result["status"], "enabled")

    def test_unknown_provider_fails_closed(self) -> None:
        provider = copy.deepcopy(CODEX)
        provider["provider_id"] = "unknown"
        with self.assertRaisesRegex(SystemExit, "provider_not_allowlisted"):
            self.verifier.verify_provider(provider, MANIFEST)

    def test_planned_provider_cannot_start(self) -> None:
        provider = copy.deepcopy(CODEX)
        provider["provider_id"] = "cursor"
        with self.assertRaisesRegex(SystemExit, "provider_not_enabled"):
            self.verifier.verify_provider(provider, MANIFEST)

    def test_provider_cannot_request_permissions(self) -> None:
        provider = copy.deepcopy(CODEX)
        provider["requested_permissions"] = ["administration:write"]
        with self.assertRaisesRegex(SystemExit, "provider_permission_claim"):
            self.verifier.verify_provider(provider, MANIFEST)

    def test_capability_drift_fails_closed(self) -> None:
        provider = copy.deepcopy(CODEX)
        provider["capabilities"].remove("checkpoint")
        with self.assertRaisesRegex(SystemExit, "provider_capability_drift"):
            self.verifier.verify_provider(provider, MANIFEST)

    def test_unknown_health_fails_closed(self) -> None:
        provider = copy.deepcopy(CODEX)
        provider["health"] = "unknown"
        with self.assertRaisesRegex(SystemExit, "provider_health_unknown"):
            self.verifier.verify_provider(provider, MANIFEST)

    def test_degraded_does_not_trigger_failover(self) -> None:
        with self.assertRaisesRegex(SystemExit, "source_health_not_failover_eligible"):
            self.verifier.verify_failover_eligibility("degraded")

    def test_unavailable_and_quota_exhausted_trigger_failover(self) -> None:
        for health in ("unavailable", "quota_exhausted"):
            with self.subTest(health=health):
                self.assertEqual(
                    self.verifier.verify_failover_eligibility(health), health
                )

    def test_schema_is_strict(self) -> None:
        schema = json.loads(
            (REMOTE_ROOT / ".agents" / "provider-contract.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(schema["properties"]["requested_permissions"]["maxItems"], 0)


if __name__ == "__main__":
    unittest.main()
