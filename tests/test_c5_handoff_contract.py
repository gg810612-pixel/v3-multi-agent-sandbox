#!/usr/bin/env python3
"""Tests for C5 single-writer lease and pushed-checkpoint handoff."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
REMOTE_ROOT = ROOT / "c5-remote"
MODULE_PATH = REMOTE_ROOT / "scripts" / "verify_handoff_contract.py"
BASE_SHA = "1" * 40
CHECKPOINT_SHA = "2" * 40
NOW = datetime(2026, 9, 17, 8, 0, tzinfo=timezone.utc)


def load_verifier():
    spec = importlib.util.spec_from_file_location("c5_handoff", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load handoff verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class C5HandoffContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = load_verifier()

    def valid_handoff(self) -> dict:
        handoff = {
            "schema_version": "V3.2.1-C5-HANDOFF-R1",
            "task_id": "task-c5-4",
            "repository": "gg810612-pixel/v3-multi-agent-sandbox",
            "branch": "c5/provider-failover",
            "base_sha": BASE_SHA,
            "checkpoint_sha": CHECKPOINT_SHA,
            "checkpoint_clean": True,
            "rules_hash": "3" * 64,
            "manifest_hash": "4" * 64,
            "risk_level": "L3",
            "completed_steps": ["tests", "checkpoint", "push"],
            "remaining_steps": ["resume", "final-validation"],
            "test_results": [{"name": "unit", "status": "pass", "artifact_digest": "sha256:" + "5" * 64}],
            "changed_paths": ["src/provider.py"],
            "known_risks": ["planned adapter remains disabled in live manifest"],
            "lease_released_at": "2026-09-17T07:30:00Z",
            "source_provider": "codex",
            "target_provider": "cursor",
            "created_at": "2026-09-17T07:31:00Z",
            "artifact_digest": "",
        }
        handoff["artifact_digest"] = self.verifier.compute_artifact_digest(handoff)
        return handoff

    def valid_lease(self) -> dict:
        return {
            "schema_version": "V3.2.1-C5-LEASE-R1",
            "repository": "gg810612-pixel/v3-multi-agent-sandbox",
            "branch": "c5/provider-failover",
            "leases": [
                {
                    "provider_id": "codex",
                    "session_id": "codex-session-1",
                    "status": "released",
                    "acquired_at": "2026-09-17T07:00:00Z",
                    "released_at": "2026-09-17T07:30:00Z",
                },
                {
                    "provider_id": "cursor",
                    "session_id": "cursor-session-1",
                    "status": "active",
                    "acquired_at": "2026-09-17T07:31:00Z",
                    "released_at": None,
                },
            ],
        }

    def test_valid_pushed_checkpoint_handoff_passes(self) -> None:
        result = self.verifier.verify_handoff(
            self.valid_handoff(), CHECKPOINT_SHA, self.valid_lease(), NOW
        )
        self.assertEqual(result["checkpoint_sha"], CHECKPOINT_SHA)
        self.assertEqual(result["target_provider"], "cursor")

    def test_two_active_writers_on_same_branch_fail(self) -> None:
        lease = self.valid_lease()
        lease["leases"][0]["status"] = "active"
        lease["leases"][0]["released_at"] = None
        with self.assertRaisesRegex(SystemExit, "active_writer_collision"):
            self.verifier.verify_handoff(self.valid_handoff(), CHECKPOINT_SHA, lease, NOW)

    def test_unpushed_checkpoint_fails(self) -> None:
        with self.assertRaisesRegex(SystemExit, "remote_checkpoint_mismatch"):
            self.verifier.verify_handoff(
                self.valid_handoff(), "9" * 40, self.valid_lease(), NOW
            )

    def test_primary_lease_must_be_released(self) -> None:
        lease = self.valid_lease()
        lease["leases"][0]["status"] = "active"
        lease["leases"][0]["released_at"] = None
        lease["leases"][1]["status"] = "released"
        lease["leases"][1]["released_at"] = "2026-09-17T07:32:00Z"
        with self.assertRaisesRegex(SystemExit, "source_lease_not_released"):
            self.verifier.verify_handoff(self.valid_handoff(), CHECKPOINT_SHA, lease, NOW)

    def test_target_cannot_acquire_before_source_release(self) -> None:
        lease = self.valid_lease()
        lease["leases"][1]["acquired_at"] = "2026-09-17T07:29:00Z"
        with self.assertRaisesRegex(SystemExit, "target_acquired_before_source_release"):
            self.verifier.verify_handoff(self.valid_handoff(), CHECKPOINT_SHA, lease, NOW)

    def test_dirty_checkpoint_fails(self) -> None:
        handoff = self.valid_handoff()
        handoff["checkpoint_clean"] = False
        handoff["artifact_digest"] = self.verifier.compute_artifact_digest(handoff)
        with self.assertRaisesRegex(SystemExit, "checkpoint_not_clean"):
            self.verifier.verify_handoff(handoff, CHECKPOINT_SHA, self.valid_lease(), NOW)

    def test_tampered_handoff_digest_fails(self) -> None:
        handoff = self.valid_handoff()
        handoff["remaining_steps"].append("tampered")
        with self.assertRaisesRegex(SystemExit, "handoff_digest_mismatch"):
            self.verifier.verify_handoff(handoff, CHECKPOINT_SHA, self.valid_lease(), NOW)

    def test_source_and_target_must_differ(self) -> None:
        handoff = self.valid_handoff()
        handoff["target_provider"] = "codex"
        handoff["artifact_digest"] = self.verifier.compute_artifact_digest(handoff)
        with self.assertRaisesRegex(SystemExit, "source_target_provider_collision"):
            self.verifier.verify_handoff(handoff, CHECKPOINT_SHA, self.valid_lease(), NOW)

    def test_schema_is_strict(self) -> None:
        schema = json.loads(
            (REMOTE_ROOT / ".agents" / "handoff.schema.json").read_text(encoding="utf-8")
        )
        self.assertIs(schema["additionalProperties"], False)
        self.assertIn("checkpoint_clean", schema["required"])


if __name__ == "__main__":
    unittest.main()
