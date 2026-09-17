#!/usr/bin/env python3
"""Tests for the interface-only, untrusted C5 Task Intake envelope."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent
REMOTE_ROOT = ROOT / "c5-remote"
MODULE_PATH = REMOTE_ROOT / "scripts" / "verify_task_intake.py"
FIXTURES = ROOT / "c5-fixtures"
NOW = datetime(2026, 9, 17, 9, 0, tzinfo=timezone.utc)


def load_verifier():
    spec = importlib.util.spec_from_file_location("c5_intake", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load task-intake verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class C5TaskIntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = load_verifier()

    def test_safe_github_issue_is_accepted_as_untrusted_data(self) -> None:
        result = self.verifier.verify_intake(fixture("intake-github-issue.json"), NOW)
        self.assertIs(result["accepted_as_data"], True)
        self.assertEqual(result["flags"], [])

    def test_every_source_must_remain_untrusted(self) -> None:
        for source in ("linear", "github_issue", "chatgpt", "line", "dashboard"):
            envelope = fixture("intake-github-issue.json")
            envelope["source"] = source
            envelope["trust"] = "trusted"
            with self.subTest(source=source):
                with self.assertRaisesRegex(SystemExit, "intake_trust_must_be_untrusted"):
                    self.verifier.verify_intake(envelope, NOW)

    def test_linear_implementation_state_claim_is_flagged(self) -> None:
        result = self.verifier.verify_intake(fixture("intake-linear.json"), NOW)
        self.assertIn("implementation_state_claim", result["flags"])

    def test_chatgpt_and_line_instruction_escalation_is_quarantined(self) -> None:
        for name in ("intake-chatgpt-injection.json", "intake-line-injection.json"):
            with self.subTest(name=name):
                result = self.verifier.verify_intake(fixture(name), NOW)
                self.assertIn("instruction_escalation", result["flags"])
                self.assertIs(result["accepted_as_data"], True)

    def test_zero_width_character_fails_normalization(self) -> None:
        envelope = fixture("intake-github-issue.json")
        envelope["intent"] = "safe\u200bhidden"
        with self.assertRaisesRegex(SystemExit, "normalized_text_contains_forbidden_character"):
            self.verifier.verify_intake(envelope, NOW)

    def test_non_nfc_text_fails_normalization(self) -> None:
        envelope = fixture("intake-github-issue.json")
        envelope["title"] = "Cafe\u0301"
        with self.assertRaisesRegex(SystemExit, "normalized_text_not_nfc"):
            self.verifier.verify_intake(envelope, NOW)

    def test_invalid_attachment_digest_fails(self) -> None:
        envelope = fixture("intake-github-issue.json")
        envelope["attachments"] = [{"name": "x.txt", "digest": "sha256:bad", "media_type": "text/plain"}]
        with self.assertRaisesRegex(SystemExit, "invalid_attachment_digest"):
            self.verifier.verify_intake(envelope, NOW)

    def test_credential_material_is_rejected_not_persisted(self) -> None:
        envelope = fixture("intake-github-issue.json")
        envelope["intent"] = "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        with self.assertRaisesRegex(SystemExit, "credential_material_detected"):
            self.verifier.verify_intake(envelope, NOW)

    def test_embedded_instruction_flag_must_match_recomputed_value(self) -> None:
        envelope = fixture("intake-line-injection.json")
        envelope["normalization"]["embedded_instruction_detected"] = False
        with self.assertRaisesRegex(SystemExit, "normalization_flag_mismatch_embedded_instruction_detected"):
            self.verifier.verify_intake(envelope, NOW)

    def test_future_timestamp_fails_closed(self) -> None:
        envelope = fixture("intake-github-issue.json")
        envelope["received_at"] = "2026-09-17T10:00:00Z"
        with self.assertRaisesRegex(SystemExit, "intake_received_in_future"):
            self.verifier.verify_intake(envelope, NOW)

    def test_interface_scope_contains_no_connector_backend(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8").lower()
        for prohibited in (
            "import requests", "import urllib", "import socket", "http.server",
            "linebot", "flask", "fastapi", "webhook", "persistent_queue",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, source)

    def test_schema_is_strict(self) -> None:
        schema = json.loads(
            (REMOTE_ROOT / ".agents" / "task-intake.schema.json").read_text(encoding="utf-8")
        )
        self.assertIs(schema["additionalProperties"], False)
        self.assertIs(schema["$defs"]["attachment"]["additionalProperties"], False)


if __name__ == "__main__":
    unittest.main()
