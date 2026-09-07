#!/usr/bin/env python3
"""Deterministic regression suite shipped with the C4 trust root."""

from __future__ import annotations

from datetime import datetime
import importlib.util
import json
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent
REMOTE_MODULE = ROOT / "verify_c4_credential_boundary.py"
LOCAL_MODULE = ROOT.parents[1] / "verify_c4_credential_boundary.py"
MODULE_PATH = REMOTE_MODULE if REMOTE_MODULE.is_file() else LOCAL_MODULE
REPOSITORY_ROOT = ROOT.parent
REMOTE_EVIDENCE = REPOSITORY_ROOT / "governance" / "c4-live-evidence.json"
LOCAL_EVIDENCE = ROOT.parents[1] / "c4-live-evidence-current.json"
EVIDENCE_PATH = REMOTE_EVIDENCE if REMOTE_EVIDENCE.is_file() else LOCAL_EVIDENCE
REMOTE_FIXTURES = ROOT / "c4-fixtures"
LOCAL_FIXTURES = ROOT.parents[1] / "c4-fixtures"
FIXTURES = REMOTE_FIXTURES if REMOTE_FIXTURES.is_dir() else LOCAL_FIXTURES
NOW = datetime.fromisoformat("2026-08-30T00:07:09+08:00")
NEGATIVE_CASES = {
    "inventory-human-credential-visible.json": "human_credential_channel_visible",
    "inventory-write-deploy-key.json": "write_capable_deploy_key",
    "inventory-classic-pat-role.json": "classic_pat_system_role",
}


def load_verifier():
    spec = importlib.util.spec_from_file_location("c4_remote_verifier", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load C4 verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(source: Path) -> dict[str, Any]:
    return json.loads(source.read_text(encoding="utf-8"))


def expect_failure(callable_object: Callable[[], object], reason: str) -> None:
    try:
        callable_object()
    except SystemExit as error:
        if reason not in str(error):
            raise AssertionError(f"expected {reason}, observed {error}") from error
    else:
        raise AssertionError(f"expected failure reason {reason}")


def main() -> None:
    verifier = load_verifier()
    result = verifier.verify(read_json(EVIDENCE_PATH), NOW)
    if result.get("agent_execution_user") != "v3-agent-runtime":
        raise AssertionError("safe evidence did not resolve to isolated runtime")
    for fixture_name, reason in NEGATIVE_CASES.items():
        fixture = read_json(FIXTURES / fixture_name)
        expect_failure(lambda fixture=fixture: verifier.verify(fixture, NOW), reason)
    print("C4_CREDENTIAL_BOUNDARY_REGRESSION=PASS cases=4")


if __name__ == "__main__":
    main()
