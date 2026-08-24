#!/usr/bin/env python3
"""Deterministic regression suite shipped with the C3 trust root."""

from __future__ import annotations

from datetime import datetime
import importlib.util
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
REMOTE_MODULE = ROOT / "verify_authoritative_provenance.py"
LOCAL_MODULE = ROOT.parents[1] / "verify_c3_authoritative_provenance.py"
MODULE_PATH = REMOTE_MODULE if REMOTE_MODULE.is_file() else LOCAL_MODULE
REPOSITORY_ROOT = ROOT.parent.parent
REGISTRY = REPOSITORY_ROOT / "governance" / "device-registry.json"
if not REGISTRY.is_file():
    REGISTRY = ROOT.parent / "governance" / "device-registry.json"
FIXTURES = ROOT / "c3-fixtures"
if not FIXTURES.is_dir():
    FIXTURES = ROOT.parents[1] / "c3-fixtures"
NOW = datetime.fromisoformat("2026-08-24T14:00:00+00:00")


def load_verifier():
    spec = importlib.util.spec_from_file_location("c3_remote_verifier", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load C3 verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def expect_failure(callable_object, reason: str) -> None:
    try:
        callable_object()
    except SystemExit as error:
        if reason not in str(error):
            raise AssertionError(f"expected {reason}, observed {error}") from error
    else:
        raise AssertionError(f"expected failure reason {reason}")


def main() -> None:
    verifier = load_verifier()
    registry = read_json(REGISTRY)
    builder_event = read_json(FIXTURES / "event-builder-synchronize.json")
    result = verifier.verify(registry, builder_event, "", NOW, "L2")
    if result.get("authoritative_role") != "builder":
        raise AssertionError("valid Builder event did not resolve to builder")

    expect_failure(
        lambda: verifier.verify(
            registry,
            builder_event,
            "subject\n\nX-Agent-Role: reviewer",
            NOW,
            "L2",
        ),
        "self_report_role_mismatch",
    )
    expect_failure(
        lambda: verifier.verify(
            registry,
            read_json(FIXTURES / "event-unmapped-synchronize.json"),
            "",
            NOW,
            "L2",
        ),
        "unmapped_authoritative_actor",
    )
    expect_failure(
        lambda: verifier.verify(
            read_json(FIXTURES / "registry-expired-builder.json"),
            builder_event,
            "",
            NOW,
            "L2",
        ),
        "device_expired",
    )
    expect_failure(
        lambda: verifier.verify(
            read_json(FIXTURES / "registry-identity-collision.json"),
            builder_event,
            "",
            NOW,
            "L2",
        ),
        "authoritative_identity_collision",
    )
    print("C3_AUTHORITATIVE_PROVENANCE_REGRESSION=PASS cases=5")


if __name__ == "__main__":
    main()
