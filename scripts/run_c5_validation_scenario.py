#!/usr/bin/env python3
"""Fail-closed legacy entrypoint. Real PR evidence collection is not implemented.

Containment only: do not connect this entrypoint to a required workflow until a
reviewed implementation can validate actual, independently collected evidence.
Candidate paths and marker files cannot opt into a success fallback.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import NoReturn


def fail(reason: str) -> NoReturn:
    raise SystemExit(f"C5_RUNTIME_GATE=FAIL reason={reason}")


def verify(root: Path, check: str, base_sha: str, head_sha: str, now: datetime) -> NoReturn:
    if check not in {"governance-contract", "test-quality"}:
        fail("unsupported_check")
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
           for value in (base_sha, head_sha)) or base_sha == head_sha:
        fail("invalid_runtime_sha")
    # Never read/import/execute candidate data or accept self-reported evidence.
    fail("trusted_runtime_evidence_unavailable")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--check", required=True, choices=["governance-contract", "test-quality"])
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    args = parser.parse_args()
    verify(args.repository_root, args.check, args.base_sha, args.head_sha, datetime.now(timezone.utc))


if __name__ == "__main__":
    main()
