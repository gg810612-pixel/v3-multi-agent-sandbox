#!/usr/bin/env python3
"""Verify C5 single-writer lease ordering and pushed-checkpoint handoff."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, NoReturn


POLICY_ID = "V3.2.1-C5-HANDOFF-CONTRACT-R1"
REPOSITORY = "gg810612-pixel/v3-multi-agent-sandbox"
PROVIDERS = {"codex", "cursor", "deepseek-harness"}
HANDOFF_KEYS = {"schema_version", "task_id", "repository", "branch", "base_sha", "checkpoint_sha", "checkpoint_clean", "rules_hash", "manifest_hash", "risk_level", "completed_steps", "remaining_steps", "test_results", "changed_paths", "known_risks", "lease_released_at", "source_provider", "target_provider", "created_at", "artifact_digest"}
LEASE_KEYS = {"schema_version", "repository", "branch", "leases"}
LEASE_ENTRY_KEYS = {"provider_id", "session_id", "status", "acquired_at", "released_at"}


def fail(reason: str) -> NoReturn:
    raise SystemExit(f"C5_HANDOFF=FAIL policy={POLICY_ID} reason={reason}")


def mapping(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(reason)
    return value


def exact_keys(value: dict[str, Any], expected: set[str], prefix: str) -> None:
    unknown = sorted(set(value) - expected)
    if unknown:
        fail(f"unknown_{prefix}_key_{unknown[0]}")
    missing = sorted(expected - set(value))
    if missing:
        fail(f"missing_{prefix}_key_{missing[0]}")


def timestamp(value: Any, reason: str) -> datetime:
    if not isinstance(value, str) or not value:
        fail(reason)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        result = datetime.fromisoformat(normalized)
    except ValueError:
        fail(reason)
    if result.tzinfo is None:
        fail(reason)
    return result.astimezone(timezone.utc)


def compute_artifact_digest(handoff: dict[str, Any]) -> str:
    payload = dict(handoff)
    payload.pop("artifact_digest", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def string_list(value: Any, reason: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        fail(reason)
    return value


def verify_handoff(handoff: dict[str, Any], remote_head: str, lease: dict[str, Any], now: datetime) -> dict[str, str]:
    handoff = mapping(handoff, "invalid_handoff")
    exact_keys(handoff, HANDOFF_KEYS, "handoff")
    if handoff.get("schema_version") != "V3.2.1-C5-HANDOFF-R1":
        fail("unsupported_handoff_schema")
    if handoff.get("repository") != REPOSITORY:
        fail("handoff_repository_mismatch")
    for key in ("base_sha", "checkpoint_sha"):
        if not isinstance(handoff.get(key), str) or re.fullmatch(r"[0-9a-f]{40}", handoff[key]) is None:
            fail(f"invalid_{key}")
    for key in ("rules_hash", "manifest_hash"):
        if not isinstance(handoff.get(key), str) or re.fullmatch(r"[0-9a-f]{64}", handoff[key]) is None:
            fail(f"invalid_{key}")
    if handoff.get("checkpoint_clean") is not True:
        fail("checkpoint_not_clean")
    if remote_head != handoff.get("checkpoint_sha"):
        fail("remote_checkpoint_mismatch")
    if handoff.get("artifact_digest") != compute_artifact_digest(handoff):
        fail("handoff_digest_mismatch")
    source = handoff.get("source_provider")
    target = handoff.get("target_provider")
    if source not in PROVIDERS or target not in PROVIDERS:
        fail("unknown_handoff_provider")
    if source == target:
        fail("source_target_provider_collision")
    if handoff.get("risk_level") not in {"L1", "L2", "L3"}:
        fail("invalid_handoff_risk")
    branch = handoff.get("branch")
    if not isinstance(branch, str) or not branch or PurePosixPath(branch).is_absolute() or ".." in PurePosixPath(branch).parts:
        fail("unsafe_handoff_branch")
    for key in ("completed_steps", "remaining_steps", "changed_paths", "known_risks"):
        string_list(handoff.get(key), f"invalid_{key}")
    tests = handoff.get("test_results")
    if not isinstance(tests, list) or not tests:
        fail("missing_test_results")
    for raw in tests:
        result = mapping(raw, "invalid_test_result")
        exact_keys(result, {"name", "status", "artifact_digest"}, "test_result")
        if result.get("status") not in {"pass", "fail", "inconclusive"}:
            fail("invalid_test_status")
        if not isinstance(result.get("artifact_digest"), str) or re.fullmatch(r"sha256:[0-9a-f]{64}", result["artifact_digest"]) is None:
            fail("invalid_test_artifact_digest")

    if now.tzinfo is None:
        fail("now_must_be_timezone_aware")
    released_at = timestamp(handoff.get("lease_released_at"), "invalid_lease_released_at")
    created_at = timestamp(handoff.get("created_at"), "invalid_handoff_created_at")
    if created_at < released_at or created_at > now.astimezone(timezone.utc):
        fail("invalid_handoff_time_order")

    lease = mapping(lease, "invalid_lease")
    exact_keys(lease, LEASE_KEYS, "lease")
    if lease.get("schema_version") != "V3.2.1-C5-LEASE-R1":
        fail("unsupported_lease_schema")
    if lease.get("repository") != REPOSITORY or lease.get("branch") != branch:
        fail("lease_scope_mismatch")
    entries = lease.get("leases")
    if not isinstance(entries, list) or not entries:
        fail("missing_leases")
    validated: list[dict[str, Any]] = []
    for raw in entries:
        entry = mapping(raw, "invalid_lease_entry")
        exact_keys(entry, LEASE_ENTRY_KEYS, "lease_entry")
        if entry.get("provider_id") not in PROVIDERS:
            fail("unknown_lease_provider")
        if entry.get("status") not in {"active", "released"}:
            fail("invalid_lease_status")
        acquired = timestamp(entry.get("acquired_at"), "invalid_lease_acquired_at")
        released = None if entry.get("released_at") is None else timestamp(entry.get("released_at"), "invalid_lease_released_at")
        if entry.get("status") == "active" and released is not None:
            fail("active_lease_has_release_time")
        if entry.get("status") == "released" and (released is None or released < acquired):
            fail("released_lease_time_invalid")
        validated.append({**entry, "acquired": acquired, "released": released})

    active = [entry for entry in validated if entry["status"] == "active"]
    if len(active) > 1:
        fail("active_writer_collision")
    source_entries = [entry for entry in validated if entry["provider_id"] == source]
    target_entries = [entry for entry in validated if entry["provider_id"] == target]
    if len(source_entries) != 1 or len(target_entries) != 1:
        fail("source_target_lease_missing")
    source_entry = source_entries[0]
    target_entry = target_entries[0]
    if source_entry["status"] != "released" or source_entry["released"] is None:
        fail("source_lease_not_released")
    if source_entry["released"] != released_at:
        fail("source_release_time_mismatch")
    if target_entry["status"] != "active":
        fail("target_lease_not_active")
    if target_entry["acquired"] <= source_entry["released"]:
        fail("target_acquired_before_source_release")

    return {"checkpoint_sha": str(handoff["checkpoint_sha"]), "target_provider": str(target)}
