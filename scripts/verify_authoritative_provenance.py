#!/usr/bin/env python3
"""Fail-closed C3 reconciliation of GitHub actor, device, and self-report data."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, NoReturn


POLICY_ID = "V3.2.1-C3-AUTHORITATIVE-PROVENANCE-DEVICE-R1"
REQUIRED_DEVICE_FIELDS = {
    "device_id",
    "device_type",
    "owner",
    "container_capable",
    "agent_allowed",
    "company_code_allowed",
    "project_id",
    "repository",
    "role",
    "actor_login",
    "actor_type",
    "credential_kind",
    "credential_id",
    "allowed_tools",
    "allowed_actions",
    "approved_by",
    "approved_at",
    "expires_at",
    "policy_reference",
}
ACTION_PERMISSION = {
    "opened": "open_pull_request",
    "synchronize": "update_pull_request",
}


def fail(reason: str) -> NoReturn:
    raise SystemExit(f"C3_PROVENANCE_DEVICE=FAIL policy={POLICY_ID} reason={reason}")


def require_mapping(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(reason)
    return value


def require_string(mapping: dict[str, Any], key: str, reason: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        fail(reason)
    return value.strip()


def parse_timestamp(value: Any, reason: str) -> datetime:
    if not isinstance(value, str) or not value:
        fail(reason)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError:
        fail(reason)
    if timestamp.tzinfo is None:
        fail(reason)
    return timestamp


def validate_registry(registry: dict[str, Any]) -> tuple[str, set[str], list[dict[str, Any]]]:
    if registry.get("schema_version") != "1.0":
        fail("unsupported_registry_schema")
    repository = require_string(registry, "repository", "missing_registry_repository")
    project_id = require_string(registry, "project_id", "missing_registry_project_id")
    risk_levels = registry.get("enforced_risk_levels")
    if not isinstance(risk_levels, list) or not risk_levels:
        fail("missing_enforced_risk_levels")
    if any(level not in {"L2", "L3"} for level in risk_levels):
        fail("invalid_enforced_risk_level")

    devices = registry.get("devices")
    if not isinstance(devices, list) or not devices:
        fail("missing_registry_devices")
    if any(not isinstance(device, dict) for device in devices):
        fail("invalid_registry_device")

    typed_devices: list[dict[str, Any]] = devices
    for device in typed_devices:
        missing = sorted(REQUIRED_DEVICE_FIELDS - set(device))
        if missing:
            fail(f"missing_device_field_{missing[0]}")
        if device.get("project_id") != project_id:
            fail("device_project_mismatch")
        if device.get("repository") != repository:
            fail("device_repository_mismatch")
        if device.get("actor_type") != "Bot":
            fail("machine_actor_type_not_bot")
        if device.get("credential_kind") != "github_app_installation":
            fail("unsupported_device_credential_kind")
        if not isinstance(device.get("agent_allowed"), bool):
            fail("invalid_agent_allowed")
        if not isinstance(device.get("allowed_tools"), list):
            fail("invalid_allowed_tools")
        if not isinstance(device.get("allowed_actions"), list):
            fail("invalid_allowed_actions")
        parse_timestamp(device.get("approved_at"), "invalid_device_approved_at")
        parse_timestamp(device.get("expires_at"), "invalid_device_expires_at")

    builders = [device for device in typed_devices if device.get("role") == "builder"]
    reviewers = [device for device in typed_devices if device.get("role") == "reviewer"]
    if len(builders) != 1 or len(reviewers) != 1:
        fail("missing_unique_builder_or_reviewer")
    builder = builders[0]
    reviewer = reviewers[0]
    builder_actor = (
        builder.get("repository"),
        builder.get("actor_login"),
        builder.get("actor_type"),
    )
    reviewer_actor = (
        reviewer.get("repository"),
        reviewer.get("actor_login"),
        reviewer.get("actor_type"),
    )
    builder_credential = (
        builder.get("credential_kind"),
        builder.get("credential_id"),
    )
    reviewer_credential = (
        reviewer.get("credential_kind"),
        reviewer.get("credential_id"),
    )
    if builder_actor == reviewer_actor or builder_credential == reviewer_credential:
        fail("authoritative_identity_collision")

    device_ids = [device.get("device_id") for device in typed_devices]
    actors = [
        (device.get("repository"), device.get("actor_login"), device.get("actor_type"))
        for device in typed_devices
    ]
    credentials = [
        (device.get("credential_kind"), device.get("credential_id"))
        for device in typed_devices
    ]
    if len(set(device_ids)) != len(device_ids):
        fail("duplicate_device_id")
    if len(set(actors)) != len(actors):
        fail("actor_mapping_not_one_to_one")
    if len(set(credentials)) != len(credentials):
        fail("credential_mapping_not_one_to_one")
    return repository, set(risk_levels), typed_devices


def parse_self_reported_role(commit_message: str) -> str | None:
    roles = re.findall(
        r"^X-Agent-Role:\s*([^\r\n]+?)\s*$",
        commit_message,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    normalized = {role.strip().lower() for role in roles if role.strip()}
    if len(normalized) > 1:
        fail("self_report_role_ambiguous")
    return next(iter(normalized), None)


def verify(
    registry: dict[str, Any],
    event: dict[str, Any],
    commit_message: str,
    now: datetime,
    risk_level: str,
) -> dict[str, str | None]:
    if now.tzinfo is None:
        fail("now_must_be_timezone_aware")
    repository, enforced_risk_levels, devices = validate_registry(registry)
    if risk_level not in enforced_risk_levels:
        fail("risk_level_not_enforced")

    event_repository = require_mapping(
        event.get("repository"), "missing_event_repository"
    )
    event_repo_name = require_string(
        event_repository, "full_name", "missing_event_repository_full_name"
    )
    if event_repo_name != repository:
        fail("event_repository_mismatch")
    action = require_string(event, "action", "missing_event_action")
    if action not in ACTION_PERMISSION:
        fail("unsupported_pull_request_action")

    sender = require_mapping(event.get("sender"), "missing_event_sender")
    sender_login = require_string(sender, "login", "missing_event_sender_login")
    sender_type = require_string(sender, "type", "missing_event_sender_type")
    pull_request = require_mapping(
        event.get("pull_request"), "missing_event_pull_request"
    )
    head = require_mapping(
        pull_request.get("head"), "missing_event_pull_request_head"
    )
    head_sha = require_string(head, "sha", "missing_event_head_sha")
    if re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
        fail("invalid_event_head_sha")

    matches = [
        device
        for device in devices
        if device.get("repository") == event_repo_name
        and device.get("actor_login") == sender_login
        and device.get("actor_type") == sender_type
    ]
    if len(matches) != 1:
        fail("unmapped_authoritative_actor")
    device = matches[0]
    if device.get("role") != "builder":
        fail("authoritative_role_not_builder")
    if device.get("agent_allowed") is not True:
        fail("device_agent_not_allowed")
    required_action = ACTION_PERMISSION[action]
    if required_action not in device.get("allowed_actions", []):
        fail("device_action_not_allowed")

    approved_at = parse_timestamp(
        device.get("approved_at"), "invalid_device_approved_at"
    )
    expires_at = parse_timestamp(
        device.get("expires_at"), "invalid_device_expires_at"
    )
    now_utc = now.astimezone(timezone.utc)
    if approved_at.astimezone(timezone.utc) > now_utc:
        fail("device_approval_not_yet_valid")
    if expires_at.astimezone(timezone.utc) <= now_utc:
        fail("device_expired")

    self_reported_role = parse_self_reported_role(commit_message)
    if self_reported_role is not None and self_reported_role != device.get("role"):
        fail("self_report_role_mismatch")

    return {
        "device_id": str(device["device_id"]),
        "credential_id": str(device["credential_id"]),
        "authoritative_actor": sender_login,
        "authoritative_role": str(device["role"]),
        "self_reported_role": self_reported_role,
        "head_sha": head_sha,
        "risk_level": risk_level,
    }


def read_json(path: Path, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail(reason)
    return require_mapping(value, reason)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--event", required=True, type=Path)
    parser.add_argument("--commit-message-file", required=True, type=Path)
    parser.add_argument("--risk-level", required=True, choices=["L2", "L3"])
    parser.add_argument("--now")
    args = parser.parse_args()

    registry = read_json(args.registry, "registry_read_failed")
    event = read_json(args.event, "event_read_failed")
    try:
        commit_message = args.commit_message_file.read_text(encoding="utf-8")
    except OSError:
        fail("commit_message_read_failed")
    now = (
        parse_timestamp(args.now, "invalid_now")
        if args.now
        else datetime.now(timezone.utc)
    )
    result = verify(registry, event, commit_message, now, args.risk_level)
    print(
        "C3_PROVENANCE_DEVICE=PASS "
        f"policy={POLICY_ID} device_id={result['device_id']} "
        f"actor={result['authoritative_actor']} role={result['authoritative_role']} "
        f"head={result['head_sha']} risk={result['risk_level']}"
    )


if __name__ == "__main__":
    main()
