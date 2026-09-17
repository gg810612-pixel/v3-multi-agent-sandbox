#!/usr/bin/env python3
"""Fail-closed verifier for the C5 manifest and Builder contract."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, NoReturn


POLICY_ID = "V3.2.1-C5-GOVERNANCE-CONTRACT-R1"
SCHEMA_VERSION = "V3.2.1-C5-MANIFEST-R1"
EXPECTED_REPOSITORY = "gg810612-pixel/v3-multi-agent-sandbox"
IMMUTABLE_REQUIRED_CHECKS = {
    "base-checks",
    "human-approval-only",
    "provenance-device",
    "credential-boundary",
}
ADDED_CHECKS = {"governance-contract", "test-quality"}
CONTRACT_MARKERS = {
    "AGENT_MERGE=DENY",
    "HUMAN_APPROVAL=REQUIRED",
    "ROLE_PERMISSION_ESCALATION=DENY",
    "SINGLE_WRITER=REQUIRED",
    "UNTRUSTED_INTAKE=REQUIRED",
    "FAILOVER_REQUIRES_PUSHED_CHECKPOINT=REQUIRED",
}
TOP_KEYS = {"schema_version", "manifest_version", "project", "rules", "identity", "builder", "roles", "providers", "handoff", "intake", "required_checks"}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def fail(reason: str) -> NoReturn:
    raise SystemExit(f"C5_GOVERNANCE_CONTRACT=FAIL policy={POLICY_ID} reason={reason}")


def require_mapping(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(reason)
    return value


def exact_keys(mapping: dict[str, Any], expected: set[str], prefix: str) -> None:
    unknown = sorted(set(mapping) - expected)
    if unknown:
        fail(f"unknown_{prefix}_key_{unknown[0]}")
    missing = sorted(expected - set(mapping))
    if missing:
        fail(f"missing_{prefix}_key_{missing[0]}")


def read_json(path: Path, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail(reason)
    return require_mapping(value, reason)


def safe_repository_file(root: Path, raw_path: Any, label: str) -> Path:
    if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path:
        fail(f"unsafe_manifest_path_{label}")
    relative = PurePosixPath(raw_path)
    if relative.is_absolute() or ".." in relative.parts or raw_path.startswith("./"):
        fail(f"unsafe_manifest_path_{label}")
    root_resolved = root.resolve()
    candidate = root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        fail(f"manifest_path_missing_{label}")
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        fail(f"manifest_path_escape_{label}")
    if not resolved.is_file():
        fail(f"manifest_path_not_file_{label}")
    return resolved


def verify_file_digest(root: Path, entry: Any, label: str) -> None:
    file_entry = require_mapping(entry, f"invalid_rule_reference_{label}")
    exact_keys(file_entry, {"path", "sha256"}, f"rule_reference_{label}")
    expected = file_entry.get("sha256")
    if not isinstance(expected, str) or SHA256_PATTERN.fullmatch(expected) is None:
        fail(f"invalid_manifest_digest_{label}")
    path = safe_repository_file(root, file_entry.get("path"), label)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        fail(f"manifest_digest_mismatch_{label}")


def verify_manifest(root: Path, base_invariants: set[str]) -> dict[str, Any]:
    if not isinstance(base_invariants, set) or any(not isinstance(item, str) for item in base_invariants):
        fail("invalid_base_invariants")
    root = root.resolve()
    manifest = read_json(root / ".agents" / "manifest.yaml", "manifest_read_failed")
    exact_keys(manifest, TOP_KEYS, "manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        fail("unsupported_manifest_schema")
    if manifest.get("manifest_version") != "1.0.0":
        fail("unsupported_manifest_version")

    project = require_mapping(manifest.get("project"), "invalid_project")
    exact_keys(project, {"id", "repository", "implementation_truth", "intent_system"}, "project")
    if project != {
        "id": "v3-multi-agent-sandbox",
        "repository": EXPECTED_REPOSITORY,
        "implementation_truth": "github",
        "intent_system": "linear",
    }:
        fail("project_contract_mismatch")

    rules = require_mapping(manifest.get("rules"), "invalid_rules")
    exact_keys(rules, {"global", "project", "risk_paths"}, "rules")
    for label in ("global", "project", "risk_paths"):
        verify_file_digest(root, rules.get(label), label)

    identity = require_mapping(manifest.get("identity"), "invalid_identity")
    exact_keys(identity, {"authoritative_source", "self_report_is_authoritative"}, "identity")
    if identity.get("authoritative_source") != "github_event_and_c3_registry":
        fail("authoritative_identity_source_mismatch")
    if identity.get("self_report_is_authoritative") is not False:
        fail("self_report_must_not_be_authoritative")

    builder = require_mapping(manifest.get("builder"), "invalid_builder")
    exact_keys(builder, {"contract", "single_writer_per_branch", "merge_allowed"}, "builder")
    if builder.get("single_writer_per_branch") is not True:
        fail("single_writer_not_required")
    if builder.get("merge_allowed") is not False:
        fail("agent_merge_must_be_denied")
    contract_path = safe_repository_file(root, builder.get("contract"), "builder_contract")
    contract = contract_path.read_text(encoding="utf-8")
    for marker in sorted(CONTRACT_MARKERS):
        if marker not in contract:
            fail(f"builder_contract_marker_missing_{marker}")

    roles = require_mapping(manifest.get("roles"), "invalid_roles")
    if "permissions" in roles:
        fail("role_permission_escalation")
    exact_keys(roles, {"routing"}, "roles")
    if roles.get("routing") != ".agents/role-routing.yaml":
        fail("role_routing_path_mismatch")

    providers = require_mapping(manifest.get("providers"), "invalid_providers")
    exact_keys(providers, {"primary", "failover_mode", "adapters"}, "providers")
    if providers.get("primary") != "codex":
        fail("primary_provider_must_be_codex")
    if providers.get("failover_mode") != "unavailable_or_quota_exhausted_only":
        fail("invalid_failover_mode")
    adapters = providers.get("adapters")
    if not isinstance(adapters, list) or len(adapters) != 3:
        fail("invalid_provider_adapters")
    statuses: dict[str, str] = {}
    for raw_adapter in adapters:
        adapter = require_mapping(raw_adapter, "invalid_provider_adapter")
        if "permissions" in adapter:
            fail("provider_permission_escalation")
        exact_keys(adapter, {"provider_id", "status", "contract_version"}, "provider_adapter")
        provider_id = adapter.get("provider_id")
        status = adapter.get("status")
        if provider_id not in {"codex", "cursor", "deepseek-harness"}:
            fail("unknown_provider")
        if provider_id in statuses:
            fail("duplicate_provider")
        if status not in {"enabled", "planned"}:
            fail("invalid_provider_status")
        if adapter.get("contract_version") != "V3.2.1-C5-PROVIDER-R1":
            fail("provider_contract_version_mismatch")
        statuses[str(provider_id)] = str(status)
    if statuses != {"codex": "enabled", "cursor": "planned", "deepseek-harness": "planned"}:
        fail("provider_activation_mismatch")

    handoff = require_mapping(manifest.get("handoff"), "invalid_handoff")
    exact_keys(handoff, {"schema", "require_clean_checkpoint", "require_pushed_commit"}, "handoff")
    if handoff != {"schema": ".agents/handoff.schema.json", "require_clean_checkpoint": True, "require_pushed_commit": True}:
        fail("handoff_contract_mismatch")

    intake = require_mapping(manifest.get("intake"), "invalid_intake")
    exact_keys(intake, {"schema", "trust"}, "intake")
    if intake != {"schema": ".agents/task-intake.schema.json", "trust": "untrusted"}:
        fail("intake_contract_mismatch")

    checks = require_mapping(manifest.get("required_checks"), "invalid_required_checks")
    exact_keys(checks, {"preserve", "add"}, "required_checks")
    preserved = checks.get("preserve")
    added = checks.get("add")
    if not isinstance(preserved, list) or len(set(preserved)) != len(preserved):
        fail("invalid_preserved_checks")
    if not isinstance(added, list) or len(set(added)) != len(added):
        fail("invalid_added_checks")
    required = IMMUTABLE_REQUIRED_CHECKS | base_invariants
    missing = sorted(required - set(preserved))
    if missing:
        fail(f"required_control_removed_{missing[0]}")
    if set(added) != ADDED_CHECKS:
        fail("c5_required_checks_mismatch")

    return {
        "repository": EXPECTED_REPOSITORY,
        "primary_provider": "codex",
        "enabled_providers": sorted(provider for provider, status in statuses.items() if status == "enabled"),
        "preserved_checks": sorted(preserved),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    result = verify_manifest(args.repository_root, IMMUTABLE_REQUIRED_CHECKS)
    print(
        "C5_GOVERNANCE_CONTRACT=PASS "
        f"policy={POLICY_ID} repository={result['repository']} primary={result['primary_provider']}"
    )


if __name__ == "__main__":
    main()
