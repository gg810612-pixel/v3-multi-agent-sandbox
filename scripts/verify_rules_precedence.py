#!/usr/bin/env python3
"""Fail-closed verifier for C5 rules precedence and path risk."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, NoReturn


POLICY_ID = "V3.2.1-C5-RULES-PRECEDENCE-R1"
RULES_SCHEMA_VERSION = "V3.2.1-C5-RULES-R1"
RISK_SCHEMA_VERSION = "V3.2.1-C5-RISK-PATHS-R1"
EXPECTED_REPOSITORY = "gg810612-pixel/v3-multi-agent-sandbox"
EXPECTED_INHERITANCE = "governance/global-rules.yaml"
RULES_KEYS = {"schema_version", "layer", "policy_id", "repository", "inherits", "rules"}
RULE_SET_KEYS = {"deny", "required", "allow"}
RISK_KEYS = {"schema_version", "levels", "default_risk", "rules"}
RISK_RULE_KEYS = {"id", "minimum_risk", "matcher"}
MATCHER_KEYS = {"exact_paths", "prefixes", "segments", "suffixes"}
RISK_RANK = {"L1": 1, "L2": 2, "L3": 3}
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9-]*$")
IMMUTABLE_GLOBAL_DENY = {
    "agent-no-merge",
    "agent-no-approve",
    "reviewer-advisory-only",
    "agent-no-governance-mutation",
    "agent-no-human-credential-access",
}
IMMUTABLE_GLOBAL_REQUIRED = {
    "github-implementation-truth",
    "human-only-approval",
    "authoritative-github-identity",
    "single-writer-branch",
    "untrusted-intake",
    "base-pinned-verifier",
    "fail-closed",
    "base-checks",
    "human-approval-only",
    "provenance-device",
    "credential-boundary",
}
FORBIDDEN_ALLOW = {
    "merge-pull-request",
    "approve-pull-request",
    "request-changes",
    "administer-repository",
    "mutate-branch-protection",
    "mutate-ruleset",
    "read-human-credentials",
}


def fail(reason: str) -> NoReturn:
    raise SystemExit(f"C5_RULES=FAIL policy={POLICY_ID} reason={reason}")


def require_mapping(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(reason)
    return value


def require_exact_keys(mapping: dict[str, Any], expected: set[str], prefix: str) -> None:
    unknown = sorted(set(mapping) - expected)
    if unknown:
        fail(f"unknown_{prefix}_key_{unknown[0]}")
    missing = sorted(expected - set(mapping))
    if missing:
        fail(f"missing_{prefix}_key_{missing[0]}")


def require_identifier(value: Any, reason: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        fail(reason)
    return value


def validate_rule_ids(value: Any, layer: str, kind: str) -> list[str]:
    if not isinstance(value, list):
        fail(f"invalid_{layer}_{kind}")
    identifiers = [require_identifier(item, f"invalid_{layer}_{kind}_id") for item in value]
    if len(set(identifiers)) != len(identifiers):
        fail(f"duplicate_{layer}_{kind}")
    return identifiers


def validate_rules_document(document: dict[str, Any], expected_layer: str) -> dict[str, list[str]]:
    require_exact_keys(document, RULES_KEYS, expected_layer)
    if document.get("schema_version") != RULES_SCHEMA_VERSION:
        fail(f"unsupported_{expected_layer}_schema")
    if document.get("layer") != expected_layer:
        fail(f"invalid_{expected_layer}_layer")
    require_identifier(document.get("policy_id"), f"invalid_{expected_layer}_policy_id")

    if expected_layer == "global":
        if document.get("repository") is not None:
            fail("global_repository_must_be_null")
        if document.get("inherits") is not None:
            fail("global_inherits_must_be_null")
    else:
        if document.get("repository") != EXPECTED_REPOSITORY:
            fail("project_repository_mismatch")
        if document.get("inherits") != EXPECTED_INHERITANCE:
            fail("project_inheritance_mismatch")

    rules = require_mapping(document.get("rules"), f"invalid_{expected_layer}_rules")
    require_exact_keys(rules, RULE_SET_KEYS, "rules")
    return {
        kind: validate_rule_ids(rules[kind], expected_layer, kind)
        for kind in sorted(RULE_SET_KEYS)
    }


def resolve_rules(global_rules: dict[str, Any], project_rules: dict[str, Any]) -> dict[str, Any]:
    global_sets = validate_rules_document(require_mapping(global_rules, "invalid_global_document"), "global")
    project_sets = validate_rules_document(require_mapping(project_rules, "invalid_project_document"), "project")

    global_deny = set(global_sets["deny"])
    project_deny = set(project_sets["deny"])
    missing_deny = sorted(IMMUTABLE_GLOBAL_DENY - global_deny)
    if missing_deny:
        fail(f"baseline_global_deny_missing_{missing_deny[0]}")
    if not global_deny.issubset(project_deny):
        fail("global_deny_removed")

    global_required = set(global_sets["required"])
    project_required = set(project_sets["required"])
    missing_required = sorted(IMMUTABLE_GLOBAL_REQUIRED - global_required)
    if missing_required:
        fail(f"baseline_global_required_missing_{missing_required[0]}")
    if not global_required.issubset(project_required):
        fail("global_required_removed")

    global_allow = set(global_sets["allow"])
    project_allow = set(project_sets["allow"])
    forbidden = sorted(global_allow & FORBIDDEN_ALLOW)
    if forbidden:
        fail(f"forbidden_global_allow_{forbidden[0]}")
    if not project_allow.issubset(global_allow):
        fail("project_allow_expands_global")

    return {
        "repository": EXPECTED_REPOSITORY,
        "deny": sorted(global_deny | project_deny),
        "required": sorted(global_required | project_required),
        "allow": sorted(global_allow & project_allow),
    }


def validate_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        fail("unsafe_changed_path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value.startswith("./"):
        fail("unsafe_changed_path")
    return value


def validate_matcher(value: Any) -> dict[str, list[str]]:
    matcher = require_mapping(value, "invalid_risk_matcher")
    unknown = sorted(set(matcher) - MATCHER_KEYS)
    if unknown:
        fail(f"unknown_matcher_key_{unknown[0]}")
    if not matcher:
        fail("empty_risk_matcher")
    validated: dict[str, list[str]] = {}
    for key, entries in matcher.items():
        if not isinstance(entries, list) or not entries:
            fail(f"invalid_matcher_{key}")
        if any(not isinstance(entry, str) or not entry for entry in entries):
            fail(f"invalid_matcher_{key}")
        if len(set(entries)) != len(entries):
            fail(f"duplicate_matcher_{key}")
        validated[key] = entries
    return validated


def validate_risk_map(risk_map: dict[str, Any]) -> list[dict[str, Any]]:
    require_exact_keys(risk_map, RISK_KEYS, "risk_map")
    if risk_map.get("schema_version") != RISK_SCHEMA_VERSION:
        fail("unsupported_risk_schema")
    if risk_map.get("levels") != ["L1", "L2", "L3"]:
        fail("invalid_risk_levels")
    if risk_map.get("default_risk") != "L3":
        fail("default_risk_must_be_l3")
    rules = risk_map.get("rules")
    if not isinstance(rules, list) or not rules:
        fail("missing_risk_rules")
    validated: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for raw_rule in rules:
        rule = require_mapping(raw_rule, "invalid_risk_rule")
        require_exact_keys(rule, RISK_RULE_KEYS, "risk_rule")
        rule_id = require_identifier(rule.get("id"), "invalid_risk_rule_id")
        if rule_id in identifiers:
            fail("duplicate_risk_rule_id")
        identifiers.add(rule_id)
        minimum_risk = rule.get("minimum_risk")
        if minimum_risk not in RISK_RANK:
            fail("invalid_minimum_risk")
        validated.append({
            "id": rule_id,
            "minimum_risk": minimum_risk,
            "matcher": validate_matcher(rule.get("matcher")),
        })
    return validated


def path_matches(path: str, matcher: dict[str, list[str]]) -> bool:
    if path in matcher.get("exact_paths", []):
        return True
    if any(path.startswith(prefix) for prefix in matcher.get("prefixes", [])):
        return True
    if any(path.endswith(suffix) for suffix in matcher.get("suffixes", [])):
        return True
    posix_path = PurePosixPath(path)
    path_segments = {segment.lower() for segment in posix_path.parts[:-1]}
    path_segments.update(
        token
        for token in re.split(r"[^a-z0-9]+", posix_path.stem.lower())
        if token
    )
    if path_segments.intersection(segment.lower() for segment in matcher.get("segments", [])):
        return True
    return False


def classify_paths(paths: list[str], risk_map: dict[str, Any]) -> str:
    if not isinstance(paths, list) or not paths:
        fail("missing_changed_paths")
    rules = validate_risk_map(require_mapping(risk_map, "invalid_risk_map"))
    path_risks: list[str] = []
    for raw_path in paths:
        path = validate_path(raw_path)
        matches = [
            rule["minimum_risk"]
            for rule in rules
            if path_matches(path, rule["matcher"])
        ]
        path_risks.append(
            max(matches, key=RISK_RANK.__getitem__)
            if matches
            else str(risk_map["default_risk"])
        )
    return max(path_risks, key=RISK_RANK.__getitem__)


def read_json(path: Path, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail(reason)
    return require_mapping(value, reason)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--global-rules", required=True, type=Path)
    parser.add_argument("--project-rules", required=True, type=Path)
    parser.add_argument("--risk-paths", required=True, type=Path)
    parser.add_argument("--changed-path", action="append", required=True)
    args = parser.parse_args()

    resolved = resolve_rules(
        read_json(args.global_rules, "global_rules_read_failed"),
        read_json(args.project_rules, "project_rules_read_failed"),
    )
    risk = classify_paths(
        args.changed_path,
        read_json(args.risk_paths, "risk_paths_read_failed"),
    )
    print(
        "C5_RULES=PASS "
        f"policy={POLICY_ID} repository={resolved['repository']} risk={risk}"
    )


if __name__ == "__main__":
    main()
