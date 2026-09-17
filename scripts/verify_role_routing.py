#!/usr/bin/env python3
"""Deterministic additive C5 role and risk router."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, NoReturn


POLICY_ID = "V3.2.1-C5-ROLE-ROUTING-R1"
SCRIPT_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_ROOT.parent
ROUTING_PATH = REPOSITORY_ROOT / ".agents" / "role-routing.yaml"
RISK_PATH = REPOSITORY_ROOT / "governance" / "risk-paths.yaml"
ROLE_ORDER = ["planner", "architect", "developer", "qa", "security-specialist", "integration"]
ALL_ROLES = set(ROLE_ORDER)
RISK_RANK = {"L1": 1, "L2": 2, "L3": 3}
TOP_KEYS = {"schema_version", "risk_levels", "roles", "defaults", "rules"}
ROLE_KEYS = {"id", "write_mode", "deliverables", "prohibitions"}
DEFAULT_KEYS = {"roles", "minimum_risk"}
RULE_KEYS = {"id", "when", "add_roles", "minimum_risk"}
WHEN_KEYS = {"any_prefixes", "any_segments", "all_suffixes", "task_kinds"}
TASK_KINDS = {"feature", "bugfix", "docs", "governance", "architecture", "api_change", "migration", "unknown"}


def fail(reason: str) -> NoReturn:
    raise SystemExit(f"C5_ROLE_ROUTING=FAIL policy={POLICY_ID} reason={reason}")


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


def string_list(value: Any, reason: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        fail(reason)
    if any(not isinstance(item, str) or not item for item in value):
        fail(reason)
    if len(set(value)) != len(value):
        fail(reason)
    return value


def read_json(path: Path, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail(reason)
    return require_mapping(value, reason)


def load_rules_verifier():
    module_path = SCRIPT_ROOT / "verify_rules_precedence.py"
    spec = importlib.util.spec_from_file_location("c5_rules_for_routing", module_path)
    if spec is None or spec.loader is None:
        fail("rules_verifier_load_failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_routing(routing: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    exact_keys(routing, TOP_KEYS, "routing")
    if routing.get("schema_version") != "V3.2.1-C5-ROLE-ROUTING-R1":
        fail("unsupported_routing_schema")
    if routing.get("risk_levels") != ["L1", "L2", "L3"]:
        fail("invalid_risk_levels")

    roles = routing.get("roles")
    if not isinstance(roles, list) or len(roles) != 6:
        fail("invalid_role_definitions")
    role_ids: list[str] = []
    for raw_role in roles:
        role = require_mapping(raw_role, "invalid_role_definition")
        if "permissions" in role:
            fail("role_permission_claim")
        exact_keys(role, ROLE_KEYS, "role")
        role_id = role.get("id")
        if role_id not in ALL_ROLES:
            fail(f"unknown_role_{role_id}")
        if role_id in role_ids:
            fail("duplicate_role_id")
        role_ids.append(str(role_id))
        if role.get("write_mode") not in {"none", "lease_only"}:
            fail("invalid_role_write_mode")
        string_list(role.get("deliverables"), "invalid_role_deliverables")
        string_list(role.get("prohibitions"), "invalid_role_prohibitions")
    if set(role_ids) != ALL_ROLES:
        fail("missing_required_role")

    defaults = require_mapping(routing.get("defaults"), "invalid_defaults")
    exact_keys(defaults, DEFAULT_KEYS, "defaults")
    default_roles = string_list(defaults.get("roles"), "invalid_default_roles")
    for role in default_roles:
        if role not in ALL_ROLES:
            fail(f"unknown_default_role_{role}")
    if defaults.get("minimum_risk") != "L1":
        fail("invalid_default_minimum_risk")

    raw_rules = routing.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        fail("missing_routing_rules")
    rules: list[dict[str, Any]] = []
    rule_ids: set[str] = set()
    for raw_rule in raw_rules:
        rule = require_mapping(raw_rule, "invalid_routing_rule")
        exact_keys(rule, RULE_KEYS, "routing_rule")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]*", rule_id) is None:
            fail("invalid_routing_rule_id")
        if rule_id in rule_ids:
            fail("duplicate_routing_rule")
        rule_ids.add(rule_id)
        when = require_mapping(rule.get("when"), "invalid_routing_when")
        unknown = sorted(set(when) - WHEN_KEYS)
        if unknown:
            fail(f"unknown_routing_when_key_{unknown[0]}")
        if not when:
            fail("empty_routing_when")
        validated_when = {
            key: string_list(value, f"invalid_routing_when_{key}")
            for key, value in when.items()
        }
        add_roles = string_list(rule.get("add_roles"), "invalid_add_roles", allow_empty=True)
        for role in add_roles:
            if role not in ALL_ROLES:
                fail(f"unknown_added_role_{role}")
        minimum_risk = rule.get("minimum_risk")
        if minimum_risk not in RISK_RANK:
            fail("invalid_routing_minimum_risk")
        rules.append({"id": rule_id, "when": validated_when, "add_roles": add_roles, "minimum_risk": minimum_risk})
    return default_roles, rules


def normalized_tokens(path: str) -> set[str]:
    posix = PurePosixPath(path)
    tokens = {part.lower() for part in posix.parts[:-1]}
    tokens.update(token for token in re.split(r"[^a-z0-9]+", posix.stem.lower()) if token)
    return tokens


def matches(rule: dict[str, Any], paths: list[str], task_kind: str) -> bool:
    when = rule["when"]
    results: list[bool] = []
    if "any_prefixes" in when:
        results.append(any(path.startswith(prefix) for path in paths for prefix in when["any_prefixes"]))
    if "any_segments" in when:
        segments = {segment.lower() for segment in when["any_segments"]}
        results.append(any(normalized_tokens(path) & segments for path in paths))
    if "all_suffixes" in when:
        results.append(all(any(path.endswith(suffix) for suffix in when["all_suffixes"]) for path in paths))
    if "task_kinds" in when:
        results.append(task_kind in when["task_kinds"])
    return bool(results) and all(results)


def route_roles(
    paths: list[str],
    task_kind: str,
    proposed_risk: str,
    requested_roles: list[str] | None = None,
    routing: dict[str, Any] | None = None,
    risk_map: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if task_kind not in TASK_KINDS:
        fail("unknown_task_kind")
    if proposed_risk not in RISK_RANK:
        fail("invalid_proposed_risk")
    routing_document = routing if routing is not None else read_json(ROUTING_PATH, "routing_read_failed")
    default_roles, rules = validate_routing(require_mapping(routing_document, "invalid_routing"))
    risk_document = risk_map if risk_map is not None else read_json(RISK_PATH, "risk_map_read_failed")
    rules_verifier = load_rules_verifier()
    path_risk = rules_verifier.classify_paths(paths, risk_document)

    matched = [rule for rule in rules if matches(rule, paths, task_kind)]
    required_risk = max(
        [path_risk] + [rule["minimum_risk"] for rule in matched],
        key=RISK_RANK.__getitem__,
    )
    if RISK_RANK[proposed_risk] < RISK_RANK[required_risk]:
        fail("risk_downgrade_attempt")
    final_risk = proposed_risk
    required_roles = set(default_roles)
    for rule in matched:
        required_roles.update(rule["add_roles"])
    if final_risk == "L3":
        required_roles.update(ALL_ROLES)

    if requested_roles is not None:
        requested = string_list(requested_roles, "invalid_requested_roles")
        unknown = sorted(set(requested) - ALL_ROLES)
        if unknown:
            fail(f"unknown_requested_role_{unknown[0]}")
        missing = sorted(required_roles - set(requested))
        if missing:
            fail(f"required_role_removed_{missing[0]}")
        selected_roles = set(requested)
    else:
        selected_roles = required_roles

    return {
        "risk_level": final_risk,
        "roles": [role for role in ROLE_ORDER if role in selected_roles],
        "matched_rules": [rule["id"] for rule in matched],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--changed-path", action="append", required=True)
    parser.add_argument("--task-kind", required=True, choices=sorted(TASK_KINDS))
    parser.add_argument("--proposed-risk", required=True, choices=["L1", "L2", "L3"])
    args = parser.parse_args()
    result = route_roles(args.changed_path, args.task_kind, args.proposed_risk)
    print(
        "C5_ROLE_ROUTING=PASS "
        f"policy={POLICY_ID} risk={result['risk_level']} roles={','.join(result['roles'])}"
    )


if __name__ == "__main__":
    main()
