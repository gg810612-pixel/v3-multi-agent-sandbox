#!/usr/bin/env python3
"""Fail-closed verifier for V3.2.1 C4 credential-boundary evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Any, NoReturn


POLICY_ID = "V3.2.1-C4-CREDENTIAL-BOUNDARY-R1"
SCHEMA_VERSION = "V3.2.1-C4-EVIDENCE-R1"
REPOSITORY = "gg810612-pixel/v3-multi-agent-sandbox"
MAX_VALIDITY = timedelta(days=100)

EXPECTED_IDENTITIES = {
    "builder": "154156095",
    "reviewer": "154666370",
}
EXPECTED_INSTALLATIONS = {
    "builder": {
        "app_id": "4605247",
        "installation_id": "154156095",
    },
    "reviewer": {
        "app_id": "4624842",
        "installation_id": "154666370",
    },
}

TOP_LEVEL_FIELDS = {
    "schema_version",
    "repository",
    "observed_at",
    "valid_until",
    "deploy_keys",
    "system_identities",
    "app_installations",
    "classic_pat_policy",
    "agent_runtime",
}
DEPLOY_KEY_FIELDS = {"id", "title", "read_only", "verified"}
IDENTITY_FIELDS = {"role", "credential_kind", "credential_id"}
INSTALLATION_FIELDS = {
    "role",
    "app_id",
    "installation_id",
    "repository_selection",
    "repository",
}
PAT_POLICY_FIELDS = {
    "allowed_for_system_roles",
    "system_role_matches",
    "inventory_status",
}
AGENT_RUNTIME_FIELDS = {
    "execution_user",
    "prohibited_human_user",
    "gh_config_present",
    "gh_config_readable",
    "ssh_dir_present",
    "ssh_auth_sock_present",
    "git_credential_helpers",
    "credential_env_names",
    "human_keychain_path_readable",
}


def fail(reason: str) -> NoReturn:
    raise SystemExit(
        f"C4_CREDENTIAL_BOUNDARY=FAIL policy={POLICY_ID} reason={reason}"
    )


def require_object(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(reason)
    return value


def require_exact_fields(
    value: Any,
    expected: set[str],
    reason: str,
) -> dict[str, Any]:
    obj = require_object(value, reason)
    if set(obj) != expected:
        fail(reason)
    return obj


def require_string(value: Any, reason: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(reason)
    return value


def require_string_list(value: Any, reason: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        fail(reason)
    return value


def parse_timestamp(value: Any, reason: str) -> datetime:
    text = require_string(value, reason)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        fail(reason)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail(reason)
    return parsed


def verify(evidence: dict[str, Any], now: datetime) -> dict[str, Any]:
    if now.tzinfo is None or now.utcoffset() is None:
        fail("verification_time_missing_timezone")

    doc = require_exact_fields(
        evidence,
        TOP_LEVEL_FIELDS,
        "missing_or_invalid_top_level_fields",
    )
    if doc["schema_version"] != SCHEMA_VERSION:
        fail("unsupported_schema_version")
    if doc["repository"] != REPOSITORY:
        fail("repository_mismatch")

    observed_at = parse_timestamp(doc["observed_at"], "invalid_observed_at")
    valid_until = parse_timestamp(doc["valid_until"], "invalid_valid_until")
    if observed_at > now:
        fail("inventory_observed_in_future")
    if valid_until < observed_at:
        fail("inventory_window_invalid")
    if valid_until - observed_at > MAX_VALIDITY:
        fail("inventory_validity_exceeds_100_days")
    if now > valid_until:
        fail("inventory_expired")

    deploy_keys = doc["deploy_keys"]
    if not isinstance(deploy_keys, list):
        fail("deploy_keys_missing_or_not_list")
    deploy_key_ids: list[int] = []
    for item in deploy_keys:
        key = require_exact_fields(
            item,
            DEPLOY_KEY_FIELDS,
            "missing_or_invalid_deploy_key_fields",
        )
        key_id = key["id"]
        if isinstance(key_id, bool) or not isinstance(key_id, int) or key_id <= 0:
            fail("invalid_deploy_key_id")
        require_string(key["title"], "invalid_deploy_key_title")
        if type(key["read_only"]) is not bool or type(key["verified"]) is not bool:
            fail("invalid_deploy_key_boolean")
        if not key["read_only"]:
            fail("write_capable_deploy_key")
        if not key["verified"]:
            fail("unverified_deploy_key")
        deploy_key_ids.append(key_id)
    if len(set(deploy_key_ids)) != len(deploy_key_ids):
        fail("duplicate_deploy_key_id")

    identities = doc["system_identities"]
    if not isinstance(identities, list):
        fail("system_identities_missing_or_not_list")
    identity_by_role: dict[str, dict[str, Any]] = {}
    credentials: list[tuple[str, str]] = []
    for item in identities:
        identity = require_exact_fields(
            item,
            IDENTITY_FIELDS,
            "missing_or_invalid_system_identity_fields",
        )
        role = require_string(identity["role"], "invalid_system_identity_role")
        kind = require_string(
            identity["credential_kind"],
            "invalid_system_identity_credential_kind",
        )
        credential_id = require_string(
            identity["credential_id"],
            "invalid_system_identity_credential_id",
        )
        if kind == "classic_pat":
            fail("classic_pat_system_role")
        if kind != "github_app_installation":
            fail("unsupported_system_identity_credential_kind")
        if role in identity_by_role:
            fail("duplicate_system_identity_role")
        identity_by_role[role] = identity
        credentials.append((kind, credential_id))
    if set(identity_by_role) != set(EXPECTED_IDENTITIES):
        fail("system_identity_roles_mismatch")
    if len(set(credentials)) != len(credentials):
        fail("credential_mapping_not_one_to_one")
    for role, expected_id in EXPECTED_IDENTITIES.items():
        if identity_by_role[role]["credential_id"] != expected_id:
            fail("system_identity_inventory_mismatch")

    installations = doc["app_installations"]
    if not isinstance(installations, list):
        fail("app_installations_missing_or_not_list")
    installation_by_role: dict[str, dict[str, Any]] = {}
    for item in installations:
        installation = require_exact_fields(
            item,
            INSTALLATION_FIELDS,
            "missing_or_invalid_app_installation_fields",
        )
        role = require_string(installation["role"], "invalid_app_installation_role")
        if role in installation_by_role:
            fail("duplicate_app_installation_role")
        installation_by_role[role] = installation
    if set(installation_by_role) != set(EXPECTED_INSTALLATIONS):
        fail("app_installation_inventory_mismatch")
    for role, expected in EXPECTED_INSTALLATIONS.items():
        installation = installation_by_role[role]
        if (
            installation["app_id"] != expected["app_id"]
            or installation["installation_id"] != expected["installation_id"]
            or installation["repository_selection"] != "selected"
            or installation["repository"] != REPOSITORY
        ):
            fail("app_installation_inventory_mismatch")

    pat_policy = require_exact_fields(
        doc["classic_pat_policy"],
        PAT_POLICY_FIELDS,
        "missing_or_invalid_classic_pat_policy_fields",
    )
    if type(pat_policy["allowed_for_system_roles"]) is not bool:
        fail("invalid_classic_pat_policy_boolean")
    matches = require_string_list(
        pat_policy["system_role_matches"],
        "invalid_classic_pat_system_role_matches",
    )
    if pat_policy["allowed_for_system_roles"] or matches:
        fail("classic_pat_system_role")
    if pat_policy["inventory_status"] != "human_owner_readback_complete":
        fail("classic_pat_inventory_inconclusive")

    runtime = require_exact_fields(
        doc["agent_runtime"],
        AGENT_RUNTIME_FIELDS,
        "missing_or_invalid_agent_runtime_fields",
    )
    execution_user = require_string(
        runtime["execution_user"],
        "invalid_agent_execution_user",
    )
    prohibited_human = require_string(
        runtime["prohibited_human_user"],
        "invalid_prohibited_human_user",
    )
    if prohibited_human != "huangchengzhang":
        fail("prohibited_human_user_mismatch")
    boolean_fields = (
        "gh_config_present",
        "gh_config_readable",
        "ssh_dir_present",
        "ssh_auth_sock_present",
        "human_keychain_path_readable",
    )
    if any(type(runtime[field]) is not bool for field in boolean_fields):
        fail("invalid_agent_runtime_boolean")
    helpers = require_string_list(
        runtime["git_credential_helpers"],
        "invalid_git_credential_helpers",
    )
    env_names = require_string_list(
        runtime["credential_env_names"],
        "invalid_credential_env_names",
    )
    if (
        execution_user == prohibited_human
        or any(runtime[field] for field in boolean_fields)
        or helpers
        or env_names
    ):
        fail("human_credential_channel_visible")

    return {
        "policy": POLICY_ID,
        "repository": REPOSITORY,
        "observed_at": observed_at.isoformat(),
        "valid_until": valid_until.isoformat(),
        "deploy_key_count": len(deploy_keys),
        "builder_installation_id": EXPECTED_IDENTITIES["builder"],
        "reviewer_installation_id": EXPECTED_IDENTITIES["reviewer"],
        "agent_execution_user": execution_user,
    }


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("evidence_file_unreadable_or_invalid_json")
    if not isinstance(value, dict):
        fail("evidence_root_not_object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--now", required=True)
    args = parser.parse_args()
    try:
        now = datetime.fromisoformat(args.now.replace("Z", "+00:00"))
    except ValueError:
        fail("verification_time_invalid")
    result = verify(read_json(args.evidence), now)
    print(
        "C4_CREDENTIAL_BOUNDARY=PASS "
        f"policy={result['policy']} repository={result['repository']} "
        f"deploy_keys={result['deploy_key_count']} "
        f"builder_installation_id={result['builder_installation_id']} "
        f"reviewer_installation_id={result['reviewer_installation_id']} "
        f"agent_execution_user={result['agent_execution_user']}"
    )


if __name__ == "__main__":
    main()
