#!/usr/bin/env python3
"""Fail-closed verifier for vendor-neutral C5 Provider adapters."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, NoReturn


POLICY_ID = "V3.2.1-C5-PROVIDER-CONTRACT-R1"
TOP_KEYS = {"schema_version", "provider_id", "adapter_version", "operation", "health", "capabilities", "requested_permissions"}
CAPABILITIES = {"identify", "health", "start", "checkpoint", "stop", "resume"}
START_OPERATIONS = {"start", "resume"}
KNOWN_HEALTH = {"available", "quota_exhausted", "unavailable", "degraded"}
FAILOVER_HEALTH = {"quota_exhausted", "unavailable"}


def fail(reason: str) -> NoReturn:
    raise SystemExit(f"C5_PROVIDER=FAIL policy={POLICY_ID} reason={reason}")


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


def manifest_adapters(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    providers = mapping(manifest.get("providers"), "manifest_providers_missing")
    adapters = providers.get("adapters")
    if not isinstance(adapters, list):
        fail("manifest_adapters_missing")
    result: dict[str, dict[str, Any]] = {}
    for raw in adapters:
        adapter = mapping(raw, "invalid_manifest_adapter")
        provider_id = adapter.get("provider_id")
        if not isinstance(provider_id, str) or provider_id in result:
            fail("invalid_manifest_provider_id")
        result[provider_id] = adapter
    return result


def verify_provider(provider: dict[str, Any], manifest: dict[str, Any]) -> dict[str, str]:
    provider = mapping(provider, "invalid_provider")
    exact_keys(provider, TOP_KEYS, "provider")
    if provider.get("schema_version") != "V3.2.1-C5-PROVIDER-R1":
        fail("provider_contract_version_mismatch")
    provider_id = provider.get("provider_id")
    adapters = manifest_adapters(mapping(manifest, "invalid_manifest"))
    if provider_id not in adapters:
        fail("provider_not_allowlisted")
    adapter = adapters[str(provider_id)]
    if adapter.get("contract_version") != provider.get("schema_version"):
        fail("provider_contract_version_mismatch")
    operation = provider.get("operation")
    if operation not in CAPABILITIES:
        fail("unsupported_provider_operation")
    if operation in START_OPERATIONS and adapter.get("status") != "enabled":
        fail("provider_not_enabled")
    permissions = provider.get("requested_permissions")
    if not isinstance(permissions, list) or permissions:
        fail("provider_permission_claim")
    capabilities = provider.get("capabilities")
    if not isinstance(capabilities, list) or set(capabilities) != CAPABILITIES or len(capabilities) != len(CAPABILITIES):
        fail("provider_capability_drift")
    health = provider.get("health")
    if health == "unknown" or health not in KNOWN_HEALTH:
        fail("provider_health_unknown")
    version = provider.get("adapter_version")
    if not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        fail("invalid_adapter_version")
    return {"provider_id": str(provider_id), "status": str(adapter.get("status")), "health": str(health)}


def verify_failover_eligibility(source_health: str) -> str:
    if source_health not in FAILOVER_HEALTH:
        fail("source_health_not_failover_eligible")
    return source_health


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        provider = json.loads(args.provider.read_text(encoding="utf-8"))
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        fail("input_read_failed")
    result = verify_provider(provider, manifest)
    print(f"C5_PROVIDER=PASS policy={POLICY_ID} provider={result['provider_id']} status={result['status']}")


if __name__ == "__main__":
    main()
