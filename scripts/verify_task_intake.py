#!/usr/bin/env python3
"""Validate normalized Task Intake envelopes strictly as untrusted data."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import unicodedata
from typing import Any, NoReturn


POLICY_ID = "V3.2.1-C5-TASK-INTAKE-R1"
REPOSITORY = "gg810612-pixel/v3-multi-agent-sandbox"
SOURCES = {"linear", "github_issue", "chatgpt", "line", "dashboard"}
TOP_KEYS = {"schema_version", "task_id", "source", "source_reference", "received_at", "raw_digest", "trust", "title", "intent", "priority_claim", "constraints", "acceptance_criteria_claims", "attachments", "requested_repository", "normalization"}
NORMALIZATION_KEYS = {"unicode_normalized", "control_characters_removed", "embedded_instruction_detected", "external_links_present"}
ATTACHMENT_KEYS = {"name", "digest", "media_type"}
INSTRUCTION_PATTERNS = (
    "ignore previous instructions",
    "ignore global rules",
    "reveal secrets",
    "approve and merge",
    "directly merge",
    "忽略 global rules",
    "忽略之前",
    "取得 secret",
    "輸出 secret",
    "直接 merge",
)
IMPLEMENTATION_CLAIMS = ("pr is merged", "pull request is merged", "ci is green", "checks are green", "already deployed")
CREDENTIAL_PATTERNS = (
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def fail(reason: str) -> NoReturn:
    raise SystemExit(f"C5_TASK_INTAKE=FAIL policy={POLICY_ID} reason={reason}")


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


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        fail("invalid_received_at")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        result = datetime.fromisoformat(normalized)
    except ValueError:
        fail("invalid_received_at")
    if result.tzinfo is None:
        fail("invalid_received_at")
    return result.astimezone(timezone.utc)


def text_list(value: Any, reason: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        fail(reason)
    return value


def validate_text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        fail("invalid_normalized_text")
    if unicodedata.normalize("NFC", value) != value:
        fail("normalized_text_not_nfc")
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in value):
        fail("normalized_text_contains_forbidden_character")
    if any(pattern.search(value) for pattern in CREDENTIAL_PATTERNS):
        fail("credential_material_detected")
    return value


def verify_intake(envelope: dict[str, Any], now: datetime) -> dict[str, Any]:
    envelope = mapping(envelope, "invalid_intake_envelope")
    exact_keys(envelope, TOP_KEYS, "intake")
    if envelope.get("schema_version") != POLICY_ID:
        fail("unsupported_intake_schema")
    if envelope.get("source") not in SOURCES:
        fail("unsupported_intake_source")
    if envelope.get("trust") != "untrusted":
        fail("intake_trust_must_be_untrusted")
    if envelope.get("requested_repository") != REPOSITORY:
        fail("requested_repository_mismatch")
    if not isinstance(envelope.get("task_id"), str) or not envelope["task_id"]:
        fail("invalid_task_id")
    if not isinstance(envelope.get("source_reference"), str) or not envelope["source_reference"]:
        fail("invalid_source_reference")
    if not isinstance(envelope.get("raw_digest"), str) or re.fullmatch(r"sha256:[0-9a-f]{64}", envelope["raw_digest"]) is None:
        fail("invalid_raw_digest")
    if now.tzinfo is None:
        fail("now_must_be_timezone_aware")
    if timestamp(envelope.get("received_at")) > now.astimezone(timezone.utc):
        fail("intake_received_in_future")

    text_values = [
        validate_text(envelope.get("title")),
        validate_text(envelope.get("intent")),
        validate_text(envelope.get("source_reference")),
    ]
    priority = envelope.get("priority_claim")
    if priority is not None:
        text_values.append(validate_text(priority))
    constraints = text_list(envelope.get("constraints"), "invalid_constraints")
    criteria = text_list(envelope.get("acceptance_criteria_claims"), "invalid_acceptance_criteria")
    text_values.extend(validate_text(item) for item in constraints + criteria)

    attachments = envelope.get("attachments")
    if not isinstance(attachments, list):
        fail("invalid_attachments")
    for raw in attachments:
        attachment = mapping(raw, "invalid_attachment")
        exact_keys(attachment, ATTACHMENT_KEYS, "attachment")
        validate_text(attachment.get("name"))
        validate_text(attachment.get("media_type"))
        if not isinstance(attachment.get("digest"), str) or re.fullmatch(r"sha256:[0-9a-f]{64}", attachment["digest"]) is None:
            fail("invalid_attachment_digest")

    combined = "\n".join(text_values)
    lowered = combined.casefold()
    instruction_detected = any(pattern in lowered for pattern in INSTRUCTION_PATTERNS)
    links_present = re.search(r"https?://", combined, flags=re.IGNORECASE) is not None
    flags: list[str] = []
    if instruction_detected:
        flags.append("instruction_escalation")
    if envelope.get("source") == "linear" and any(claim in lowered for claim in IMPLEMENTATION_CLAIMS):
        flags.append("implementation_state_claim")
    if links_present:
        flags.append("external_link")

    normalization = mapping(envelope.get("normalization"), "invalid_normalization")
    exact_keys(normalization, NORMALIZATION_KEYS, "normalization")
    expected = {
        "unicode_normalized": True,
        "control_characters_removed": True,
        "embedded_instruction_detected": instruction_detected,
        "external_links_present": links_present,
    }
    for key, value in expected.items():
        if normalization.get(key) is not value:
            fail(f"normalization_flag_mismatch_{key}")

    return {"accepted_as_data": True, "flags": sorted(flags), "source": str(envelope["source"])}


def main() -> None:
    raise SystemExit("C5_TASK_INTAKE=INTERFACE_ONLY use verify_intake from the base-pinned gate")


if __name__ == "__main__":
    main()
