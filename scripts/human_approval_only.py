#!/usr/bin/env python3
"""C2 deterministic gate: only effective human approvals may satisfy approval."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, NoReturn
import urllib.error
import urllib.parse
import urllib.request


DECISIVE_HUMAN_STATES = {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}


def fail(reason: str) -> NoReturn:
    raise SystemExit(f"C2_HUMAN_APPROVAL_ONLY=FAIL reason={reason}")


def load_reviews(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"invalid_reviews_input_{type(error).__name__}")

    if isinstance(payload, dict):
        payload = payload.get("reviews")
    if not isinstance(payload, list):
        fail("reviews_not_a_list")
    if not all(isinstance(review, dict) for review in payload):
        fail("review_entry_not_an_object")
    return payload


def fetch_reviews(repository: str, pull_number: int, token: str) -> list[dict[str, Any]]:
    if repository.count("/") != 1 or not all(repository.split("/")):
        fail("invalid_repository")
    if pull_number <= 0:
        fail("invalid_pull_number")
    if not token:
        fail("missing_github_token")

    owner, name = (urllib.parse.quote(part, safe="") for part in repository.split("/"))
    reviews: list[dict[str, Any]] = []
    for page in range(1, 101):
        url = (
            f"https://api.github.com/repos/{owner}/{name}/pulls/{pull_number}/reviews"
            f"?per_page=100&page={page}"
        )
        request = urllib.request.Request(url)
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("Authorization", f"Bearer {token}")
        request.add_header("X-GitHub-Api-Version", "2026-03-10")
        request.add_header("User-Agent", "v3-c2-human-approval-only")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                page_reviews = json.load(response)
        except (urllib.error.URLError, json.JSONDecodeError) as error:
            fail(f"github_reviews_fetch_failed_{type(error).__name__}")
        if not isinstance(page_reviews, list) or not all(
            isinstance(review, dict) for review in page_reviews
        ):
            fail("github_reviews_response_invalid")
        reviews.extend(page_reviews)
        if len(page_reviews) < 100:
            return reviews
    fail("github_reviews_pagination_limit_exceeded")


def verify(reviews: list[dict[str, Any]], expected_human: str | None) -> str:
    effective_human_reviews: dict[str, str] = {}

    for index, review in enumerate(reviews):
        state = review.get("state")
        if not isinstance(state, str) or not state:
            fail(f"review_{index}_missing_state")
        state = state.upper()

        user = review.get("user") or review.get("author")
        if not isinstance(user, dict):
            fail(f"review_{index}_missing_authority_identity")
        login = user.get("login")
        user_type = user.get("type") or user.get("__typename")
        if not isinstance(login, str) or not login:
            fail(f"review_{index}_missing_login")
        if not isinstance(user_type, str) or not user_type:
            fail(f"review_{index}_missing_user_type")

        if state == "APPROVED" and user_type != "User":
            fail(f"non_human_approved_{login}_{user_type}")

        if user_type == "User" and state in DECISIVE_HUMAN_STATES:
            effective_human_reviews[login] = state

    effective_humans = sorted(
        login
        for login, state in effective_human_reviews.items()
        if state == "APPROVED"
    )
    if expected_human is not None:
        if effective_human_reviews.get(expected_human) != "APPROVED":
            fail(f"expected_human_not_effectively_approved_{expected_human}")
    elif not effective_humans:
        fail("no_effective_human_approval")

    return ",".join(effective_humans)


def main() -> None:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--reviews", type=Path)
    source.add_argument("--repository")
    parser.add_argument("--pull-number", type=int)
    parser.add_argument("--token-env", default="GITHUB_TOKEN")
    parser.add_argument("--expected-human")
    args = parser.parse_args()

    if args.reviews is not None:
        if args.pull_number is not None:
            fail("pull_number_not_allowed_with_fixture")
        reviews = load_reviews(args.reviews)
    else:
        if args.pull_number is None:
            fail("pull_number_required_for_live_check")
        reviews = fetch_reviews(
            args.repository,
            args.pull_number,
            os.environ.get(args.token_env, ""),
        )

    effective_humans = verify(reviews, args.expected_human)
    print(
        "C2_HUMAN_APPROVAL_ONLY=PASS "
        f"effective_humans={effective_humans or 'none'}"
    )


if __name__ == "__main__":
    main()
