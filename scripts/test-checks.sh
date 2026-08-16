#!/usr/bin/env bash
set -euo pipefail

source_root="$(git rev-parse --show-toplevel 2>/dev/null)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

mkdir -p "$test_root/.github/workflows" "$test_root/.github" "$test_root/scripts"
cp "$source_root/scripts/check.sh" "$test_root/scripts/check.sh"
cp "$source_root/.github/workflows/deterministic-gates.yml" "$test_root/.github/workflows/deterministic-gates.yml"
cp "$source_root/.github/CODEOWNERS" "$test_root/.github/CODEOWNERS"

git -C "$test_root" init -q
git -C "$test_root" add .

(
  cd "$test_root"
  ./scripts/check.sh >/dev/null
)

printf '%s%s\n' '-----BEGIN RSA PRIVATE ' 'KEY-----' > "$test_root/red-team.txt"
git -C "$test_root" add red-team.txt

if (
  cd "$test_root"
  ./scripts/check.sh >/dev/null 2>&1
); then
  printf 'red-team: private-key marker was not blocked\n' >&2
  exit 1
fi

rm "$test_root/red-team.txt"
git -C "$test_root" rm --cached -q red-team.txt
touch "$test_root/forbidden.pem"
git -C "$test_root" add forbidden.pem

if (
  cd "$test_root"
  ./scripts/check.sh >/dev/null 2>&1
); then
  printf 'red-team: forbidden credential extension was not blocked\n' >&2
  exit 1
fi

printf 'red-team: PASS\n'
