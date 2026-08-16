#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'base-checks: %s\n' "$1" >&2
  exit 1
}

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail 'must run inside a Git repository'
cd "$repo_root"

workflow='.github/workflows/deterministic-gates.yml'
codeowners='.github/CODEOWNERS'

[[ -f "$workflow" ]] || fail "missing ${workflow}"
[[ -f "$codeowners" ]] || fail "missing ${codeowners}"

while IFS= read -r tracked_path; do
  case "$tracked_path" in
    *.pem|*.key|*.p12|*.pfx)
      fail "forbidden credential file is tracked: ${tracked_path}"
      ;;
  esac
done < <(git ls-files)

if git grep -nIE -- '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' -- . >/dev/null; then
  fail 'private-key material marker found in tracked content'
fi

if ! grep -Eq 'uses: actions/checkout@[0-9a-f]{40}([[:space:]]|$)' "$workflow"; then
  fail 'actions/checkout must be pinned to a full commit SHA'
fi

grep -Eq '^[[:space:]]*permissions:[[:space:]]*$' "$workflow" || fail 'workflow must declare permissions'
grep -Eq '^[[:space:]]*contents:[[:space:]]*read[[:space:]]*$' "$workflow" || fail 'workflow contents permission must be read-only'
grep -Eq '^[[:space:]]*persist-credentials:[[:space:]]*false[[:space:]]*$' "$workflow" || fail 'checkout credentials must not persist'

while IFS= read -r shell_file; do
  bash -n "$shell_file" || fail "shell syntax failed: ${shell_file}"
done < <(git ls-files '*.sh')

printf 'base-checks: PASS\n'
