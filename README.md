# v3-multi-agent-sandbox

Public sandbox for validating the V3 controlled multi-agent development governance, security gates, and acceptance tests. No private or production data.

## Deterministic baseline

Run the same required check locally and in CI:

```bash
./scripts/check.sh
```

Run the red-team regression test:

```bash
./scripts/test-checks.sh
```

`base-checks` is the deterministic merge signal. AI review is advisory and must never be configured as the only required check.
