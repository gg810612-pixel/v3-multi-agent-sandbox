# C5 Fixture Boundary Containment — NOT Gate Activation

The original scenario runner produced synthetic raw runs and AST reports without
executing actual PR tests. An empty repository could receive a quality PASS. This
document supersedes the original activation instructions. Do not add the previous
workflow candidate to this PR. Existing green C5 checks are not acceptance of this
runner; C5 and production activation remain BLOCKED.

## This patch

- `run_c5_validation_scenario.py` is a fail-closed legacy entrypoint. Both checks
  reject with `trusted_runtime_evidence_unavailable`; no candidate marker or
  self-reported evidence enables success. This is containment, not a complete gate.
- `run_c5_fixture_selftest.py` retains synthetic unit fixtures for verifier testing.
  Its CLI requires `--self-test-only` and reports `C5_FIXTURE_SELF_TEST`, never a
  runtime-gate acceptance. It must not be invoked by a required gate.
- `test_c5_fixture_boundary.py` protects the empty-repo, forged-evidence, marker,
  CLI and fixture-dispatch boundaries. Run with Python unittest discovery in scripts.
- No workflow, C2/C3/C4 verifier, permission, protection or merge mutation is included.

## Acceptance criteria for containment only

1. Empty and populated candidate roots cannot pass the legacy quality gate.
2. All eleven synthetic scenario markers cannot enable either legacy gate.
3. Fixture CLI without the explicit self-test flag fails; fixture PASS is labelled
   synthetic-only, not final-green. All original negative fixtures are retained.
4. Legacy CLI exits nonzero and never prints a PASS; boundary regression tests pass.
5. Review is advisory COMMENT only; approval and any merge remain Human-owned.

## Safe delivery order

Stage A: review this non-workflow containment / bootstrap correction. Human decides
whether to merge it as containment only. It does not activate C5 or authorize removal
of any protection. Do not add a workflow dependent on head-only code to this PR.

Stage B: separately implement actual two-run test collection, source AST inspection,
changed-behavior and coverage evidence, authoritative exception lookup and isolated
untrusted execution. Review and bootstrap the implementation into protected base
before a separate activation PR uses it. That activation must keep existing check
names and fail closed if its trusted prerequisites are missing.

Mandatory negatives before activation: no tests, import/collection failure, forged
or missing artifacts, reused run identity, SHA mismatch, trivial assertions, flaky
runs, invalid negative assertions, untrusted exception claims, and candidate attempts
to alter the verifier or access credentials. Real PR red/green evidence is required;
synthetic fixtures and check names alone cannot satisfy it.
