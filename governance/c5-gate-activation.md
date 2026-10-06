# C5 Gate Activation Remediation

This controlled-pilot remediation activates base-pinned runtime execution behind the
existing `governance-contract` and `test-quality` required-check names.

Acceptance criteria:

- the base trust root, not PR-controlled code, selects and executes every scenario;
- seven governance scenarios fail only `governance-contract`;
- four test-quality scenarios fail only `test-quality`;
- the final clean head makes both C5 checks pass;
- existing C2, C3 and C4 jobs, identities and credential boundaries remain unchanged;
- no Agent approval or merge operation is present.

This PR does not claim C5 runtime closure. A separate validation PR must produce the
eleven red heads and final green evidence after this activation is Human-merged.
