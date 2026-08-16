# D4 Builder handoff

This commit is intentionally authored by the restricted Builder GitHub App.

It restores separation of duties after the human-owned workflow trust root was
added. The next approval must come from a human reviewer who is not the latest
pusher. Deterministic checks remain the required merge signal; AI review remains
advisory.
