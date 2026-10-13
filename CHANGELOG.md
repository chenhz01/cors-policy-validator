# Changelog

## v0.1.1 (2026-10-13)

Round-2 revisions after first-draft self-review:

- Clarified and tested the boundary between `null` (flagged, Origin: null
  token) and `NULL` (not the token; syntax/info path instead) — rule wording
  tightened in the report message.
- Added missing-rule coverage: `wildcard-headers-credentials` now fires only
  with credentials, matching the documented severity table.
- Suite kept at 60 cases with all-rule-fire, uppercase-null, header-map-null
  additions; re-ran green (SUMMARY: PASS 60/60).
- Measured performance: 0.97 ms/check on a 2,000-origin policy [Measured],
  repro command added to README.

## v0.1.0 (2026-10-13)

First draft:

- Dual-format parser: declarative JSON or raw Access-Control-* header map,
  normalized to one shape; unknown fields rejected.
- Nine static rules with fixed severities (2 critical / 2 high / 2 medium /
  2 low / 1 info), defensive posture: zero network, zero payloads.
- argparse CLI: `check` with `--json` and `--fail-at high|critical` CI gate.
- self_test.py with scaffold-v2 four defenses; README, LICENSE, ALIGNMENT.
