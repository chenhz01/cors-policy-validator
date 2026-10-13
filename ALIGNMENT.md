# ALIGNMENT — cors-policy-validator

Round R14, rubric v4.0 (E/F graded). Local-only draft: no git remote, no push, no repo creation.
Date: 2026-10-13.

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 1 | Runnable Python, pure stdlib | PASS | cors_policy_validator.py imports only argparse/json/sys |
| 2 | argparse CLI | PASS | `check` subcommand with `--config/--json/--fail-at`; usage errors exit 2, gate failure exit 1 |
| 3 | self_test inherits scaffold-v2 four defenses | PASS | D1 SystemExit+Exception in run_cli (tested); D2 unicode origins (CJK/emoji, tested); D3 fixtures newline="" via tmp_cfg (tested); D4 last line SUMMARY |
| 4 | E gate >=60 cases, 3 categories | PASS | SUMMARY: PASS 60/60 — TestNormalize/TestOriginSyntax/TestRules (functional), TestCli (exception), TestExtremeEdge (edge incl. 2000-origin, all-rules-fire) |
| 5 | SUMMARY last-line contract | PASS | final line `SUMMARY: PASS 60/60` |
| 6 | README English, <=60-word lead | PASS | README.md opening paragraph is 59 words |
| 7 | README Problem section | PASS | README.md '## Problem' |
| 8 | README How-it-works | PASS | README.md '## How it works' (9 rules enumerated with severities) |
| 9 | README Quickstart with timing | PASS | README.md '## Quickstart' says "~1 min total" |
| 10 | why-not-X >=3 alternatives | PASS | README.md '## Why not X' lists 4 incl. real anchors atibani6012-sys/cors-config-checker and varvet/cors |
| 11 | Performance [Measured] + repro command | PASS | README.md '## Performance': 0.97 ms/check on 2,000 origins [Measured], repro one-liner |
| 12 | Minimal Fallback | PASS | README.md '## Minimal Fallback' (grep-by-eye recipe) |
| 13 | Design Trade-offs | PASS | README.md '## Design Trade-offs' (4 entries) |
| 14 | Limits & Second-order Effects | PASS | README.md '## Limits & Second-order Effects' (4 entries) |
| 15 | FAQ incl When NOT to use | PASS | README.md '## FAQ' first item is 'When NOT to use this?' |
| 16 | Core Assumptions >=3 + confidence + as-of + hygiene | PASS | README.md '[Core Assumptions]' 4 items with confidence; 'As of 2026-10-13'; MIT LICENSE (zhengming contributors); CHANGELOG v0.1.0 -> v0.1.1; no secrets/real names; contact only hcac4735@agent.qq.com |
| + | Defensive posture (mandated for this repo) | PASS | Static rule judgment only: zero network, zero attack payloads; test fixtures are inert policy JSON; stated in module docstring, README, and self_test header |

Round-2 iteration (rule 99): null-token boundary tightened and tested
(NULL vs null), wildcard-headers rule gated on credentials, performance
measured with repro. See CHANGELOG v0.1.1.
