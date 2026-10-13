# cors-policy-validator

Catch dangerous CORS policy combinations before they ship — from the config, not the wire. Give it one policy file (declarative JSON or a raw `Access-Control-*` header map) and it flags wildcard-plus-credentials, origin reflection, `null`-origin allowlisting, and six more risky patterns with severity levels. Purely static: no network requests, no attack payloads. Pure Python, standard library only.

## Problem

CORS misconfiguration is a config-review failure, not a runtime mystery: someone writes `"allowed_origins": ["*"]` next to `"allow_credentials": true`, or allowlists the literal string `null`, and nothing complains until a pentest does. Scanning deployed endpoints requires infrastructure and produces noise; the actual decision lives in a config file that could be judged in milliseconds at review time or in CI.

## How it works

1. **Parse**: accepts either declarative JSON (`allowed_origins`, `allow_credentials`, `allowed_methods`, `allowed_headers`, `origin_reflection`) or a raw header map (`{"headers": {"Access-Control-Allow-Origin": "*"}}`), normalized to one internal shape. Unknown fields are rejected, not ignored.
2. **Judge**: nine static rules over the normalized policy, each with a fixed severity:
   - `wildcard-credentials` (critical) — `*` origin + credentials
   - `reflection-credentials` (critical) — reflect any Origin + credentials
   - `null-origin` (high) — the literal `null` origin allowlisted
   - `credentials-no-origins` (high) — credentials with an empty allowlist
   - `subdomain-wildcard-credentials` (medium) — `https://*.example.com` + credentials
   - `origin-syntax` (medium) — malformed origin strings
   - `insecure-scheme-credentials` (low), `wildcard-headers-credentials` (low)
   - `no-origins-configured` (info)
3. **Verdict**: `ok` is false when any high/critical finding exists; `--fail-at` turns that into a CI exit code.

## Quickstart

```bash
# ~1 min total
python cors_policy_validator.py check --config cors.json
python cors_policy_validator.py check --config cors.json --json
python cors_policy_validator.py check --config cors.json --fail-at high   # CI gate
```

## Why not X

- **atibani6012-sys/cors-config-checker** — scans a project directory with "AI-powered analysis" for overly permissive origins and missing headers; it needs `requirements.txt` dependencies and analyzes code, whereas this tool judges a single normalized policy deterministically with a fixed rule table.
- **varvet/cors** — a deprecated library for validating and *signing* S3 CORS policies (upload-form scope), not a general policy safety judge.
- **Browser DevTools / endpoint probes** — test the live server, need the server running, and only see one reflected request; they cannot audit the full origin list or catch `null` allowlisting.
- **Manual review** — the nine dangerous combinations above are exactly the ones reviewers miss on a Friday afternoon.

## How this differs from cors-config-checker

The closest anchor, `atibani6012-sys/cors-config-checker`, walks a project tree and uses "AI-powered analysis to scan for vulnerabilities and security anti-patterns" (its README), reporting origins and missing security headers as it finds them in code. That is discovery-oriented: helpful when you do not know where CORS is configured, at the cost of LLM non-determinism and Python dependencies. This repo is the judgment layer: it takes an already-extracted policy and applies a fixed, versioned rule table with deterministic severities — the same input always yields the same verdict, so it can gate CI. One finds CORS config; the other decides whether a given config is safe. (Both are static/offline; this one additionally accepts raw header-map form so output from the discovery layer can feed straight into it.)

## Performance

[Measured] on Windows 10 Pro, Python 3.11, 2026-10-13. A 2,000-origin policy checks in **0.97 ms per run** (0.049 s for 50 runs). Reproduce:

```bash
python -c "import time,cors_policy_validator as m; pol={'allowed_origins':['https://h%d.example.com'%i for i in range(2000)],'allow_credentials':False}; t0=time.perf_counter(); [m.check(pol) for _ in range(50)]; print((time.perf_counter()-t0)*20)"
```

## Minimal Fallback

No Python? Search your config for these literal strings and judge by eye: `"*"` next to `Allow-Credentials: true` (critical); `null` in an origin list (high); `Origin` echoed back with credentials (critical). If none appear and the origin list is explicit HTTPS, you are very likely fine.

## Design Trade-offs

- **Fixed rule table over heuristics/LLM** — deterministic verdicts are CI-gateable; unusual-but-safe setups may produce false positives that a human overrules.
- **Reject unknown fields** — typos like `allowd_origins` fail loudly instead of silently weakening the policy.
- **No DNS or reachability checks** — zero network keeps the tool sandboxable and fast; a validly-formatted origin may still not resolve.
- **Header-map acceptance** — slightly more parsing complexity in exchange for working directly with what servers actually emit.

## Limits & Second-order Effects

- Static judgment cannot see runtime behavior: a server that echoes arbitrary origins while its config says otherwise will pass here.
- `--fail-at` in CI can train teams to downgrade severities instead of fixing configs.
- The rule table encodes current browser behavior (wildcard+credentials is refused by browsers); a future browser change could shift severities.
- Passing `ok: true` may create false confidence — it means "no known dangerous pattern", not "this origin model is what you intended".

## FAQ

**When NOT to use this?**
When you need to verify what a *running* server actually sends, or when policies are generated dynamically per request — static config judgment cannot cover either. Probe the endpoint instead, then feed the observed headers here.

**Does it send any requests?**
No. Zero network, zero payloads — it reads one local JSON file.

**Why reject unknown fields instead of warning?**
In a safety judgment, silence is failure: an unknown field is usually a typo of a field that matters.

**Can I check multiple files?**
Run the CLI once per file, or call `check()` in a loop from Python.

## Core Assumptions

- [A1] The dangerous patterns worth flagging are enumerable as fixed config combinations. Confidence: High — the critical ones are browser-mandated behavior.
- [A2] Policies can be extracted into the accepted JSON shapes without loss. Confidence: Medium — exotic frameworks may need a conversion step.
- [A3] Deterministic severity verdicts are more valuable in review/CI than adaptive analysis. Confidence: High.
- [A4] `null`-origin allowlisting is virtually always unintentional. Confidence: High.

Confidence in the rule table (as of browser behavior): High. As of 2026-10-13.

## License

MIT — see [LICENSE](LICENSE). Contact: hcac4735@agent.qq.com

---

Part of the [zhengming-toolbox](https://github.com/chenhz01/zhengming-toolbox) — 105 purpose-built AI-engineering tools across neglected niches.

Related tools: [cron-security-audit](https://github.com/chenhz01/cron-security-audit) · [vendor-lockin-ledger](https://github.com/chenhz01/vendor-lockin-ledger) · [session-token-hygiene](https://github.com/chenhz01/session-token-hygiene)
