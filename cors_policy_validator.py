#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cors-policy-validator — static safety judgment of CORS policy configurations.

Parses a CORS policy (declarative JSON or raw header map) and flags dangerous
combinations — wildcard origins with credentials, origin reflection, "null"
origin allowlisting, and related patterns. Purely static: reads one local
config file. No network requests, no attack payloads, no execution.
"""
import argparse
import json
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sys.stderr.reconfigure(encoding="utf-8", newline="\n")
except Exception:
    pass

VERSION = "0.1.1"
SEV_ORDER = ["info", "low", "medium", "high", "critical"]

KNOWN_FIELDS = {"allowed_origins", "allow_credentials", "allowed_methods",
                "allowed_headers", "origin_reflection"}
KNOWN_HEADERS = {"access-control-allow-origin", "access-control-allow-credentials",
                 "access-control-allow-methods", "access-control-allow-headers",
                 "access-control-expose-headers", "access-control-max-age",
                 "vary", "origin"}


class ConfigError(Exception):
    """Input problem that maps to exit code 2."""


def _normalize(policy):
    """Accept declarative JSON or a raw header map; return a canonical dict."""
    if not isinstance(policy, dict):
        raise ConfigError("policy must be a JSON object")
    if "headers" in policy:
        headers = policy["headers"]
        if not isinstance(headers, dict):
            raise ConfigError("'headers' must be an object")
        lowered = {k.lower(): str(v) for k, v in headers.items()}
        creds = lowered.get("access-control-allow-credentials", "false").lower() == "true"
        return {
            "allowed_origins": _split_header_value(lowered.get("access-control-allow-origin", "")),
            "allow_credentials": creds,
            "allowed_methods": _split_header_value(lowered.get("access-control-allow-methods", "")),
            "allowed_headers": _split_header_value(lowered.get("access-control-allow-headers", "")),
            "origin_reflection": False,
        }
    unknown = set(policy) - KNOWN_FIELDS
    if unknown:
        raise ConfigError("unknown policy field(s): %s" % ", ".join(sorted(unknown)))
    origins = policy.get("allowed_origins", [])
    if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
        raise ConfigError("'allowed_origins' must be a list of strings")
    return {
        "allowed_origins": list(origins),
        "allow_credentials": bool(policy.get("allow_credentials", False)),
        "allowed_methods": list(policy.get("allowed_methods", [])),
        "allowed_headers": list(policy.get("allowed_headers", [])),
        "origin_reflection": bool(policy.get("origin_reflection", False)),
    }


def _split_header_value(v):
    return [p.strip() for p in v.split(",") if p.strip()] if v else []


def valid_origin(o):
    """Origin must be scheme://host[:port]; wildcard subdomains allowed as host."""
    if o == "*":
        return True
    if "://" not in o:
        return False
    scheme, host = o.split("://", 1)
    if scheme not in ("http", "https"):
        return False
    if not host or host.startswith("/") or " " in host:
        return False
    return True


def check(policy):
    """Core static check. Returns report dict. Raises ConfigError on bad shape."""
    p = _normalize(policy)
    origins = p["allowed_origins"]
    creds = p["allow_credentials"]
    findings = []

    def add(rule, sev, msg):
        findings.append({"rule": rule, "severity": sev, "message": msg})

    for o in origins:
        if not valid_origin(o):
            add("origin-syntax", "medium", "malformed origin %r (expected scheme://host[:port])" % o)

    if "*" in origins and creds:
        add("wildcard-credentials", "critical",
            "allowed_origins contains '*' together with allow_credentials=true; "
            "browsers refuse credentialed wildcard CORS and misconfigured servers "
            "instead echo arbitrary origins")
    if p["origin_reflection"] and creds:
        add("reflection-credentials", "critical",
            "origin_reflection=true with allow_credentials=true reflects any "
            "attacker-chosen Origin with credentialed responses")
    if "null" in origins:
        add("null-origin", "high",
            "the string 'null' is allowlisted as an origin; sandboxed iframes and "
            "redirected requests send Origin: null, so this is rarely intentional")
    if creds and not origins and not p["origin_reflection"]:
        add("credentials-no-origins", "high",
            "allow_credentials=true but no origin is allowlisted; policy is "
            "either inert or relies on undocumented reflection")
    for o in origins:
        if o.startswith("http://*.") or o.startswith("https://*."):
            if creds:
                add("subdomain-wildcard-credentials", "medium",
                    "wildcard subdomain %r combined with credentials trusts every "
                    "subdomain, including any that can be registered or hijacked" % o)
        if o.startswith("http://") and creds:
            add("insecure-scheme-credentials", "low",
                "origin %r uses http:// with credentials; tokens travel in cleartext" % o)
    if "*" in p["allowed_headers"] and creds:
        add("wildcard-headers-credentials", "low",
            "allowed_headers='*' with credentials echoes arbitrary request headers")
    if not origins and not p["origin_reflection"]:
        add("no-origins-configured", "info", "no origins allowlisted; policy denies cross-origin access")

    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    blocking = counts["high"] + counts["critical"]
    return {
        "schema": "cors-policy-validator/v1",
        "effective": p,
        "findings": findings,
        "counts": counts,
        "max_severity": max((f["severity"] for f in findings),
                            key=lambda s: SEV_ORDER.index(s)) if findings else "none",
        "ok": blocking == 0,
    }


def load_policy(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except OSError as e:
        raise ConfigError("cannot read config: %s" % e)
    except ValueError as e:
        raise ConfigError("config is not valid JSON: %s" % e)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cors-policy-validator",
        description="Static safety judgment of CORS policy configurations. Zero network, zero payloads.")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("check", help="check a CORS policy file")
    p.add_argument("--config", required=True, help="policy JSON (declarative or raw header map)")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--fail-at", choices=["high", "critical"], default=None,
                   help="exit 1 when any finding reaches this severity")

    args = parser.parse_args(argv)
    if args.cmd != "check":
        parser.print_usage(sys.stderr)
        return 2
    try:
        report = check(load_policy(args.config))
    except ConfigError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        print("cors-policy-validator: %d finding(s), max severity: %s"
              % (len(report["findings"]), report["max_severity"]))
        for f in report["findings"]:
            print("  [%s] %s: %s" % (f["severity"].upper(), f["rule"], f["message"]))
        print("verdict: %s" % ("PASS" if report["ok"] else "FAIL"))

    if args.fail_at and report["counts"][args.fail_at] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
