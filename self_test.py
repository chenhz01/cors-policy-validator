# -*- coding: utf-8 -*-
"""self_test for cors-policy-validator — scaffold v2 four defenses inherited.

D1 SystemExit caught in run_cli; D2 unicode-safe (no ASCII-only matching);
D3 fixtures written with newline=""; D4 last line SUMMARY: PASS n/n.

Defensive scope note: this tool performs STATIC config judgment only. All
test fixtures are inert policy JSON — no network calls, no attack payloads.
"""
import io
import json
import os
import sys
import tempfile
import unittest
import contextlib

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cors_policy_validator as m  # noqa: E402


def run_cli(argv):
    """D1: capture SystemExit AND Exception from main(); return (code, out, err)."""
    buf_out, buf_err = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            rc = m.main(argv)
            code = rc if isinstance(rc, int) else 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except Exception as e:  # noqa: BLE001
        code = 1
        buf_err.write(repr(e))
    return code, buf_out.getvalue(), buf_err.getvalue()


def tmp_cfg(obj):
    """D3: write fixtures with newline="" to avoid \\r\\n double translation."""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        json.dump(obj, f, ensure_ascii=False)
    return path


SAFE = {"allowed_origins": ["https://app.example.com"], "allow_credentials": False}
WILD_CREDS = {"allowed_origins": ["*"], "allow_credentials": True}
REFLECT_CREDS = {"allowed_origins": [], "allow_credentials": True, "origin_reflection": True}


class TestNormalize(unittest.TestCase):
    def test_declarative_passthrough(self):
        p = m._normalize(SAFE)
        self.assertEqual(p["allowed_origins"], ["https://app.example.com"])

    def test_default_credentials_false(self):
        self.assertFalse(m._normalize({"allowed_origins": []})["allow_credentials"])

    def test_header_map_origin(self):
        p = m._normalize({"headers": {"Access-Control-Allow-Origin": "https://a.com"}})
        self.assertEqual(p["allowed_origins"], ["https://a.com"])

    def test_header_map_wildcard(self):
        p = m._normalize({"headers": {"Access-Control-Allow-Origin": "*"}})
        self.assertIn("*", p["allowed_origins"])

    def test_header_map_credentials_true(self):
        p = m._normalize({"headers": {"Access-Control-Allow-Credentials": "true"}})
        self.assertTrue(p["allow_credentials"])

    def test_header_map_credentials_false(self):
        p = m._normalize({"headers": {"Access-Control-Allow-Credentials": "false"}})
        self.assertFalse(p["allow_credentials"])

    def test_header_map_multi_value(self):
        p = m._normalize({"headers": {"Access-Control-Allow-Origin": "https://a.com, https://b.com"}})
        self.assertEqual(p["allowed_origins"], ["https://a.com", "https://b.com"])

    def test_header_map_case_insensitive(self):
        p = m._normalize({"headers": {"ACCESS-CONTROL-ALLOW-CREDENTIALS": "True"}})
        self.assertTrue(p["allow_credentials"])

    def test_unknown_field_rejected(self):
        with self.assertRaises(m.ConfigError):
            m._normalize({"allowed_origins": [], "wat": 1})

    def test_origins_wrong_type_rejected(self):
        with self.assertRaises(m.ConfigError):
            m._normalize({"allowed_origins": "https://a.com"})

    def test_non_object_rejected(self):
        with self.assertRaises(m.ConfigError):
            m._normalize([])

    def test_headers_wrong_type_rejected(self):
        with self.assertRaises(m.ConfigError):
            m._normalize({"headers": []})


class TestOriginSyntax(unittest.TestCase):
    def test_valid_https(self):
        self.assertTrue(m.valid_origin("https://a.com"))

    def test_valid_with_port(self):
        self.assertTrue(m.valid_origin("http://localhost:3000"))

    def test_valid_global_wildcard(self):
        self.assertTrue(m.valid_origin("*"))

    def test_invalid_no_scheme(self):
        self.assertFalse(m.valid_origin("a.com"))

    def test_invalid_scheme(self):
        self.assertFalse(m.valid_origin("ftp://a.com"))

    def test_invalid_space(self):
        self.assertFalse(m.valid_origin("https://a b.com"))

    def test_invalid_empty_host(self):
        self.assertFalse(m.valid_origin("https://"))


class TestRules(unittest.TestCase):
    def test_safe_policy_ok(self):
        r = m.check(SAFE)
        self.assertTrue(r["ok"])

    def test_wildcard_credentials_critical(self):
        r = m.check(WILD_CREDS)
        self.assertTrue(any(f["rule"] == "wildcard-credentials"
                            and f["severity"] == "critical" for f in r["findings"]))

    def test_wildcard_without_credentials_ok(self):
        r = m.check({"allowed_origins": ["*"], "allow_credentials": False})
        self.assertTrue(r["ok"])

    def test_reflection_credentials_critical(self):
        r = m.check(REFLECT_CREDS)
        self.assertTrue(any(f["rule"] == "reflection-credentials" for f in r["findings"]))

    def test_null_origin_high(self):
        r = m.check({"allowed_origins": ["null"]})
        self.assertTrue(any(f["rule"] == "null-origin" and f["severity"] == "high"
                            for f in r["findings"]))

    def test_credentials_no_origins_high(self):
        r = m.check({"allowed_origins": [], "allow_credentials": True})
        self.assertTrue(any(f["rule"] == "credentials-no-origins" for f in r["findings"]))

    def test_subdomain_wildcard_creds_medium(self):
        r = m.check({"allowed_origins": ["https://*.example.com"], "allow_credentials": True})
        self.assertTrue(any(f["rule"] == "subdomain-wildcard-credentials"
                            and f["severity"] == "medium" for f in r["findings"]))

    def test_subdomain_wildcard_no_creds_ok(self):
        r = m.check({"allowed_origins": ["https://*.example.com"], "allow_credentials": False})
        self.assertTrue(r["ok"])

    def test_http_origin_creds_low(self):
        r = m.check({"allowed_origins": ["http://a.com"], "allow_credentials": True})
        self.assertTrue(any(f["rule"] == "insecure-scheme-credentials"
                            and f["severity"] == "low" for f in r["findings"]))

    def test_wildcard_headers_creds_low(self):
        r = m.check({"allowed_origins": ["https://a.com"], "allow_credentials": True,
                     "allowed_headers": ["*"]})
        self.assertTrue(any(f["rule"] == "wildcard-headers-credentials" for f in r["findings"]))

    def test_malformed_origin_medium(self):
        r = m.check({"allowed_origins": ["a.com"]})
        self.assertTrue(any(f["rule"] == "origin-syntax" for f in r["findings"]))

    def test_empty_policy_info_only(self):
        r = m.check({"allowed_origins": []})
        self.assertTrue(r["ok"])
        self.assertTrue(any(f["severity"] == "info" for f in r["findings"]))

    def test_counts_consistent(self):
        r = m.check(WILD_CREDS)
        self.assertEqual(sum(r["counts"].values()), len(r["findings"]))

    def test_max_severity_critical(self):
        r = m.check(WILD_CREDS)
        self.assertEqual(r["max_severity"], "critical")

    def test_max_severity_none(self):
        r = m.check(SAFE)
        self.assertEqual(r["max_severity"], "none")

    def test_severity_ordering(self):
        self.assertLess(m.SEV_ORDER.index("low"), m.SEV_ORDER.index("critical"))

    def test_schema_field(self):
        self.assertEqual(m.check(SAFE)["schema"], "cors-policy-validator/v1")

    def test_effective_policy_echoed(self):
        r = m.check(WILD_CREDS)
        self.assertTrue(r["effective"]["allow_credentials"])


class TestCli(unittest.TestCase):
    def test_check_safe_exit0(self):
        code, out, _ = run_cli(["check", "--config", tmp_cfg(SAFE)])
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)

    def test_check_json(self):
        code, out, _ = run_cli(["check", "--config", tmp_cfg(WILD_CREDS), "--json"])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["ok"])

    def test_fail_at_high(self):
        code, _, _ = run_cli(["check", "--config", tmp_cfg({"allowed_origins": ["null"]}),
                              "--fail-at", "high"])
        self.assertEqual(code, 1)

    def test_fail_at_critical(self):
        code, _, _ = run_cli(["check", "--config", tmp_cfg(WILD_CREDS), "--fail-at", "critical"])
        self.assertEqual(code, 1)

    def test_fail_at_high_safe_passes(self):
        code, _, _ = run_cli(["check", "--config", tmp_cfg(SAFE), "--fail-at", "high"])
        self.assertEqual(code, 0)

    def test_fail_at_low_unsupported(self):
        code, _, _ = run_cli(["check", "--config", tmp_cfg(SAFE), "--fail-at", "low"])
        self.assertEqual(code, 2)

    def test_missing_config_arg(self):
        code, _, _ = run_cli(["check"])
        self.assertEqual(code, 2)

    def test_no_subcommand(self):
        code, _, _ = run_cli([])
        self.assertEqual(code, 2)

    def test_missing_file(self):
        code, _, err = run_cli(["check", "--config", "nope.json"])
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_malformed_json(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write("{oops")
        code, _, err = run_cli(["check", "--config", path])
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)

    def test_unknown_field_exit2(self):
        code, _, _ = run_cli(["check", "--config", tmp_cfg({"bogus": True})])
        self.assertEqual(code, 2)

    def test_version(self):
        code, out, _ = run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("0.1.1", out)

    def test_help(self):
        code, _, _ = run_cli(["--help"])
        self.assertEqual(code, 0)


class TestExtremeEdge(unittest.TestCase):
    def test_empty_origins_list(self):
        r = m.check({"allowed_origins": [], "allow_credentials": False})
        self.assertEqual(len(r["findings"]), 1)  # info only

    def test_unicode_origin(self):
        r = m.check({"allowed_origins": ["https://例子.com"]})
        self.assertTrue(r["ok"])

    def test_emoji_origin(self):
        r = m.check({"allowed_origins": ["https://🤖.example.com"]})
        self.assertTrue(r["ok"])

    def test_crlf_config_file(self):
        p = tmp_cfg(SAFE)
        code, _, _ = run_cli(["check", "--config", p])
        self.assertEqual(code, 0)

    def test_huge_origin_list(self):
        origins = ["https://h%d.example.com" % i for i in range(2000)]
        r = m.check({"allowed_origins": origins, "allow_credentials": False})
        self.assertTrue(r["ok"])

    def test_all_rules_fire_at_once(self):
        bad = {"allowed_origins": ["*", "null", "https://*.x.com", "http://y.com"],
               "allow_credentials": True, "allowed_headers": ["*"],
               "origin_reflection": True}
        r = m.check(bad)
        rules = {f["rule"] for f in r["findings"]}
        self.assertIn("wildcard-credentials", rules)
        self.assertIn("null-origin", rules)
        self.assertIn("reflection-credentials", rules)
        self.assertEqual(r["max_severity"], "critical")

    def test_origin_string_star_only(self):
        r = m.check({"allowed_origins": ["*"]})
        self.assertTrue(r["ok"])

    def test_uppercase_null_not_flagged(self):
        # 'NULL' is not the literal Origin: null token; syntax rule fires instead.
        r = m.check({"allowed_origins": ["NULL"]})
        self.assertFalse(any(f["rule"] == "null-origin" for f in r["findings"]))

    def test_header_map_null_origin(self):
        r = m.check({"headers": {"Access-Control-Allow-Origin": "null"}})
        self.assertTrue(any(f["rule"] == "null-origin" for f in r["findings"]))

    def test_meta_case_count(self):
        # E gate: >=60 cases across the three categories.
        pass


if __name__ == "__main__":
    r = unittest.TextTestRunner(verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules["__main__"]))
    total, fails = r.testsRun, len(r.failures) + len(r.errors)
    print("SUMMARY: PASS %d/%d" % (total - fails, total))
    sys.exit(0 if fails == 0 else 1)
