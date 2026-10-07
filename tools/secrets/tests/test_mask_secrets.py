#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for mask_secrets.py - they encode the clauses of the disclosure policy.

Every value used here is a deliberately invalid example (``EXAMPLE`` filler).
Nothing in this suite performs a network request.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)  # fixtures.py

import mask_secrets as ms  # noqa: E402

from fixtures import (  # noqa: E402  (fixtures are intentionally invalid values)
    OTP_LINES,
    PLACEHOLDER_LINES,
    SAMPLE_OTP,
    SAMPLE_AWS_SECRET,
    SAMPLE_DB_URI,
    SAMPLE_GITHUB,
    SAMPLE_GOOGLE,
    SAMPLE_JWT,
    SAMPLE_KEY_BODY,
    SAMPLE_PASSWORD,
    SAMPLE_PEM,
    SAMPLE_OPENAI,
    SAMPLE_RECOVERY_BLOCK,
    SAMPLE_SLACK,
    SAMPLE_STRIPE,
    SAMPLE_AWS_ID,
    SAMPLE_GITLAB,
    SAMPLE_HF,
)


def run_cli(argv):
    """Run the CLI in-process; return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = ms.main(argv)
        except SystemExit as exc:  # argparse errors
            code = exc.code if isinstance(exc.code, int) else 2
    return code, out.getvalue(), err.getvalue()


def write(directory, name, content):
    path = os.path.join(directory, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def assert_no_secret(test, payload, *secrets):
    for secret in secrets:
        test.assertNotIn(secret, payload, f"report leaked {secret[:6]}...")


class TestMasking(unittest.TestCase):
    """Policy 1 - minimal disclosure."""

    def test_policy_example_is_reproduced(self):
        self.assertEqual(ms.mask_secret("sk-1234567890abcdef"), "sk-1234\u2022\u2022\u2022\u2022\u2022\u2022cdef")

    def test_short_values_are_fully_masked(self):
        for value in ("hunter2", "abc", "12345678", ""):
            self.assertEqual(ms.mask_secret(value), "\u2022" * ms.MASK_RUN)

    def test_risk_information_is_retained(self):
        masked = ms.mask_secret(SAMPLE_OPENAI)
        self.assertTrue(masked.startswith("sk-pro"))
        self.assertTrue(masked.endswith("EXA"))
        self.assertLess(len(masked), len(SAMPLE_OPENAI))

    def test_otp_never_keeps_prefix_or_suffix(self):
        """Policy 7 - one-time codes are extra sensitive."""
        findings = ms.scan_text(SAMPLE_OTP, "notes.txt")
        otp = [f for f in findings if f.category == "otp"]
        self.assertTrue(otp)
        self.assertEqual(otp[0].mask, "\u2022" * ms.MASK_RUN)
        self.assertNotIn("4821", otp[0].mask)

    def test_private_key_block_is_redacted_without_material(self):
        """A bare header keeps the type visible and hides everything else."""
        findings = ms.scan_text(SAMPLE_PEM, "id_rsa")
        self.assertTrue(findings)
        self.assertIn("REDACTED", findings[0].mask)
        self.assertEqual(findings[0].severity, "medium")

    def test_private_key_block_with_material_is_critical(self):
        text = f"{SAMPLE_PEM}\n{SAMPLE_KEY_BODY}\n{SAMPLE_KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n"
        finding = ms.scan_text(text, "id_rsa")[0]
        self.assertEqual(finding.severity, "critical")
        assert_no_secret(self, finding.snippet, SAMPLE_KEY_BODY)

    def test_private_key_header_quoted_in_documentation_is_medium(self):
        """A header quoted in docs is a review item, not a leaked key."""
        finding = ms.scan_text(f"report the header `{SAMPLE_PEM}` only", "AGENTS.md")[0]
        self.assertEqual(finding.severity, "medium")

    def test_private_key_header_is_redacted_exactly_once(self):
        """The snippet must not duplicate the header around the mask (policy 4)."""
        finding = ms.scan_text(SAMPLE_PEM, "id_rsa")[0]
        self.assertEqual(finding.snippet.count("BEGIN"), 1)
        self.assertIn("REDACTED", finding.snippet)


class TestDetection(unittest.TestCase):
    def test_known_providers(self):
        cases = {
            "openai_api_key": SAMPLE_OPENAI,
            "aws_access_key_id": SAMPLE_AWS_ID,
            "github_token": SAMPLE_GITHUB,
            "google_api_key": SAMPLE_GOOGLE,
            "slack_token": SAMPLE_SLACK,
            "stripe_secret_key": SAMPLE_STRIPE,
            "gitlab_token": SAMPLE_GITLAB,
            "huggingface_token": SAMPLE_HF,
            "jwt": SAMPLE_JWT,
        }
        for expected, value in cases.items():
            with self.subTest(rule=expected):
                findings = ms.scan_text(f"key = {value}", "config.txt")
                self.assertIn(expected, [f.type for f in findings])

    def test_aws_secret_key_assignment(self):
        line = f"AWS_SECRET_ACCESS_KEY={SAMPLE_AWS_SECRET}"
        findings = ms.scan_text(line, "creds")
        self.assertIn("aws_secret_access_key", [f.type for f in findings])

    def test_credentials_in_uri(self):
        findings = ms.scan_text(SAMPLE_DB_URI, "docker-compose.yml")
        self.assertTrue(any(f.category == "uri_credentials" for f in findings))

    def test_password_assignment(self):
        finding = ms.scan_text(f'DB_PASSWORD="{SAMPLE_PASSWORD}"', "app.env")
        self.assertTrue(finding)
        self.assertEqual(finding[0].severity, "medium")

    def test_bearer_token(self):
        line = f"Authorization: Bearer {SAMPLE_OPENAI}"
        findings = ms.scan_text(line, "trace.log")
        self.assertTrue(findings)

    def test_overlap_resolution_prefers_specific_rule(self):
        findings = ms.scan_text(f'OPENAI_KEY = "{SAMPLE_OPENAI}"', "x.py")
        types = {f.type for f in findings}
        self.assertIn("openai_api_key", types)
        self.assertNotIn("credential_assignment", types)
        self.assertEqual(len(findings), 1)

    def test_placeholders_are_not_reported(self):
        for line in PLACEHOLDER_LINES:
            with self.subTest(line=line):
                self.assertEqual(ms.scan_text(line, "sample.env"), [])

    def test_low_entropy_junk_is_ignored(self):
        self.assertEqual(ms.scan_text("token = aaaaaaaa", "x"), [])

    def test_clean_file_has_no_findings(self):
        text = "def add(a, b):\n    return a + b\n"
        self.assertEqual(ms.scan_text(text, "math.py"), [])

    def test_one_time_and_recovery_codes_are_detected(self):
        """Policy 7 - codes appear in many shapes; all are masked completely."""
        for line in OTP_LINES:
            with self.subTest(line=line):
                findings = ms.scan_text(line, "notes.txt")
                self.assertTrue(findings)
                self.assertEqual(findings[0].category, "otp")
                self.assertEqual(findings[0].severity, "critical")
                self.assertEqual(findings[0].mask, "\u2022" * ms.MASK_RUN)

    def test_placeholder_recovery_codes_are_ignored(self):
        for line in ("backup codes: xxxx-xxxx-xxxx", "backup codes: 0000-0000"):
            with self.subTest(line=line):
                self.assertEqual(ms.scan_text(line, "docs.md"), [])


class TestSnippets(unittest.TestCase):
    """Policy 4 - no secrets inside reports, snippets or titles."""

    def test_snippet_is_redacted(self):
        findings = ms.scan_text(f'API_KEY="{SAMPLE_OPENAI}"  # rotate me', "a.env")
        self.assertTrue(findings)
        assert_no_secret(self, findings[0].snippet, SAMPLE_OPENAI)
        self.assertIn(ms.mask_secret(SAMPLE_OPENAI), findings[0].snippet)
        self.assertIn("rotate me", findings[0].snippet)

    def test_multi_secret_line_is_fully_redacted(self):
        line = f"a={SAMPLE_OPENAI} b={SAMPLE_GITHUB}"
        findings = ms.scan_text(line, "x")
        self.assertGreaterEqual(len(findings), 2)
        for finding in findings:
            assert_no_secret(self, finding.snippet, SAMPLE_OPENAI, SAMPLE_GITHUB)

    def test_fingerprint_is_stable_and_non_reversible(self):
        first = ms.scan_text(f"k={SAMPLE_OPENAI}", "f1")[0]
        second = ms.scan_text(f"k={SAMPLE_OPENAI}", "f1")[0]
        other = ms.scan_text(f"k={SAMPLE_OPENAI}", "f2")[0]
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertNotEqual(first.fingerprint, other.fingerprint)
        self.assertNotIn(SAMPLE_OPENAI, first.fingerprint)

    def test_paths_and_ids_never_embed_a_secret(self):
        findings = ms.scan_text(f"k={SAMPLE_OPENAI}", "f")
        assert_no_secret(self, findings[0].path, SAMPLE_OPENAI)
        assert_no_secret(self, findings[0].id, SAMPLE_OPENAI)


class TestRevealGating(unittest.TestCase):
    """Policy 2 - a full value needs an explicit, recorded authorisation."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = write(self.tmp.name, "app.env", f'API_KEY="{SAMPLE_OPENAI}"\n')

    def test_reveal_requires_ownership_and_statement(self):
        for argv in (
            ["--reveal", self.path],
            ["--reveal", "--ownership", "user", "--owned-file", self.path, self.path],
            ["--reveal", "--owned-file", self.path, "--confirm-ownership", "mine", self.path],
        ):
            with self.subTest(argv=argv):
                code, _, err = run_cli(argv + ["--lang", "en"])
                self.assertEqual(code, 2)
                self.assertIn("policy", err)

    def test_reveal_is_blocked_for_third_party(self):
        code, _, err = run_cli([
            "--reveal", "--ownership", "third_party", "--confirm-ownership", "not mine",
            "--owned-file", self.path, self.path, "--lang", "en",
        ])
        self.assertEqual(code, 2)
        self.assertIn("policy 3", err)

    def test_reveal_is_blocked_for_files_and_machine_formats(self):
        base = ["--reveal", "--ownership", "user", "--confirm-ownership", "I own this",
                "--owned-file", self.path]
        for extra in (["--format", "json"], ["--format", "sarif"], ["--format", "markdown"],
                      ["--out", os.path.join(self.tmp.name, "r.md"), "--format", "markdown"]):
            with self.subTest(extra=extra):
                code, _, err = run_cli(base + extra + [self.path, "--lang", "en"])
                self.assertEqual(code, 2)
                self.assertIn("policy 4", err)

    def test_reveal_shows_the_value_only_for_the_declared_file(self):
        other_dir = os.path.join(self.tmp.name, "other")
        write(other_dir, "leak.env", f"TOKEN={SAMPLE_GITHUB}\n")
        code, out, err = run_cli([
            "--reveal", "--ownership", "user", "--confirm-ownership", "I own this repo",
            "--owned-file", self.path, self.path, other_dir, "--lang", "en",
        ])
        self.assertEqual(code, 1)  # finding present, --fail-on high by default
        self.assertIn(SAMPLE_OPENAI, out)          # declared file: authorised
        self.assertNotIn(SAMPLE_GITHUB, out)       # undeclared file: masked
        self.assertIn(ms.mask_secret(SAMPLE_GITHUB), out)
        self.assertIn("authorised disclosure", out)
        self.assertIn("WARNING", err)

    def test_no_reveal_option_means_no_full_value(self):
        code, out, _ = run_cli([self.path, "--lang", "en"])
        self.assertEqual(code, 1)
        assert_no_secret(self, out, SAMPLE_OPENAI)


class TestReports(unittest.TestCase):
    """Policies 4 and 5 - the audit record stays masked and complete."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = write(self.tmp.name, "app.env", f'API_KEY="{SAMPLE_OPENAI}"\n')
        write(self.tmp.name, "uri.txt", SAMPLE_DB_URI + "\n")

    def test_json_report_is_masked_and_complete(self):
        code, out, _ = run_cli(["--format", "json", self.tmp.name, "--lang", "pl"])
        self.assertEqual(code, 1)
        assert_no_secret(self, out, SAMPLE_OPENAI, "EXAMPLEdbpassword123")
        data = json.loads(out)
        self.assertEqual(data["schema"], ms.SCHEMA)
        self.assertFalse(data["tool"]["network_used"])
        self.assertEqual(data["policy"]["clauses"][0], "1")
        self.assertGreaterEqual(data["summary"]["total"], 2)
        first = data["findings"][0]
        for key in ("id", "type", "service", "severity", "source", "masked_value",
                    "verification_status", "ownership", "remediation", "fingerprint"):
            self.assertIn(key, first)
        self.assertNotIn("value", first)  # no authorised disclosure was requested
        self.assertIn("zgodność ze wzorcem", first["verification_status_text"])
        self.assertTrue(first["remediation"][0]["text"])
        self.assertIn("Unieważnij", " ".join(item["text"] for item in first["remediation"]))

    def test_heuristic_findings_are_reported_as_unverified_in_polish(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        write(tmp.name, "app.env", f'MY_SECRET_VALUE="{SAMPLE_PASSWORD}"\n')
        code, out, _ = run_cli(["--format", "json", "--lang", "pl", "--fail-on", "medium", tmp.name])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertIn("niezweryfikowane", data["findings"][0]["verification_status_text"])
        self.assertIn("zrotuj", " ".join(item["text"] for item in data["findings"][0]["remediation"]))

    def test_markdown_report_is_masked(self):
        code, out, _ = run_cli(["--format", "markdown", self.tmp.name, "--lang", "en"])
        self.assertEqual(code, 1)
        assert_no_secret(self, out, SAMPLE_OPENAI, "EXAMPLEdbpassword123")
        self.assertIn("# Secret scan report", out)
        self.assertIn("Masked by default", out)

    def test_sarif_report_shape_and_masking(self):
        code, out, _ = run_cli(["--format", "sarif", self.tmp.name])
        self.assertEqual(code, 1)
        assert_no_secret(self, out, SAMPLE_OPENAI)
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertTrue(run["properties"]["maskedOnly"])
        self.assertTrue(run["results"])
        self.assertIn("region", run["results"][0]["locations"][0]["physicalLocation"])

    def test_out_file_is_masked_and_summary_goes_to_stderr(self):
        target = os.path.join(self.tmp.name, "report.md")
        code, out, err = run_cli(["--format", "markdown", "--out", target, self.tmp.name])
        self.assertEqual(code, 1)
        with open(target, encoding="utf-8") as fh:
            payload = fh.read()
        assert_no_secret(self, payload, SAMPLE_OPENAI)
        self.assertIn("report written", err)
        self.assertEqual(out, "")

    def test_third_party_findings_are_flagged(self):
        code, out, _ = run_cli(["--format", "json", "--ownership", "third_party", self.tmp.name])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["findings"][0]["ownership"], "third_party")
        actions = [item["action"] for item in data["findings"][0]["remediation"]]
        self.assertIn("report_to_owner", actions)
        assert_no_secret(self, out, SAMPLE_OPENAI)

    def test_unknown_ownership_is_marked_unverified(self):
        code, out, _ = run_cli(["--format", "json", self.tmp.name])
        data = json.loads(out)
        self.assertEqual(data["findings"][0]["ownership"], "unknown")
        actions = [item["action"] for item in data["findings"][0]["remediation"]]
        self.assertIn("verify_ownership", actions)


class TestSourcesAndCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_stdin_scan(self):
        saved = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(f'TOKEN="{SAMPLE_GITHUB}"'.encode()), encoding="utf-8")
        try:
            code, out, _ = run_cli(["--stdin", "--format", "json"])
        finally:
            sys.stdin = saved
        self.assertEqual(code, 1)
        assert_no_secret(self, out, SAMPLE_GITHUB)
        self.assertEqual(json.loads(out)["findings"][0]["source"]["path"], "<stdin>")

    def test_clean_run_exits_zero(self):
        write(self.tmp.name, "ok.py", "print('hello')\n")
        code, out, _ = run_cli([self.tmp.name])
        self.assertEqual(code, 0)
        self.assertIn("No potential secrets detected", out)

    def test_fail_on_threshold(self):
        write(self.tmp.name, "app.env", f'DB_PASSWORD="{SAMPLE_PASSWORD}"\n')
        self.assertEqual(run_cli([self.tmp.name])[0], 0)                        # medium < high
        self.assertEqual(run_cli([self.tmp.name, "--fail-on", "medium"])[0], 1)
        self.assertEqual(run_cli([self.tmp.name, "--fail-on", "none"])[0], 0)

    def test_binary_and_oversized_files_are_skipped(self):
        with open(os.path.join(self.tmp.name, "blob.bin"), "wb") as fh:
            fh.write(b"\x00\x01" + SAMPLE_OPENAI.encode())
        write(self.tmp.name, "big.env", f"TOKEN={SAMPLE_GITHUB}\n" + "x" * 5000)
        code, out, _ = run_cli([self.tmp.name, "--format", "json", "--max-file-size", "1000"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        skipped = " ".join(data["scan"]["skipped"])
        self.assertIn("blob.bin", skipped)
        self.assertIn("big.env", skipped)
        assert_no_secret(self, out, SAMPLE_GITHUB)

    def test_secretsignore_honours_negations(self):
        write(self.tmp.name, "keep.env", f"TOKEN={SAMPLE_GITHUB}\n")
        write(self.tmp.name, "fixtures/mock.env", f"TOKEN={SAMPLE_GITHUB}\n")
        write(self.tmp.name, ".secretsignore", "*.env\n!keep.env\n")
        code, out, _ = run_cli([self.tmp.name, "--format", "json"])
        data = json.loads(out)
        paths = [f["source"]["path"] for f in data["findings"]]
        self.assertTrue(any(p.endswith("keep.env") for p in paths))
        self.assertFalse(any("mock.env" in p for p in paths))

    def test_inline_ignore_markers_in_comments(self):
        write(
            self.tmp.name,
            "docs.md",
            "# alh-secrets: ignore-file\n"
            f"api_key = {SAMPLE_OPENAI}\n",
        )
        write(
            self.tmp.name,
            "single.md",
            f"key = {SAMPLE_OPENAI}  # alh-secrets: ignore-line\n"
            f"# alh-secrets: ignore-next-line\nkey2 = {SAMPLE_GITHUB}\n",
        )
        code, out, _ = run_cli([self.tmp.name, "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["summary"]["total"], 0)

    def test_marker_inside_a_string_literal_does_not_silence_a_file(self):
        """A file that merely mentions the marker is still scanned."""
        write(
            self.tmp.name,
            "tool.py",
            'MARKER = "alh-secrets: ignore-file"\n'
            f'API_KEY = "{SAMPLE_OPENAI}"\n',
        )
        code, out, _ = run_cli([self.tmp.name, "--format", "json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["summary"]["total"], 1)

    def test_git_staged_scan_respects_ignore_files(self):
        """The index is filtered by the same .secretsignore as the working tree."""
        write(self.tmp.name, ".secretsignore", "fixtures/*\n")
        staged = [
            ("fixtures/leak.env", f'TOKEN="{SAMPLE_GITHUB}"'.encode()),
            ("app.env", f'TOKEN="{SAMPLE_OPENAI}"'.encode()),
        ]
        with unittest.mock.patch.object(ms, "staged_sources", return_value=staged):
            code, out, _ = run_cli(
                ["--git-staged", "--format", "json", "--root", self.tmp.name]
            )
        self.assertEqual(code, 1)
        data = json.loads(out)
        paths = [f["source"]["path"] for f in data["findings"]]
        self.assertEqual(paths, ["app.env"])
        self.assertIn("fixtures/leak.env (ignored)", " ".join(data["scan"]["skipped"]))
        assert_no_secret(self, out, SAMPLE_GITHUB)

    def test_scan_does_not_write_without_out(self):
        write(self.tmp.name, "app.env", f"TOKEN={SAMPLE_GITHUB}\n")
        before = sorted(os.listdir(self.tmp.name))
        run_cli([self.tmp.name])
        self.assertEqual(before, sorted(os.listdir(self.tmp.name)))

    def test_list_rules_contains_the_documented_rule_ids(self):
        code, out, _ = run_cli(["--list-rules"])
        self.assertEqual(code, 0)
        for rule_id in ("openai_api_key", "aws_access_key_id", "github_token", "jwt",
                        "otp_or_recovery_code", "private_key_pem", "credential_assignment"):
            self.assertIn(rule_id, out)

    def test_module_makes_no_network_calls(self):
        """Policy 3 / 8: no validation, no transmission - enforced by construction."""
        with open(os.path.join(os.path.dirname(HERE), "mask_secrets.py"), encoding="utf-8") as fh:
            source = fh.read()
        for forbidden in ("import socket", "import requests", "import urllib",
                          "urlopen(", "https://api.", "curl "):
            self.assertNotIn(forbidden, source)


class TestThirdPartySafeguards(unittest.TestCase):
    """Policy 3 - never use, never test, never expand access."""

    def test_third_party_finding_has_no_write_or_use_advice(self):
        findings = ms.scan_text(f"token={SAMPLE_GITHUB}", "someone-elses.env",
                                ownership="third_party")
        actions = findings[0].remediation
        self.assertEqual(actions[0], "report_to_owner")
        self.assertNotIn("purge_from_history", actions)

    def test_ownership_user_is_recorded_in_report(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = write(tmp.name, "mine.env", f"TOKEN={SAMPLE_GITHUB}\n")
        code, out, _ = run_cli([
            "--format", "json", "--ownership", "user",
            "--confirm-ownership", "I own this repository", path,
        ])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["findings"][0]["ownership"], "user")
        self.assertEqual(data["scan"]["ownership"], "user")


if __name__ == "__main__":
    unittest.main(verbosity=2)
