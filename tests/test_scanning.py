import _isolate  # noqa: F401
import json
import contextlib
import io
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from seckit.detect import detect
from seckit.cli import _show
from seckit.scanning import _finding, _run, normalize_semgrep, normalize_trivy, scan


class ScanningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_detect_manifests_and_framework_dependencies(self):
        (self.root / "package.json").write_text(json.dumps({"dependencies": {"next": "1", "react": "1", "express": "1"}}))
        (self.root / "tsconfig.json").touch()
        (self.root / ".github/workflows").mkdir(parents=True)
        (self.root / ".github/workflows/ci.yml").touch()
        detected = detect(self.root)
        self.assertTrue({"Node.js", "JavaScript", "React", "Next.js", "Express", "TypeScript", "GitHub Actions"}.issubset(detected))

    def test_package_manifest_without_react_does_not_infer_react(self):
        (self.root / "package.json").write_text(json.dumps({"dependencies": {"lodash": "1"}}))
        self.assertNotIn("React", detect(self.root))

    def test_prunes_vendor_trees(self):
        ignored = self.root / "node_modules" / "nested"
        ignored.mkdir(parents=True)
        (ignored / "package.json").write_text(json.dumps({"dependencies": {"react": "1"}}))
        self.assertEqual(detect(self.root), [])

    def test_normalize_semgrep_redacts_snippet_and_secret(self):
        data = {"results": [{"check_id": "rule.x", "path": "src/a.py", "start": {"line": 9},
            "extra": {"message": "unsafe token=verysecret", "lines": "SECRET_SNIPPET", "metadata": {"severity": "ERROR", "confidence": "HIGH"}}}]}
        finding = normalize_semgrep(data, self.root)[0]
        self.assertEqual(finding["severity"], "HIGH")
        self.assertNotIn("verysecret", json.dumps(finding))
        self.assertNotIn("SECRET_SNIPPET", json.dumps(finding))
        self.assertEqual(finding["line"], 9)

    def test_terminal_escapes_untrusted_finding_paths_and_preserves_json_path(self):
        name = "unsafe\x1b[2K\r\n\u202eforged.js"
        data = {"results": [{"check_id": "fixture", "path": name, "start": {"line": 1},
                             "extra": {"message": "fixture", "severity": "ERROR"}}]}
        report = {"findings": normalize_semgrep(data, self.root)}
        terminal = io.StringIO()
        with contextlib.redirect_stdout(terminal):
            _show(report)
        output = terminal.getvalue()
        for control in ("\x1b", "\r", "\u202e"):
            self.assertNotIn(control, output)
        self.assertIn(r"unsafe\x1b[2K\r\n\u202eforged.js", output)
        encoded = io.StringIO()
        with contextlib.redirect_stdout(encoded):
            _show(report, as_json=True)
        self.assertEqual(json.loads(encoded.getvalue())["findings"][0]["file"], name)

    def test_normalize_trivy_vulnerability_has_stable_fields(self):
        data = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{"VulnerabilityID": "CVE-1234", "PkgName": "demo", "Severity": "HIGH", "FixedVersion": "2.0", "Description": "issue"}]}]}
        one = normalize_trivy(data, self.root)[0]
        two = normalize_trivy(data, self.root)[0]
        self.assertEqual(one, two)
        self.assertFalse(one["fix_available"])
        self.assertEqual(one["file"], "requirements.txt")
        self.assertEqual(one["classification"], "confirmed")
        self.assertEqual(one["verification_status"], "unverified")
        self.assertEqual(one["priority"], "P1")

    def test_same_cve_on_distinct_packages_has_distinct_stable_identity(self):
        data = {"Results": [{"Target": "locks/package-lock.json", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2025-1234", "PkgName": "alpha", "InstalledVersion": "1.0", "Severity": "HIGH"},
            {"VulnerabilityID": "CVE-2025-1234", "PkgName": "beta", "InstalledVersion": "2.0", "Severity": "HIGH"},
        ]}]}
        first, second = normalize_trivy(data, self.root)
        self.assertEqual(first["rule_id"], second["rule_id"])
        self.assertNotEqual(first["id"], second["id"])

    def test_relative_nested_finding_path_is_kept_under_scan_root(self):
        data = {"Results": [{"Target": "packages/app/package-lock.json", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2025-1234", "PkgName": "alpha", "Severity": "HIGH"}]}]}
        finding = normalize_trivy(data, self.root)[0]
        self.assertEqual(finding["file"], "packages/app/package-lock.json")

    def test_credential_priority_and_heuristic_classification(self):
        finding = _finding("Semgrep", "secret.token", "Potential secret", "HIGH", "MEDIUM",
                           "src/a.py", 3, "Possible token", "impact", "rotate", False, "verify", self.root, credential=True)
        self.assertEqual(finding["priority"], "P0")
        self.assertEqual(finding["classification"], "heuristic")

    def test_trivy_secret_is_p0_without_returning_matched_value(self):
        data = {"Results": [{"Target": "src/config.py", "Secrets": [{
            "RuleID": "generic-api-key", "Title": "API Key", "Severity": "HIGH",
            "StartLine": 5, "Match": "credential=do-not-leak"}]}]}
        finding = normalize_trivy(data, self.root)[0]
        self.assertEqual(finding["priority"], "P0")
        self.assertNotIn("do-not-leak", json.dumps(finding))

    def test_scan_reports_missing_executables_as_errors(self):
        result = scan(self.root, "not-a-real-trivy", "not-a-real-semgrep")
        self.assertEqual(result["findings"], [])
        self.assertEqual(len(result["errors"]), 2)

    @patch("seckit.scanning.subprocess.run")
    def test_scan_requests_explicit_scanners_pruning_and_local_semgrep_rules(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, stdout='{"Results":[]}', stderr="")
        scan(self.root, "trivy", "semgrep")
        trivy_command, semgrep_command = (call.args[0] for call in run.call_args_list)
        self.assertIn("vuln,misconfig,secret", trivy_command)
        for flag in ("--config", "--ignorefile", "--secret-config"):
            self.assertEqual(trivy_command[trivy_command.index(flag) + 1], "")
        self.assertIn("--skip-dirs", trivy_command)
        self.assertIn("--no-rewrite-rule-ids", semgrep_command)
        self.assertIn("--disable-version-check", semgrep_command)

    @patch("seckit.scanning.subprocess.run")
    def test_scanner_diagnostic_text_is_not_returned(self, run):
        run.return_value = subprocess.CompletedProcess([], 0,
            stdout=json.dumps({"Results": [], "Errors": [{"Message": "secret=do-not-leak"}]}), stderr="")
        result = scan(self.root, "trivy", "semgrep")
        self.assertIn("Trivy reported 1 scan error(s)", result["errors"])
        self.assertNotIn("do-not-leak", json.dumps(result))

    @patch("seckit.scanning.subprocess.run")
    def test_non_object_json_output_is_rejected_without_echoing_output(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, stdout='["sensitive"]', stderr="")
        payload, error = _run(["scanner"], self.root)
        self.assertIsNone(payload)
        self.assertEqual(error, "Scanner returned JSON with an unexpected top-level type")


    def test_credentialed_cors_is_high_priority_without_being_a_token_exposure(self):
        finding = _finding("Semgrep", "seckit.javascript.cors-reflect-credentials", "CORS credentials", "HIGH", "HIGH",
                           "src/app.js", 2, "Review CORS", "impact", "restrict origins", False, "verify", self.root)
        self.assertEqual(finding["priority"], "P1")

    @patch("seckit.scanning.subprocess.run")
    def test_docker_secret_duplicate_retains_both_rules_as_one_exposure(self, run):
        trivy = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [
            {"ID": "DS-0031", "Title": "Secret in ENV", "Severity": "CRITICAL", "CauseMetadata": {"StartLine": 2}}],
            "Secrets": [{"RuleID": "github-pat", "Title": "GitHub token", "Severity": "HIGH", "StartLine": 2}]}]}
        run.side_effect = [subprocess.CompletedProcess([], 0, stdout=json.dumps(trivy), stderr=""),
                           subprocess.CompletedProcess([], 0, stdout='{"results":[]}', stderr="")]
        report = scan(self.root, "trivy", "semgrep")
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule_id"], "github-pat")
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["related_rules"], [{"scanner": "Trivy", "rule_id": "DS-0031"}])


if __name__ == "__main__":
    unittest.main()
