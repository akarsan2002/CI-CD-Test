import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from mini_aibom.cli import main
from mini_aibom.engine import scan_path
from mini_aibom.reporters import sarif

FAKE_KEY = "sk-FAKEFAKEFAKEFAKEFAKEFAKE1234"


def run_cli(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(list(argv))
    return code, out.getvalue()


class ExitCodeTests(unittest.TestCase):
    def test_clean_project_passes(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text("print('hi')\n")
            self.assertEqual(run_cli("scan", d, "--fail-on", "low")[0], 0)

    def test_hardcoded_key_fails_the_gate(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text(f'k = "{FAKE_KEY}"\n')
            self.assertEqual(run_cli("scan", d, "--fail-on", "high")[0], 1)

    def test_threshold_is_respected(self):
        with tempfile.TemporaryDirectory() as d:  # only a low-severity import
            (Path(d) / "a.py").write_text("from openai import OpenAI\n")
            self.assertEqual(run_cli("scan", d, "--fail-on", "high")[0], 0)
            self.assertEqual(run_cli("scan", d, "--fail-on", "low")[0], 1)

    def test_missing_path_is_a_tool_error_not_a_finding(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(main(["scan", "/definitely/not/here"]), 2)  # 2 != 1


class OutputFileTests(unittest.TestCase):
    def test_output_flag_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text("from openai import OpenAI\n")
            out = Path(d) / "r.json"
            code, text = run_cli("scan", d, "-f", "json", "-o", str(out))
            self.assertEqual(code, 0)
            self.assertEqual(len(json.loads(out.read_text())), 1)
            self.assertIn("Wrote 1 finding", text)


class SarifTests(unittest.TestCase):
    def make(self, files):
        d = tempfile.TemporaryDirectory()
        for name, content in files.items():
            p = Path(d.name) / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        self.addCleanup(d.cleanup)
        return Path(d.name)

    def test_structure_and_levels(self):
        root = self.make({"a.py": f'from openai import OpenAI\nk = "{FAKE_KEY}"\n'})
        doc = json.loads(sarif(scan_path(root)))
        self.assertEqual(doc["version"], "2.1.0")
        results = doc["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        levels = {r["ruleId"]: r["level"] for r in results}
        self.assertEqual(levels["aibom/api_key"], "error")
        self.assertEqual(levels["aibom/llm_provider"], "note")
        rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {"aibom/api_key", "aibom/llm_provider"})

    def test_secret_never_appears(self):
        root = self.make({"a.py": f'k = "{FAKE_KEY}"\n'})
        self.assertNotIn(FAKE_KEY, sarif(scan_path(root)))

    def test_fingerprints_stable_across_runs_and_unique(self):
        root = self.make({"a.py": "import openai\n\n\nimport openai\n"})  # same text twice
        fp1 = [r["partialFingerprints"]["aibomFingerprint/v1"]
               for r in json.loads(sarif(scan_path(root)))["runs"][0]["results"]]
        fp2 = [r["partialFingerprints"]["aibomFingerprint/v1"]
               for r in json.loads(sarif(scan_path(root)))["runs"][0]["results"]]
        self.assertEqual(fp1, fp2)                 # stable
        self.assertEqual(len(set(fp1)), len(fp1))  # distinct despite identical text

    def test_fingerprint_survives_line_shift(self):
        a = self.make({"a.py": "import openai\n"})
        b = self.make({"a.py": "# new comment\n\n\nimport openai\n"})
        fa = json.loads(sarif(scan_path(a)))["runs"][0]["results"][0]["partialFingerprints"]
        fb = json.loads(sarif(scan_path(b)))["runs"][0]["results"][0]["partialFingerprints"]
        self.assertEqual(fa, fb)

    def test_paths_rebased_to_working_directory(self):
        root = self.make({"sub/app.py": "import openai\n"})
        old = os.getcwd()
        os.chdir(root)  # pretend this is the repo root, like in CI
        try:
            out = Path(root) / "r.sarif"
            run_cli("scan", "sub", "-f", "sarif", "-o", str(out))
            uri = json.loads(out.read_text())["runs"][0]["results"][0]["locations"][0][
                "physicalLocation"]["artifactLocation"]["uri"]
        finally:
            os.chdir(old)
        self.assertEqual(uri, "sub/app.py")  # not just "app.py"

    def test_line_is_at_least_one(self):
        root = self.make({"m.pt": "x"})  # model files have no line number
        r = json.loads(sarif(scan_path(root)))["runs"][0]["results"][0]
        self.assertGreaterEqual(r["locations"][0]["physicalLocation"]["region"]["startLine"], 1)


if __name__ == "__main__":
    unittest.main()
