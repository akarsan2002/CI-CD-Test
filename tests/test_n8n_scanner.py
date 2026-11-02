"""Tests for the n8n scanner. Most use a REAL n8n export (workflow_ai.json).
Tests using the *_HANDWRITTEN fixture rely on formats NOT yet confirmed by a real export."""
import unittest
from pathlib import Path

from mini_aibom.engine import scan_path
from mini_aibom.scanners.n8n_scanner import N8NScanner

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "n8n"
FAKE_KEY = "sk-FAKEFAKEFAKEFAKEFAKEFAKE1234"


def run(name):
    return N8NScanner().scan(FIX / name)


class RealExportTests(unittest.TestCase):
    def setUp(self):
        self.f = run("workflow_ai.json")

    def test_ai_node_found_by_type(self):
        nodes = [c for c in self.f if c.category == "llm_provider"]
        self.assertEqual([c.name for c in nodes], ["OpenAI"])
        self.assertIn("Message a model", nodes[0].evidence)
        self.assertIsNotNone(nodes[0].line)

    def test_key_found_in_http_node_not_ai_node(self):
        keys = [c for c in self.f if c.category == "api_key"]
        self.assertEqual(len(keys), 1)
        self.assertIn('node "HTTP Request"', keys[0].evidence)
        self.assertIn("headerParameters", keys[0].evidence)  # the exact JSON path
        self.assertIn("hardcoded_api_key", keys[0].flags)

    def test_full_secret_never_stored_anywhere(self):
        for c in self.f:
            self.assertNotIn(FAKE_KEY, str(c.to_dict()))

    def test_endpoint_found(self):
        eps = [c for c in self.f if c.category == "endpoint"]
        self.assertEqual([c.name for c in eps], ["OpenAI"])

    def test_model_hidden_inside_json_string_found(self):
        models = [c.name for c in self.f if c.category == "model_reference"]
        self.assertEqual(models, ["gpt-4o"])

    def test_non_ai_node_ignored(self):
        self.assertFalse(any("Execute workflow" in c.evidence and c.category == "llm_provider"
                             for c in self.f))

    def test_no_duplicate_with_code_scanner(self):
        findings = scan_path(FIX)
        keys = [c for c in findings
                if c.file.endswith("workflow_ai.json") and c.category == "api_key"]
        self.assertEqual(len(keys), 1)  # code scanner steps aside for n8n files


class EdgeCaseTests(unittest.TestCase):
    def test_clean_workflow_finds_nothing(self):
        self.assertEqual(run("workflow_clean.json"), [])

    def test_broken_json_does_not_crash_n8n_scanner(self):
        self.assertEqual(run("workflow_broken.json"), [])

    def test_broken_json_falls_back_to_generic_scan(self):
        findings = scan_path(FIX)
        keys = [c for c in findings
                if c.file.endswith("workflow_broken.json") and c.category == "api_key"]
        self.assertEqual(len(keys), 1)  # still caught as plain text

    def test_non_workflow_json_ignored(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "data.json"
            p.write_text('{"nodes": [1, 2], "connections": "x"}')
            self.assertEqual(N8NScanner().scan(p), [])


class HandwrittenFixtureTests(unittest.TestCase):
    """Format NOT verified against a real export. Update when you have one."""

    def setUp(self):
        self.f = run("workflow_credentials_HANDWRITTEN.json")

    def test_credential_reference_is_not_a_secret(self):
        self.assertEqual([c for c in self.f if c.category == "api_key"], [])
        anth = [c for c in self.f if c.name == "Anthropic"][0]
        self.assertIn("credential reference: anthropicApi", anth.evidence)

    def test_known_and_guessed_nodes(self):
        by_cat = {c.category for c in self.f}
        self.assertIn("llm_provider", by_cat)      # lmChatAnthropic (table)
        self.assertIn("agent_framework", by_cat)   # agent (table)
        guessed = [c for c in self.f if c.category == "ai_node"]
        self.assertEqual(len(guessed), 1)
        self.assertLess(guessed[0].confidence, 1.0)  # guesses get lower confidence

    def test_mcp_exposed_flag(self):
        flagged = [c for c in self.f if "mcp_exposed" in c.flags]
        self.assertEqual(len(flagged), 1)


if __name__ == "__main__":
    unittest.main()
