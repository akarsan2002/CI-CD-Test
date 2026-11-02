import tempfile
import unittest
from pathlib import Path

from mini_aibom.base import get_scanners
from mini_aibom.engine import scan_path
from mini_aibom import scanners  # noqa: F401

FAKE_KEY = "sk-FAKEFAKEFAKEFAKEFAKEFAKE1234"


def scan_files(files: dict[str, str]):
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, content in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return scan_path(root)


class ScannerTests(unittest.TestCase):
    def test_all_scanners_registered(self):
        names = {s.name for s in get_scanners()}
        self.assertEqual(names, {"dependency", "code", "model_file", "mcp_config", "n8n", "log"})

    def test_requirements_detects_ai_and_ignores_others(self):
        f = scan_files({"requirements.txt": "flask==3.0\nopenai==1.0\nlangchain\n"})
        names = {c.name for c in f}
        self.assertEqual(names, {"OpenAI", "LangChain"})

    def test_unpinned_flag(self):
        f = scan_files({"requirements.txt": "openai==1.0\nlangchain\n"})
        by_name = {c.name: c for c in f}
        self.assertNotIn("unpinned_version", by_name["OpenAI"].flags)
        self.assertIn("unpinned_version", by_name["LangChain"].flags)

    def test_commented_import_ignored(self):
        f = scan_files({"a.py": "# import openai\n"})
        self.assertEqual(f, [])

    def test_real_import_found(self):
        f = scan_files({"a.py": "from openai import OpenAI\n"})
        self.assertEqual([c.name for c in f], ["OpenAI"])

    def test_key_is_masked_and_flagged(self):
        f = scan_files({"a.py": f'k = "{FAKE_KEY}"\n'})
        keys = [c for c in f if c.category == "api_key"]
        self.assertEqual(len(keys), 1)
        self.assertNotIn(FAKE_KEY, keys[0].evidence)  # full secret never stored
        self.assertIn("hardcoded_api_key", keys[0].flags)

    def test_anthropic_key_not_double_reported_as_openai(self):
        f = scan_files({"a.py": 'k = "sk-ant-' + "A" * 30 + '"\n'})
        keys = [c.name for c in f if c.category == "api_key"]
        self.assertEqual(keys, ["Anthropic API key"])

    def test_pickle_model_flagged_safetensors_not(self):
        f = scan_files({"m.pt": "x", "m.safetensors": "x"})
        by_file = {c.file: c for c in f}
        self.assertIn("pickle_format", by_file["m.pt"].flags)
        self.assertNotIn("pickle_format", by_file["m.safetensors"].flags)

    def test_mcp_flags(self):
        cfg = ('{"mcpServers": {"a": {"command": "npx", "args": ["-y", "pkg"]},'
               '"b": {"url": "http://evil.example.com/x", "env": {"MY_TOKEN": "abc"}}}}')
        f = scan_files({".mcp.json": cfg})
        flags = {c.name: set(c.flags) for c in f}
        self.assertIn("unpinned_package", flags["mcp:a"])
        self.assertTrue({"remote_server", "insecure_transport", "inline_secret"} <= flags["mcp:b"])

    def test_node_modules_skipped(self):
        f = scan_files({"node_modules/x/a.py": "import openai\n"})
        self.assertEqual(f, [])

    def test_broken_json_does_not_crash(self):
        f = scan_files({"package.json": "{ not json", ".mcp.json": "also bad"})
        self.assertEqual(f, [])


if __name__ == "__main__":
    unittest.main()
