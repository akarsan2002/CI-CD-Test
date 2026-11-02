"""Scanner 2: source code (imports, endpoints, model names, hardcoded keys).

LESSON 6: Free text is messy, so this scanner uses regex, which is fast and
works across many languages but can be wrong. We manage that with a
`confidence` score: an import (0.9) is stronger evidence than a model-name
string (0.6), because "gpt-4" could appear in a comment, test, or docs.

LESSON 7 (false positives): we skip comment lines for imports/endpoints/models
so commented-out code doesn't create findings. We do NOT skip comments for
keys, because a secret pasted in a comment is still a leaked secret.
"""
import re
from pathlib import Path

from ..base import BaseScanner, read_text_safe
from ..detect import find_endpoints, find_keys, find_models, mask, parse_n8n_workflow
from ..models import AIComponent
from ..signatures import IMPORT_ALIASES, lookup_package

PY_SUFFIXES = {".py"}
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
OTHER_TEXT = {".java", ".go", ".rs", ".rb", ".env", ".yaml", ".yml", ".toml",
              ".json", ".ini", ".cfg", ".sh"}

PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))")
JS_IMPORT = re.compile(r"""(?:from\s+|require\(\s*|import\s+)['"]([^'"]+)['"]""")
COMMENT_PREFIXES = ("#", "//", "/*", "*")


# LESSON 8: a security tool must never become a secret leak itself. We store
# only a masked preview (see detect.mask), never the full key.


def py_root(module: str) -> str:
    for alias_prefix, pkg in IMPORT_ALIASES.items():
        if module.startswith(alias_prefix):
            return pkg
    return module.split(".")[0]


def js_root(module: str) -> str:
    parts = module.split("/")
    return "/".join(parts[:2]) if module.startswith("@") else parts[0]


class CodeScanner(BaseScanner):
    name = "code"
    description = "AI imports, endpoints, model names and hardcoded keys in source files"

    def supports(self, path: Path) -> bool:
        return (path.suffix in PY_SUFFIXES | JS_SUFFIXES | OTHER_TEXT
                or path.name.startswith(".env"))

    def scan(self, path: Path) -> list[AIComponent]:
        text = read_text_safe(path)
        if text is None:
            return []
        # LESSON 16: two scanners looking at the same file report the same
        # thing twice. A specialised scanner (n8n) knows the file better than
        # this generic one, so we step aside. If the JSON is broken, the n8n
        # scanner can't parse it, so this scanner still scans it as plain text.
        if path.suffix == ".json" and parse_n8n_workflow(text):
            return []
        out: list[AIComponent] = []
        for i, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            out.extend(self._keys(path, i, line))  # keys: check every line
            if stripped.startswith(COMMENT_PREFIXES):
                continue
            out.extend(self._imports(path, i, line))
            out.extend(self._endpoints(path, i, line))
            out.extend(self._models(path, i, line))
        return out

    def _add(self, path, i, name, category, evidence, confidence, flags=None):
        return AIComponent(
            name=name, category=category, source_scanner=self.name,
            file=str(path), line=i, evidence=evidence.strip()[:120],
            confidence=confidence, flags=flags or [],
        )

    def _imports(self, path, i, line):
        found = []
        if path.suffix in PY_SUFFIXES:
            m = PY_IMPORT.match(line)
            modules = [g for g in (m.groups() if m else ()) if g]
            roots = [py_root(mod) for mod in modules]
        elif path.suffix in JS_SUFFIXES:
            roots = [js_root(m) for m in JS_IMPORT.findall(line)]
        else:
            return found
        for root in roots:
            info = lookup_package(root)
            if info:
                found.append(self._add(path, i, info[0], info[1], line, 0.9))
        return found

    def _endpoints(self, path, i, line):
        return [self._add(path, i, name, "endpoint", line, 0.8)
                for _host, name in find_endpoints(line)]

    def _models(self, path, i, line):
        return [self._add(path, i, model, "model_reference", line, 0.6)
                for model, _vendor in find_models(line)]

    def _keys(self, path, i, line):
        return [self._add(path, i, f"{provider} API key", "api_key",
                          f"key {mask(secret)}", 0.9, ["hardcoded_api_key"])
                for provider, secret in find_keys(line)]
