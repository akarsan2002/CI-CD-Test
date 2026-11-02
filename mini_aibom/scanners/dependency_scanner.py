"""Scanner 1: dependency files (the easiest and most reliable signal).

LESSON 5: Declared dependencies are structured data, not free text, so we
PARSE them instead of regex-searching. Parsing is more accurate and gives
high confidence. Prefer parsing whenever the format allows it.
"""
import json
import re
import tomllib
from pathlib import Path

from ..base import BaseScanner, read_text_safe, find_line
from ..models import AIComponent
from ..signatures import lookup_package

REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)")


class DependencyScanner(BaseScanner):
    name = "dependency"
    description = "AI SDKs declared in requirements.txt, package.json, pyproject.toml"

    def supports(self, path: Path) -> bool:
        return (
            path.name == "package.json"
            or path.name == "pyproject.toml"
            or (path.name.startswith("requirements") and path.suffix == ".txt")
        )

    def scan(self, path: Path) -> list[AIComponent]:
        text = read_text_safe(path)
        if text is None:
            return []
        if path.name == "package.json":
            return self._package_json(path, text)
        if path.name == "pyproject.toml":
            return self._pyproject(path, text)
        return self._requirements(path, text)

    def _make(self, path, dep, evidence, line, flags=None):
        info = lookup_package(dep)
        if not info:
            return None
        display, category = info
        return AIComponent(
            name=display, category=category, source_scanner=self.name,
            file=str(path), line=line, evidence=evidence,
            confidence=0.95, flags=flags or [],
        )

    def _requirements(self, path, text):
        out = []
        for i, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = REQ_NAME.match(line)
            if not m:
                continue
            flags = [] if "==" in line else ["unpinned_version"]
            comp = self._make(path, m.group(1), line, i, flags)
            if comp:
                out.append(comp)
        return out

    def _package_json(self, path, text):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        out = []
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for dep, version in (data.get(section) or {}).items():
                flags = ["unpinned_version"] if version in ("*", "latest") else []
                comp = self._make(path, dep, f'"{dep}": "{version}"',
                                  find_line(text, f'"{dep}"'), flags)
                if comp:
                    out.append(comp)
        return out

    def _pyproject(self, path, text):
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return []
        specs: list[str] = list(data.get("project", {}).get("dependencies", []))
        for group in data.get("project", {}).get("optional-dependencies", {}).values():
            specs.extend(group)
        specs.extend(data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys())
        out = []
        for spec in specs:
            m = REQ_NAME.match(spec)
            if not m:
                continue
            flags = [] if "==" in spec else ["unpinned_version"]
            comp = self._make(path, m.group(1), spec, find_line(text, m.group(1)), flags)
            if comp:
                out.append(comp)
        return out
