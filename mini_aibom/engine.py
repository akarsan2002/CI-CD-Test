"""The engine: walk files, ask each scanner, clean up, score, sort.

LESSON 12: The engine knows nothing about AI or any specific scanner. It
just loops. Notice the try/except: one malformed file must never crash a
scan of 50,000 files.
"""
import os
import sys
from pathlib import Path

from .base import get_scanners
from .models import AIComponent
from .risk import score_component
from . import scanners  # noqa: F401  (import triggers scanner registration)

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
             "dist", "build", ".mypy_cache", ".pytest_cache"}


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):  # does not follow symlinks
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            yield Path(dirpath) / name


def scan_path(root: Path) -> list[AIComponent]:
    root = root.resolve()
    base = root if root.is_dir() else root.parent
    active = get_scanners()
    findings: list[AIComponent] = []

    for path in iter_files(root):
        for scanner in active:
            try:
                if not scanner.supports(path):
                    continue
                for comp in scanner.scan(path):
                    comp.file = str(path.relative_to(base))
                    findings.append(comp)
            except Exception as exc:  # keep scanning no matter what
                print(f"warning: {scanner.name} failed on {path}: {exc}", file=sys.stderr)

    # De-duplicate: the same finding reported twice adds noise, not value.
    seen, unique = set(), []
    for c in findings:
        key = (c.category, c.name, c.file, c.line, c.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(score_component(c))

    unique.sort(key=lambda c: (-c.risk_score, c.file, c.line or 0))
    return unique
