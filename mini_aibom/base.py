"""Scanner base class with AUTOMATIC registration.

LESSON 2: Trusera's trick (and ours): any class that inherits BaseScanner and
sets a `name` registers itself the moment Python reads its file. Adding a new
scanner = write one file, import it once. No central list to edit.

How it works: Python calls __init_subclass__ every time a subclass is defined.
We use that hook to append the new class to a registry list.

Each scanner answers two questions:
  supports(path) -> "is this file something I understand?"  (cheap check)
  scan(path)     -> "what AI components are in it?"          (the real work)
Splitting these keeps scanning fast: most files are skipped by supports().
"""
from abc import ABC, abstractmethod
from pathlib import Path

from .models import AIComponent

_registry: list[type["BaseScanner"]] = []

MAX_TEXT_BYTES = 1_000_000  # don't read files bigger than 1 MB as text


class BaseScanner(ABC):
    name: str = ""
    description: str = ""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.name:  # abstract/intermediate classes without a name are skipped
            _registry.append(cls)

    @abstractmethod
    def supports(self, path: Path) -> bool: ...

    @abstractmethod
    def scan(self, path: Path) -> list[AIComponent]: ...


def get_scanners() -> list[BaseScanner]:
    return [cls() for cls in _registry]


def read_text_safe(path: Path) -> str | None:
    """Read a file as text, or return None if it is too big or unreadable.

    LESSON 3: Real repos contain huge files, binaries and weird encodings.
    A scanner that crashes or hangs on them is useless. Always guard reads.
    (Model files are legitimately huge, which is why the model-file scanner
    never reads contents, it only looks at the filename and size.)
    """
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def find_line(text: str, needle: str) -> int | None:
    """Return the 1-based line number of the first occurrence of needle."""
    idx = text.find(needle)
    return None if idx == -1 else text.count("\n", 0, idx) + 1
