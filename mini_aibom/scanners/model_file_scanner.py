"""Scanner 3: model weight files (.gguf, .safetensors, .pt ...).

LESSON 9: Not every scanner reads content. Here the filename alone is the
evidence, and reading a multi-GB file would be wasteful. Also note the
security angle: pickle-based formats (.pt, .pth, .ckpt) can run arbitrary
code when loaded, so they get a risk flag. safetensors/gguf do not.
"""
from pathlib import Path

from ..base import BaseScanner
from ..models import AIComponent
from ..signatures import MODEL_FILE_EXTENSIONS


class ModelFileScanner(BaseScanner):
    name = "model_file"
    description = "Model weight files on disk"

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in MODEL_FILE_EXTENSIONS

    def scan(self, path: Path) -> list[AIComponent]:
        ext = path.suffix.lower()
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        flags = ["pickle_format"] if MODEL_FILE_EXTENSIONS[ext] else []
        return [AIComponent(
            name=path.name, category="model_file", source_scanner=self.name,
            file=str(path), line=None,
            evidence=f"{ext} file, {size:,} bytes", confidence=1.0, flags=flags,
        )]
