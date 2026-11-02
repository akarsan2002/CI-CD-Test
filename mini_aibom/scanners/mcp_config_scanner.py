"""Scanner 4: MCP server configuration files.

LESSON 10: This is where AI-BOM scanning becomes SECURITY scanning. We don't
just list MCP servers, we judge how they're configured:
  - unpinned_package: `npx some-server` with no version runs whatever is
    latest at launch time, a supply-chain risk.
  - inline_secret: a token written straight into the config file.
  - remote_server / insecure_transport: data leaves the machine (and over
    plain http it can be read or altered in transit).
This is the kind of logic where a team can add value no generic scanner has.
"""
import json
from pathlib import Path

from ..base import BaseScanner, read_text_safe, find_line
from ..models import AIComponent

CONFIG_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}
SECRET_WORDS = ("KEY", "TOKEN", "SECRET", "PASSWORD")
LAUNCHERS = {"npx", "uvx", "bunx"}


class MCPConfigScanner(BaseScanner):
    name = "mcp_config"
    description = "MCP servers and how they are configured"

    def supports(self, path: Path) -> bool:
        return path.name in CONFIG_NAMES

    def scan(self, path: Path) -> list[AIComponent]:
        text = read_text_safe(path)
        if text is None:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        servers = data.get("mcpServers") or data.get("servers") or {}
        out = []
        for server_name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            flags = self._flags(cfg)
            command = cfg.get("command") or cfg.get("url", "")
            args = " ".join(map(str, cfg.get("args", [])))
            out.append(AIComponent(
                name=f"mcp:{server_name}", category="mcp_server",
                source_scanner=self.name, file=str(path),
                line=find_line(text, f'"{server_name}"'),
                evidence=f"{command} {args}".strip()[:120],
                confidence=1.0, flags=flags,
            ))
        return out

    def _flags(self, cfg: dict) -> list[str]:
        flags = []
        url = cfg.get("url", "")
        if url.startswith(("http://", "https://")):
            flags.append("remote_server")
            if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                flags.append("insecure_transport")
        if cfg.get("command") in LAUNCHERS:
            pkg = next((a for a in cfg.get("args", []) if not str(a).startswith("-")), "")
            pkg = str(pkg)
            if pkg and "==" not in pkg and "@" not in pkg[1:]:
                flags.append("unpinned_package")
        for key, value in (cfg.get("env") or {}).items():
            if any(w in key.upper() for w in SECRET_WORDS):
                if value and not str(value).startswith("$"):
                    flags.append("inline_secret")
                    break
        return flags
