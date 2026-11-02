"""Scanner 6: network logs (DNS / proxy), the "what ACTUALLY happened" scanner.

How it differs from the other scanners (read this first):
  - Code, n8n and config scanners read INTENT (what software is set up to do).
  - This one reads BEHAVIOR (what the network really saw).
  - It cannot see keys, prompts or models (traffic is encrypted). It sees
    only hostnames, who asked, and how often.
  - It is the raw material for shadow-AI discovery. Note it does not say
    "shadow" by itself: that needs an approved list to compare against.

Design choices:
  - Format-tolerant: instead of one parser per log format, we pull every
    hostname-looking token out of each line, and take the first IPv4 address as
    the "source". Works for dnsmasq-style and Squid-style lines. LIMITATION: in
    some formats the first IP is the destination, not the client.
  - LESSON 18: stream the file line by line. Logs are huge. read_text_safe()
    would skip anything over 1 MB, which would skip nearly every real log.
  - Aggregate: 10,000 identical DNS lookups become ONE finding with a count,
    not 10,000 findings.
"""
import re
from pathlib import Path

from ..base import BaseScanner
from ..detect import match_ai_host
from ..models import AIComponent

HOST_TOKEN = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")   # dotted names, port excluded
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAX_LINES = 2_000_000  # safety valve for gigantic logs


class LogScanner(BaseScanner):
    name = "log"
    description = "AI service traffic seen in DNS/proxy logs (.log files)"

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() == ".log"

    def scan(self, path: Path) -> list[AIComponent]:
        # (source, listed_host) -> [vendor, count, first_line_number]
        seen: dict[tuple[str, str], list] = {}
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for n, line in enumerate(fh, start=1):
                    if n > MAX_LINES:
                        break
                    self._line(line, n, seen)
        except OSError:
            return []

        return components_from_seen(seen, str(path))

    @staticmethod
    def _line(line, n, seen, default_source="unknown", max_keys=None):
        return observe_line(line, n, seen, default_source, max_keys)


def observe_line(line: str, n: int, seen: dict,
                 default_source: str = "unknown", max_keys: int | None = None) -> list:
    """Check one log line; update `seen`; return [(source, host, vendor)] for NEW keys.

    Shared by the file scanner AND the live syslog receiver (collectors/), so the
    matching logic exists once. `default_source` is used when the line itself
    contains no IP (the syslog receiver passes the sender's address).

    LESSON 19: `max_keys` protects memory. The source comes from the message TEXT,
    so anyone able to send lines could invent endless fake sources and grow `seen`
    forever. A live collector must cap anything that grows from untrusted input.
    """
    low = line.lower()
    hits = set()
    for token in HOST_TOKEN.findall(low):
        m = match_ai_host(token)
        if m:
            hits.add(m)  # one hit per listed host per line, even if repeated
    if not hits:
        return []
    ip = IPV4.search(low)
    source = ip.group(0) if ip else default_source
    new = []
    for host, vendor in hits:
        key = (source, host)
        if key in seen:
            seen[key][1] += 1
        elif max_keys is None or len(seen) < max_keys:
            seen[key] = [vendor, 1, n]
            new.append((source, host, vendor))
    return new


def components_from_seen(seen: dict, file_label: str) -> list[AIComponent]:
    return [
        AIComponent(
            name=vendor, category="network_activity", source_scanner="log",
            file=file_label, line=first_line,
            evidence=f"{count} hit(s) from {source} to {host}",
            confidence=0.8, flags=[],
        )
        for (source, host), (vendor, count, first_line) in seen.items()
    ]
