"""Shared detection helpers, used by more than one scanner.

LESSON 14: When the n8n scanner needed "find keys, endpoints and model names
inside a string", we already had that logic buried inside CodeScanner.
Copy-pasting it would mean two places to fix every bug. So it moved here.
Rule of thumb: the second time you need something, extract it.
"""
import json
import re

from .signatures import ENDPOINTS, KEY_PATTERNS, MODEL_PATTERNS


def mask(secret: str) -> str:
    """A security tool must never become a secret leak itself."""
    return secret[:6] + "..." + secret[-2:]


# LESSON 15 (lookalike domains): `"api.openai.com" in text` is WRONG because
# it also matches "api.openai.com.evil.example". We require that the host is
# not glued to other hostname characters on either side:
#   (?<![\w.\-])   the char before must not be a word char, dot or hyphen
#   (?![\w\-]|\.[\w\-])  after it: no word char/hyphen, and no ".more-domain"
# A sentence-ending period ("... api.openai.com. Next") is still allowed.
_ENDPOINT_PATTERNS = [
    (re.compile(r"(?<![\w.\-])" + re.escape(host) + r"(?![\w\-]|\.[\w\-])"), host, name)
    for host, name in ENDPOINTS.items()
]


def find_endpoints(text: str) -> list[tuple[str, str]]:
    """Return [(host, vendor_name)] for AI hosts present in text."""
    return [(host, name) for pat, host, name in _ENDPOINT_PATTERNS if pat.search(text)]


def find_models(text: str) -> list[tuple[str, str]]:
    """Return [(model_string, vendor)] for model names present in text."""
    return [(m.group(1), vendor)
            for pattern, vendor in MODEL_PATTERNS for m in pattern.finditer(text)]


def find_keys(text: str) -> list[tuple[str, str]]:
    """Return [(provider, full_secret)]. Callers must mask before storing!"""
    found, taken = [], []  # taken = character spans already claimed
    for provider, pattern in KEY_PATTERNS:
        for m in pattern.finditer(text):
            if any(m.start() < e and m.end() > s for s, e in taken):
                continue  # a more specific pattern already claimed this text
            taken.append((m.start(), m.end()))
            found.append((provider, m.group(0)))
    return found


def parse_n8n_workflow(text: str) -> dict | None:
    """Return the parsed workflow if `text` is an n8n workflow export, else None.

    Identified by STRUCTURE (a "nodes" list whose items have a "type", plus
    "connections"), not by filename, because exports are named anything.
    """
    if '"nodes"' not in text or '"connections"' not in text:  # cheap pre-check
        return None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return None
    nodes = doc.get("nodes") if isinstance(doc, dict) else None
    if not isinstance(nodes, list) or not nodes:
        return None
    if not all(isinstance(n, dict) and "type" in n for n in nodes):
        return None
    return doc


# ---- hostname matching for logs ---------------------------------------------
# LESSON 17: for LOGS we PARSE the hostname out first, then compare it as a
# whole. We never search the raw line for a substring. We try each suffix of the
# hostname ("a.b.c" -> "a.b.c", "b.c", "c") against a dictionary of AI hosts:
#   api.openai.com             -> match
#   eu.api.openai.com          -> match (a subdomain of a listed host)
#   api.openai.com.evil.example-> no suffix is a listed host, so no match
#   myapi.openai.com           -> suffixes are "myapi.openai.com", "openai.com": no match
_AI_HOSTS = {h: n for h, n in ENDPOINTS.items() if ":" not in h}  # skip host:port entries


def match_ai_host(hostname: str) -> tuple[str, str] | None:
    """Return (listed_host, vendor_name) if hostname is, or is under, an AI host."""
    labels = hostname.lower().rstrip(".").split(".")
    for i in range(len(labels) - 1):  # never test a bare TLD like "com"
        candidate = ".".join(labels[i:])
        if candidate in _AI_HOSTS:
            return candidate, _AI_HOSTS[candidate]
    return None
