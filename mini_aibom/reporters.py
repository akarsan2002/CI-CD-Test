"""Reporters: turn findings into output. Scanners never format anything.

LESSON 13: Separating "finding" from "presentation" is why one scan can
produce a terminal table for you, JSON for scripts and CycloneDX for tools.
CycloneDX is an industry-standard BOM format that other security tools read.
"""
import hashlib
import json
from collections import Counter
from pathlib import Path

from .models import AIComponent

CYCLONEDX_TYPES = {
    "llm_provider": "library", "agent_framework": "framework",
    "vector_db": "library", "model_reference": "machine-learning-model",
    "model_file": "machine-learning-model", "mcp_server": "application",
    "endpoint": "data", "ai_node": "application", "network_activity": "data",
}


def table(findings: list[AIComponent]) -> str:
    if not findings:
        return "No AI components found."
    header = f"{'SEV':<9}{'SCORE':<6}{'CATEGORY':<17}{'NAME':<26}{'LOCATION':<36}FLAGS"
    lines = [header, "-" * len(header)]
    for c in findings:
        loc = f"{c.file}:{c.line}" if c.line else c.file
        if len(loc) > 35:
            loc = "..." + loc[-32:]  # keep the END, the line number matters most
        lines.append(f"{c.severity:<9}{c.risk_score:<6}{c.category:<17}"
                     f"{c.name[:25]:<26}{loc:<36}{','.join(c.flags)}")
    counts = Counter(c.severity for c in findings)
    summary = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts[s])
    lines += ["", f"{len(findings)} findings: {summary}"]
    return "\n".join(lines)


def as_json(findings: list[AIComponent]) -> str:
    return json.dumps([c.to_dict() for c in findings], indent=2)


def cyclonedx(findings: list[AIComponent]) -> str:
    """Minimal CycloneDX 1.6 document.

    Simplification: real CycloneDX puts services under a separate `services`
    key, and secrets are findings, not components, so we leave keys out of
    the BOM entirely (a BOM should be safe to share; secrets must not be in it).
    """
    components = []
    for c in findings:
        if c.category == "api_key":
            continue
        components.append({
            "type": CYCLONEDX_TYPES.get(c.category, "library"),
            "name": c.name,
            "properties": [
                {"name": "mini-aibom:category", "value": c.category},
                {"name": "mini-aibom:location", "value": f"{c.file}:{c.line}" if c.line else c.file},
                {"name": "mini-aibom:risk-score", "value": str(c.risk_score)},
                {"name": "mini-aibom:severity", "value": c.severity},
                {"name": "mini-aibom:confidence", "value": str(c.confidence)},
            ] + [{"name": "mini-aibom:flag", "value": f} for f in c.flags],
        })
    return json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                       "version": 1, "components": components}, indent=2)


SARIF_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
RULE_TEXT = {
    "api_key": "Hardcoded AI API key", "llm_provider": "LLM provider in use",
    "agent_framework": "AI agent framework in use", "model_reference": "AI model referenced",
    "endpoint": "AI service endpoint", "model_file": "Model weight file",
    "mcp_server": "MCP server or exposure", "vector_db": "Vector database in use",
    "ai_node": "AI workflow node", "network_activity": "AI service traffic observed",
}


def sarif(findings: list[AIComponent]) -> str:
    """SARIF 2.1.0: the standard format CI systems (GitHub code scanning etc.) read.

    LESSON 21: CI tools don't want our table, they want a standard. Also note
    the fingerprint: GitHub uses it to tell "same finding as last run" from
    "new finding". Line numbers shift, so we hash stable fields instead, and add
    an occurrence counter so two identical imports in one file stay distinct.
    """
    rule_ids = sorted({c.category for c in findings})
    rules = [{"id": f"aibom/{r}", "name": r,
              "shortDescription": {"text": RULE_TEXT.get(r, r)}} for r in rule_ids]
    seen_count: Counter = Counter()
    results = []
    for c in findings:
        base = hashlib.sha256("|".join([c.category, c.name, c.file, c.evidence]).encode()).hexdigest()
        seen_count[base] += 1
        flags = f" [flags: {', '.join(c.flags)}]" if c.flags else ""
        results.append({
            "ruleId": f"aibom/{c.category}",
            "level": SARIF_LEVELS.get(c.severity, "note"),
            "message": {"text": f"{c.name}: {c.evidence}{flags}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": Path(c.file).as_posix()},
                "region": {"startLine": c.line or 1},
            }}],
            "partialFingerprints": {"aibomFingerprint/v1": f"{base}:{seen_count[base]}"},
            "properties": {"riskScore": c.risk_score, "confidence": c.confidence},
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "mini-aibom", "version": "0.1.0", "rules": rules}},
                  "results": results}],
    }
    return json.dumps(doc, indent=2)


REPORTERS = {"table": table, "json": as_json, "cyclonedx": cyclonedx, "sarif": sarif}
