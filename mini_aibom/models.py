"""The ONE data shape every scanner must produce.

LESSON 1: A scanner can look at anything (a requirements file, a Dockerfile,
a binary model file), but it must always answer in the same format. That is
what lets us add new scanners, risk scoring and reporters without touching
each other. Trusera does the same with a Pydantic model called AIComponent.
We use a plain dataclass to keep dependencies at zero.
"""
from dataclasses import dataclass, field, asdict


@dataclass
class AIComponent:
    name: str              # e.g. "OpenAI", "gpt-4o", "mcp:filesystem"
    category: str          # llm_provider, agent_framework, model_reference,
                           # api_key, endpoint, model_file, mcp_server, vector_db
    source_scanner: str    # which scanner found it (useful when debugging)
    file: str              # where it was found
    line: int | None       # line number if known
    evidence: str          # the exact text/proof. Never report without evidence.
    confidence: float      # 0.0-1.0, how sure are we this is really AI usage
    flags: list[str] = field(default_factory=list)  # risk signals, see risk.py
    risk_score: int = 0    # filled in later by risk.py
    severity: str = "low"  # filled in later by risk.py

    def to_dict(self) -> dict:
        return asdict(self)
