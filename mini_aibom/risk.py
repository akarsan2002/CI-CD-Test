"""Risk scoring: a pure, stateless function.

LESSON 11: "Stateless" means score_component(c) depends only on c: no globals,
no history. That makes it trivially testable and predictable. The tradeoff
is that this score has NO context: it doesn't know whether the code is
reachable, who can call it, or what tools the model controls. Adding that
context (reachability and blast radius) is the natural next step.
"""
from .models import AIComponent

CATEGORY_BASE = {
    "model_reference": 5, "llm_provider": 10, "endpoint": 10, "vector_db": 10,
    "model_file": 10, "agent_framework": 15, "mcp_server": 20, "api_key": 30,
    "ai_node": 10, "network_activity": 10,
}
FLAG_WEIGHTS = {
    "hardcoded_api_key": 40,
    "inline_secret": 35,
    "pickle_format": 20,
    "unpinned_package": 15,
    "insecure_transport": 20,
    "remote_server": 10,
    "unpinned_version": 5,
    "mcp_exposed": 15,
}


def severity_for(score: int) -> str:
    if score >= 76: return "critical"
    if score >= 51: return "high"
    if score >= 26: return "medium"
    return "low"


def score_component(c: AIComponent) -> AIComponent:
    score = CATEGORY_BASE.get(c.category, 5)
    score += sum(FLAG_WEIGHTS.get(f, 0) for f in c.flags)
    c.risk_score = min(score, 100)
    c.severity = severity_for(c.risk_score)
    return c
