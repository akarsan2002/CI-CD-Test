"""Scanner 5: n8n workflow exports (.json), built against a REAL export.

What the real export taught us (these shaped the design):

1. AI nodes are identified by their `type` string, e.g.
   "@n8n/n8n-nodes-langchain.openAi". Config lives under `parameters`.
2. Secrets can sit ANYWHERE inside `parameters`. In the real file the key was at
   nodes[1].parameters.headerParameters.parameters[0].value, inside an
   HTTP Request node, not an AI node. So we do NOT look at known field names;
   we walk every string in the node and run the shared detectors on it.
3. A model name can be hidden inside a JSON *string* (`jsonBody` holds JSON
   as text). Walking strings handles that for free.
4. Workflows are recognised by structure, not filename (see detect.py).
5. Unknown fields must never crash us. Everything uses .get() and isinstance.

NOT yet confirmed by a real export: how `credentials` references look (the
test export had none), and most node type names. Those parts are marked.
"""
from pathlib import Path

from ..base import BaseScanner, read_text_safe, find_line
from ..detect import find_endpoints, find_keys, find_models, mask, parse_n8n_workflow
from ..models import AIComponent
from ..signatures import N8N_AI_NAMESPACE, N8N_AI_NODES


def walk_strings(value, path):
    """Yield (json_path, string) for every string inside nested dicts/lists."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from walk_strings(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk_strings(v, f"{path}[{i}]")


def classify_node(node_type: str):
    """Return (display_name, category, confidence) for an AI node, else None."""
    if not node_type.startswith(N8N_AI_NAMESPACE):
        return None
    suffix = node_type[len(N8N_AI_NAMESPACE):]
    if suffix in N8N_AI_NODES:
        name, category = N8N_AI_NODES[suffix]
        return name, category, 1.0
    # Not in our table: guess from the name, with LOWER confidence.
    low = suffix.lower()
    if low.startswith("vectorstore"):
        return f"n8n vector store ({suffix})", "vector_db", 0.7
    if "mcp" in low:
        return f"n8n MCP node ({suffix})", "mcp_server", 0.7
    if "agent" in low:
        return "n8n AI Agent", "agent_framework", 0.7
    return f"n8n AI node ({suffix})", "ai_node", 0.7


class N8NScanner(BaseScanner):
    name = "n8n"
    description = "AI nodes, endpoints, models and hardcoded keys in n8n workflow exports"

    def supports(self, path: Path) -> bool:
        return path.suffix == ".json"  # cheap; scan() decides by structure

    def scan(self, path: Path) -> list[AIComponent]:
        text = read_text_safe(path)
        if text is None:
            return []
        doc = parse_n8n_workflow(text)
        if doc is None:
            return []

        wf_name = str(doc.get("name") or path.stem)
        out: list[AIComponent] = []

        for i, node in enumerate(doc["nodes"]):
            out.extend(self._node(path, text, i, node))

        # pinData holds saved sample data from test runs. It can contain real
        # data and secrets, so it gets scanned too.
        pin = doc.get("pinData")
        if isinstance(pin, dict):
            for node_name, items in pin.items():
                out.extend(self._strings(path, text, str(node_name),
                                         walk_strings(items, f"pinData[{node_name!r}]")))

        # INFERRED from the field name `settings.availableInMCP` seen in the
        # real export; verify what it means in n8n's docs before relying on it.
        settings = doc.get("settings")
        if isinstance(settings, dict) and settings.get("availableInMCP") is True:
            out.append(AIComponent(
                name=f"workflow exposed to MCP: {wf_name}"[:60], category="mcp_server",
                source_scanner=self.name, file=str(path),
                line=find_line(text, "availableInMCP"),
                evidence="settings.availableInMCP is true", confidence=0.7,
                flags=["mcp_exposed"]))
        return out

    def _node(self, path, text, index, node):
        if not isinstance(node, dict):
            return []
        ntype = str(node.get("type", ""))
        nname = str(node.get("name", ntype))
        out = []

        info = classify_node(ntype)
        if info:
            display, category, confidence = info
            # A credential REFERENCE (name + id) is the safe, normal way to
            # store a key, so we note it but never flag it. (Format from
            # memory, not yet seen in a real export.)
            creds = node.get("credentials")
            note = f"; credential reference: {', '.join(sorted(creds))}" \
                if isinstance(creds, dict) and creds else ""
            out.append(AIComponent(
                name=display, category=category, source_scanner=self.name,
                file=str(path), line=find_line(text, str(node.get("id", ntype))),
                evidence=f'node "{nname}" ({ntype}){note}'[:160],
                confidence=confidence, flags=[]))

        out.extend(self._strings(path, text, nname,
                                 walk_strings(node.get("parameters"), f"nodes[{index}].parameters")))
        return out

    def _strings(self, path, text, node_name, strings):
        out = []
        for json_path, s in strings:
            for provider, secret in find_keys(s):
                out.append(AIComponent(
                    name=f"{provider} API key", category="api_key",
                    source_scanner=self.name, file=str(path),
                    line=find_line(text, secret),
                    evidence=f'key {mask(secret)} in node "{node_name}" at {json_path}'[:160],
                    confidence=0.95, flags=["hardcoded_api_key"]))
            for host, vendor in find_endpoints(s):
                out.append(AIComponent(
                    name=vendor, category="endpoint", source_scanner=self.name,
                    file=str(path), line=find_line(text, host),
                    evidence=f'node "{node_name}" calls {host} ({json_path})'[:160],
                    confidence=0.9, flags=[]))
            for model, _vendor in find_models(s):
                out.append(AIComponent(
                    name=model, category="model_reference", source_scanner=self.name,
                    file=str(path), line=find_line(text, model),
                    evidence=f'{model} in node "{node_name}" ({json_path})'[:160],
                    confidence=0.6, flags=[]))
        return out
