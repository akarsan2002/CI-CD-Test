"""Detection DATA, kept separate from detection LOGIC.

LESSON 4: This file is the "signature database". Scanners are small and
generic; the knowledge of *what counts as AI* lives here. New SDKs and models
appear every month, so this file is what needs ongoing maintenance. It is
the real long-term work of any AI-BOM tool, and where a team can build an
advantage by keeping it better than the open-source defaults.
"""
import re

# Package name (lowercase, '_' -> '-') -> (display name, category).
# Covers both pip and npm names.
PACKAGES: dict[str, tuple[str, str]] = {
    "openai": ("OpenAI", "llm_provider"),
    "anthropic": ("Anthropic", "llm_provider"),
    "@anthropic-ai/sdk": ("Anthropic", "llm_provider"),
    "google-generativeai": ("Google Generative AI", "llm_provider"),
    "google-genai": ("Google GenAI", "llm_provider"),
    "@google/generative-ai": ("Google Generative AI", "llm_provider"),
    "mistralai": ("Mistral", "llm_provider"),
    "cohere": ("Cohere", "llm_provider"),
    "ollama": ("Ollama", "llm_provider"),
    "litellm": ("LiteLLM", "llm_provider"),
    "transformers": ("Hugging Face Transformers", "llm_provider"),
    "langchain": ("LangChain", "agent_framework"),
    "langgraph": ("LangGraph", "agent_framework"),
    "crewai": ("CrewAI", "agent_framework"),
    "pyautogen": ("AutoGen", "agent_framework"),
    "autogen": ("AutoGen", "agent_framework"),
    "llama-index": ("LlamaIndex", "agent_framework"),
    "chromadb": ("ChromaDB", "vector_db"),
}

# Families of packages sharing a prefix (langchain-openai, @langchain/core ...)
PREFIX_PACKAGES: list[tuple[str, tuple[str, str]]] = [
    ("langchain-", ("LangChain", "agent_framework")),
    ("@langchain/", ("LangChain", "agent_framework")),
    ("llama-index-", ("LlamaIndex", "agent_framework")),
]

# Python import names that differ from their package names.
IMPORT_ALIASES = {
    "google.generativeai": "google-generativeai",
    "google.genai": "google-genai",
}


def lookup_package(name: str) -> tuple[str, str] | None:
    n = name.lower().replace("_", "-")
    if n in PACKAGES:
        return PACKAGES[n]
    for prefix, info in PREFIX_PACKAGES:
        if n.startswith(prefix):
            return info
    return None


# Hostnames that mean "this code talks to an AI service".
ENDPOINTS: dict[str, str] = {
    "api.openai.com": "OpenAI",
    "api.anthropic.com": "Anthropic",
    "generativelanguage.googleapis.com": "Google Generative AI",
    "api.mistral.ai": "Mistral",
    "api.cohere.com": "Cohere",
    "api.deepseek.com": "DeepSeek",
    "localhost:11434": "Ollama (local)",
    "127.0.0.1:11434": "Ollama (local)",
}

# Model-name patterns. Strings are weak evidence (any text can contain them),
# so findings from these get LOWER confidence than imports.
MODEL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(gpt-(?:3\.5|4|5)[\w.\-]*)"), "OpenAI"),
    (re.compile(r"\b(claude-[a-z0-9][\w.\-]*)"), "Anthropic"),
    (re.compile(r"\b(gemini-[\w.\-]+)"), "Google"),
    (re.compile(r"\b(llama-?\d[\w.\-]*)", re.I), "Meta"),
    (re.compile(r"\b(mistral-(?:large|medium|small|tiny)[\w.\-]*)"), "Mistral"),
    (re.compile(r"\b(deepseek-[\w.\-]+)"), "DeepSeek"),
]

# Secret formats. ORDER MATTERS: the Anthropic key also matches the generic
# OpenAI-style "sk-" pattern, so the more specific pattern must come first.
KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Anthropic", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("Hugging Face", re.compile(r"hf_[A-Za-z0-9]{20,}")),
]

# Model weight files. Pickle-based formats can execute code when loaded.
MODEL_FILE_EXTENSIONS = {
    ".gguf": False,
    ".safetensors": False,
    ".onnx": False,
    ".pt": True,
    ".pth": True,
    ".ckpt": True,
}  # extension -> is it pickle-based (unsafe to load from untrusted sources)?

# ---- n8n -------------------------------------------------------------------
# n8n AI nodes live in this namespace (seen in a real export:
# "@n8n/n8n-nodes-langchain.openAi").
N8N_AI_NAMESPACE = "@n8n/n8n-nodes-langchain."

# Node type suffix -> (display name, category).
# ONLY "openAi" is confirmed from a real export. The rest are from memory and
# should be verified against real exports before you trust them.
N8N_AI_NODES: dict[str, tuple[str, str]] = {
    "openAi": ("OpenAI", "llm_provider"),                 # CONFIRMED
    "lmChatOpenAi": ("OpenAI", "llm_provider"),           # unverified
    "lmChatAnthropic": ("Anthropic", "llm_provider"),     # unverified
    "anthropic": ("Anthropic", "llm_provider"),           # unverified
    "lmChatGoogleGemini": ("Google Gemini", "llm_provider"),  # unverified
    "lmChatOllama": ("Ollama", "llm_provider"),           # unverified
    "agent": ("n8n AI Agent", "agent_framework"),         # unverified
}
