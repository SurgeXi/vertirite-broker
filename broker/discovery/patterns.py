# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Pattern library for Vertirite discovery (Pillar B).

Each entry maps a low-level signal (process name, network endpoint,
container image, log line) to a stable pattern identifier the broker
recognises. Pattern IDs are stable across releases so findings are
comparable over time.

This library is the long pole. Every customer onboarding teaches us
new vendor-installed AI patterns (Epic's clinical assistant, GE Predix
AI add-on, Siemens MindSphere, etc.); those entries land here in a
follow-up PR. The seed set below covers the open-source / SaaS-AI
patterns we expect to find in every customer environment from day one.

Coverage estimate of the seed set against a typical regional-hospital
or mid-market manufacturer environment: ~80%. The remaining 20%
typically comprises vendor-installed inference boxes with custom
binaries; those need the eBPF / auditd layer added in a future PR.

Schema for a pattern entry:
    {
        "pattern_id": str — stable ID, snake_case, no whitespace
        "name": str — human label for the UI
        "signal_type": "process" | "network" | "container" | "log"
        "match": ...  — type-specific match shape (see below)
        "confidence": "low" | "medium" | "high"
                      ↑ default confidence; the scanner may downgrade
        "category": "client-library" | "inference-runtime" | "service-endpoint" | "vendor-product"
        "remediation": short string — what bringing this under governance
                       requires (used in the dashboard UI).
    }

Match shapes by signal type:
    process:    {"cmdline_re": str regex applied to /proc/<pid>/cmdline (NUL→space)}
    network:    {"port": int} OR {"host_re": str regex against the remote hostname}
    container:  {"image_re": str regex applied to the docker image name+tag}
    log:        {"line_re": str regex, "source": "syslog"|"journald"|"file:<path>"}
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


PATTERN_LIBRARY: List[Dict[str, Any]] = [
    # ─── AI client libraries (Python) ────────────────────────────────
    {
        "pattern_id": "py-openai-client",
        "name": "OpenAI Python client",
        "signal_type": "process",
        "match": {"cmdline_re": r"python.*\bopenai\b"},
        "confidence": "medium",
        "category": "client-library",
        "remediation": "Route the OpenAI base_url through the Vertirite broker; the broker forwards to OpenAI under policy.",
    },
    {
        "pattern_id": "py-anthropic-client",
        "name": "Anthropic Python client",
        "signal_type": "process",
        "match": {"cmdline_re": r"python.*\banthropic\b"},
        "confidence": "medium",
        "category": "client-library",
        "remediation": "Route the Anthropic base_url through the Vertirite broker; the broker forwards to Anthropic under policy.",
    },
    {
        "pattern_id": "py-langchain",
        "name": "LangChain Python",
        "signal_type": "process",
        "match": {"cmdline_re": r"python.*\blangchain\b"},
        "confidence": "low",
        "category": "client-library",
        "remediation": "Wrap LangChain chat models with a Vertirite client; the broker becomes the LLM endpoint LangChain talks to.",
    },
    {
        "pattern_id": "py-llamaindex",
        "name": "LlamaIndex Python",
        "signal_type": "process",
        "match": {"cmdline_re": r"python.*\bllama[_-]?index\b"},
        "confidence": "low",
        "category": "client-library",
        "remediation": "LlamaIndex's LLM provider must be configured to point at the Vertirite broker.",
    },
    {
        "pattern_id": "py-transformers",
        "name": "HuggingFace transformers (local inference)",
        "signal_type": "process",
        "match": {"cmdline_re": r"python.*\btransformers\b"},
        "confidence": "low",
        "category": "inference-runtime",
        "remediation": "Local inference is not currently policy-gated by Vertirite; consider running this behind the fleet agent's local inference adapter.",
    },

    # ─── AI client libraries (Node / TS) ─────────────────────────────
    {
        "pattern_id": "node-openai-sdk",
        "name": "OpenAI Node SDK",
        "signal_type": "process",
        "match": {"cmdline_re": r"node.*(openai|@openai/api)"},
        "confidence": "medium",
        "category": "client-library",
        "remediation": "Set baseURL on the OpenAI Node client to the Vertirite broker.",
    },
    {
        "pattern_id": "node-anthropic-sdk",
        "name": "Anthropic Node SDK",
        "signal_type": "process",
        "match": {"cmdline_re": r"node.*@anthropic-ai/sdk"},
        "confidence": "medium",
        "category": "client-library",
        "remediation": "Set baseURL on the Anthropic Node client to the Vertirite broker.",
    },

    # ─── Local inference runtimes ────────────────────────────────────
    {
        "pattern_id": "ollama-runtime",
        "name": "Ollama (local LLM runtime)",
        "signal_type": "process",
        "match": {"cmdline_re": r"\bollama\b\s*(serve|run)"},
        "confidence": "high",
        "category": "inference-runtime",
        "remediation": "Front Ollama with the Vertirite broker so calls to :11434 go through policy + audit.",
    },
    {
        "pattern_id": "llama-cpp",
        "name": "llama.cpp server",
        "signal_type": "process",
        "match": {"cmdline_re": r"\bllama[._-]?cpp\b|\bllama-server\b"},
        "confidence": "high",
        "category": "inference-runtime",
        "remediation": "Front the llama-server endpoint with the Vertirite broker.",
    },
    {
        "pattern_id": "vllm-runtime",
        "name": "vLLM inference server",
        "signal_type": "process",
        "match": {"cmdline_re": r"python.*\bvllm\b\.(entrypoints|api_server)"},
        "confidence": "high",
        "category": "inference-runtime",
        "remediation": "Front vLLM's OpenAI-compatible endpoint with the Vertirite broker.",
    },
    {
        "pattern_id": "text-generation-webui",
        "name": "text-generation-webui",
        "signal_type": "process",
        "match": {"cmdline_re": r"python.*text[_-]generation[_-]webui"},
        "confidence": "high",
        "category": "inference-runtime",
        "remediation": "Front this endpoint with the Vertirite broker; restrict direct access.",
    },

    # ─── Network signals — outbound to known SaaS LLM hosts ──────────
    {
        "pattern_id": "net-openai-saas",
        "name": "Outbound traffic to api.openai.com",
        "signal_type": "network",
        "match": {"host_re": r"^(api|chat)\.openai\.com$"},
        "confidence": "high",
        "category": "service-endpoint",
        "remediation": "Route OpenAI traffic through the Vertirite broker. Add an egress firewall rule to block direct api.openai.com after migration.",
    },
    {
        "pattern_id": "net-anthropic-saas",
        "name": "Outbound traffic to api.anthropic.com",
        "signal_type": "network",
        "match": {"host_re": r"^api\.anthropic\.com$"},
        "confidence": "high",
        "category": "service-endpoint",
        "remediation": "Route Anthropic traffic through the Vertirite broker. Add an egress firewall rule after migration.",
    },
    {
        "pattern_id": "net-bedrock-saas",
        "name": "Outbound traffic to AWS Bedrock",
        "signal_type": "network",
        "match": {"host_re": r"\bbedrock(-runtime)?\.[a-z0-9-]+\.amazonaws\.com$"},
        "confidence": "high",
        "category": "service-endpoint",
        "remediation": "Route Bedrock InvokeModel through the Vertirite broker; the broker IAM-assumes the Bedrock role under policy.",
    },
    {
        "pattern_id": "net-azure-openai",
        "name": "Outbound traffic to Azure OpenAI",
        "signal_type": "network",
        "match": {"host_re": r"\.openai\.azure\.com$"},
        "confidence": "high",
        "category": "service-endpoint",
        "remediation": "Route Azure OpenAI traffic through the Vertirite broker.",
    },
    {
        "pattern_id": "net-vertex-ai",
        "name": "Outbound traffic to Google Vertex AI",
        "signal_type": "network",
        "match": {"host_re": r"-aiplatform\.googleapis\.com$"},
        "confidence": "high",
        "category": "service-endpoint",
        "remediation": "Route Vertex AI traffic through the Vertirite broker.",
    },
    {
        "pattern_id": "net-cohere-saas",
        "name": "Outbound traffic to Cohere",
        "signal_type": "network",
        "match": {"host_re": r"^api\.cohere\.(ai|com)$"},
        "confidence": "high",
        "category": "service-endpoint",
        "remediation": "Route Cohere traffic through the Vertirite broker.",
    },
    {
        "pattern_id": "net-together-saas",
        "name": "Outbound traffic to Together AI",
        "signal_type": "network",
        "match": {"host_re": r"\.together\.(ai|xyz)$"},
        "confidence": "high",
        "category": "service-endpoint",
        "remediation": "Route Together AI traffic through the Vertirite broker.",
    },

    # ─── Suspicious / malicious egress (threat tier) ─────────────────
    {
        "pattern_id": "net-crypto-mining-pool",
        "name": "Crypto-mining pool",
        "signal_type": "network",
        "match": {"host_re": r"(minexmr|supportxmr|nanopool|f2pool|ethermine|hashvault|moneroocean|xmrpool)\."},
        "confidence": "high",
        "category": "suspicious-egress",
        "remediation": "Investigate immediately — outbound to a crypto-mining pool usually means a compromised host or insider misuse. Block at the egress proxy.",
    },
    {
        "pattern_id": "net-paste-exfil",
        "name": "Data exfiltration to a paste/dump site",
        "signal_type": "network",
        "match": {"host_re": r"^(paste\.ee|pastebin\.com|hastebin\.com|ghostbin\.\w+|dpaste\.\w+|0bin\.\w+|transfer\.sh)$"},
        "confidence": "high",
        "category": "suspicious-egress",
        "remediation": "Investigate — automated POSTs to a paste/dump site are a common exfiltration channel. Block + audit the source process.",
    },
    {
        "pattern_id": "net-webhook-exfil",
        "name": "Egress to an ad-hoc webhook/collector",
        "signal_type": "network",
        "match": {"host_re": r"^(webhook\.site|requestbin\.\w+|\w+\.pipedream\.net|\w+\.ngrok\.(io|app))$"},
        "confidence": "medium",
        "category": "suspicious-egress",
        "remediation": "Ad-hoc webhook collectors are used to siphon data during testing — and by attackers. Confirm ownership or block.",
    },
    {
        "pattern_id": "net-unsanctioned-ai",
        "name": "Unsanctioned AI service (shadow AI)",
        "signal_type": "network",
        "match": {"host_re": r"(api\.deepseek\.com|api\.x\.ai|api\.groq\.com|openrouter\.ai|api\.perplexity\.ai)$"},
        "confidence": "high",
        "category": "suspicious-egress",
        "remediation": "An AI provider not on the sanctioned list. Decide: sanction + route through the broker, or block.",
    },

    # ─── Catch-all: any external destination the sensor can't name ───
    {
        "pattern_id": "net-unrecognized-external-egress",
        "name": "Outbound traffic to an unrecognized external host",
        "signal_type": "network",
        "match": {"host_re": r".+"},  # sensor applies this ONLY as a fallback for external hosts
        "confidence": "low",
        "category": "service-endpoint",
        "remediation": "Review this destination. If it carries AI/automation traffic, route it through the Vertirite broker; otherwise dismiss.",
    },

    # ─── East-west / internal flows (intra-network — NOT egress) ─────
    # These never cross the network edge, so the proxy/DNS/egress tier is BLIND
    # to them. They are surfaced only by an internal sensor: a switch SPAN/TAP
    # (Zeek conn.log), NetFlow/IPFIX/sFlow from switches, or an on-host eBPF
    # agent. analyze_flow() classifies and assigns these pattern_ids directly,
    # so they carry NO host_re (match_host/egress never picks them up).
    {
        "pattern_id": "net-internal-lateral",
        "name": "Internal host-to-host flow (east-west)",
        "signal_type": "network",
        "match": {"flow": "internal"},  # classified by analyze_flow, not host_re
        "confidence": "low",
        "category": "east-west",
        "remediation": "Traffic that never leaves the network. Confirm both endpoints are expected; an unexpected internal peer can be lateral movement or an unsanctioned internal service.",
    },
    {
        "pattern_id": "net-internal-llm-port",
        "name": "Internal AI inference endpoint (east-west)",
        "signal_type": "network",
        "match": {"flow": "internal", "ports": [11434, 8000, 8080]},
        "confidence": "high",
        "category": "east-west",
        "remediation": "A host is serving LLM inference to OTHER internal hosts (Ollama :11434, vLLM :8000, etc.). Front it with the Vertirite broker so internal AI calls are governed + audited too — egress rules never see this.",
    },
    {
        "pattern_id": "net-ot-protocol",
        "name": "Industrial control protocol (east-west)",
        "signal_type": "network",
        "match": {"flow": "internal", "ports": [502, 20000, 44818, 4840, 2404, 102]},
        "confidence": "medium",
        "category": "east-west",
        "remediation": "OT/ICS protocol traffic (Modbus/DNP3/EtherNet-IP/OPC-UA/IEC-104). Baseline the expected device-to-device pairs; a new talker on a control segment warrants investigation.",
    },
    {
        "pattern_id": "net-host-local-ipc",
        "name": "Process-to-process on the same host (loopback/IPC)",
        "signal_type": "network",
        "match": {"flow": "host-local"},
        "confidence": "low",
        "category": "host-local",
        "remediation": "Two processes talking over loopback on one host — visible ONLY to an on-host (eBPF/auditd) sensor, never to a network tap. Confirm the local service is expected.",
    },

    # ─── Local ports often used by inference services ────────────────
    {
        "pattern_id": "port-ollama-default",
        "name": "Process listening on :11434 (Ollama default)",
        "signal_type": "network",
        "match": {"port": 11434},
        "confidence": "high",
        "category": "service-endpoint",
        "remediation": "Front the Ollama endpoint with the Vertirite broker; restrict direct port 11434 to the broker host.",
    },
    {
        "pattern_id": "port-vllm-default",
        "name": "Process listening on :8000 (common for vLLM / FastAPI inference)",
        "signal_type": "network",
        "match": {"port": 8000},
        "confidence": "low",
        "category": "service-endpoint",
        "remediation": "Confirm this is an AI inference endpoint; if so, front it with the Vertirite broker.",
    },

    # ─── Container images ────────────────────────────────────────────
    {
        "pattern_id": "container-ollama",
        "name": "Container running ollama/ollama image",
        "signal_type": "container",
        "match": {"image_re": r"^ollama/ollama"},
        "confidence": "high",
        "category": "inference-runtime",
        "remediation": "Front the Ollama container's exposed port with the Vertirite broker.",
    },
    {
        "pattern_id": "container-vllm",
        "name": "Container running vllm image",
        "signal_type": "container",
        "match": {"image_re": r"vllm/vllm-openai|^vllm/"},
        "confidence": "high",
        "category": "inference-runtime",
        "remediation": "Front the vLLM container with the Vertirite broker.",
    },
    {
        "pattern_id": "container-huggingface-tgi",
        "name": "HuggingFace text-generation-inference container",
        "signal_type": "container",
        "match": {"image_re": r"ghcr\.io/huggingface/text-generation-inference"},
        "confidence": "high",
        "category": "inference-runtime",
        "remediation": "Front the TGI container with the Vertirite broker.",
    },
    {
        "pattern_id": "container-litellm",
        "name": "LiteLLM proxy container (an LLM aggregator — not Vertirite)",
        "signal_type": "container",
        "match": {"image_re": r"berriai/litellm|^litellm/"},
        "confidence": "medium",
        "category": "service-endpoint",
        "remediation": "If LiteLLM is the SAS routing layer, repoint it at the Vertirite broker as its upstream so audit + policy still apply.",
    },
    # --- self-protection (Mechanism #2). Reported PROGRAMMATICALLY by
    # protection/selfwitness.py, never matched by the egress sensor; the inert
    # "self" match keeps it out of host matching (same trick as east-west flows).
    # BASELINE on purpose: self-witness must fire even after the premium catalog
    # has rotted (a thief who blocks the feed also rots the catalog). ---
    {
        "pattern_id": "self-egress-suppressed",
        "name": "Vertirite governance channel suppressed (possible hidden/stolen copy)",
        "signal_type": "network",
        "match": {"self": "egress-suppressed"},
        "confidence": "high",
        "category": "self-protection",
        "remediation": "Vertirite's own phone-home is being blocked. Confirm the intelligence feed host is reachable from this instance; an intentional block is a strong signal someone is hiding this deployment from governance.",
    },
    {
        "pattern_id": "self-environment-changed",
        "name": "Vertirite environment fingerprint changed (possible copied install)",
        "signal_type": "network",
        "match": {"self": "environment-changed"},
        "confidence": "high",
        "category": "self-protection",
        "remediation": "This install's environment fingerprint no longer matches the one it was bound to (Mechanism #3). If this was a legitimate migration, re-bind via POST /v1/protection/rebind; otherwise it may be a copy running in a foreign environment.",
    },
    # --- self-DISCLOSURE. A discovery product must be able to see its OWN
    # egress: when Vertirite itself reaches out (its beacon / brain / AI /
    # heartbeat / feed endpoints), that traffic is recognised here and shown as
    # SELF rather than mislabelled as unknown external egress or hidden. Matched
    # PROGRAMMATICALLY by network_sensor against the broker's own configured
    # egress hosts (settings + VERTIRITE_SELF_HOSTS), never by host_re. ---
    {
        "pattern_id": "self-vertirite-egress",
        "name": "Vertirite (this product) \u2014 its own control / AI / heartbeat egress",
        "signal_type": "network",
        "match": {"self": "vertirite-egress"},
        "confidence": "high",
        "category": "self-disclosure",
        "remediation": "This is Vertirite itself, disclosed for transparency (beacon / brain / AI inference / heartbeat / intelligence feed). No action needed \u2014 a product that governs every inference must be able to see its own. To route it out, unset the relevant SURGE_OPERATOR_* URL (Sovereign / no-phone-home default).",
    },
]


def list_patterns(tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """The active discovery patterns.

    With a ``tenant_id``, returns that tenant's ACTIVE catalog — the open
    baseline merged with its FRESH/STALE premium layer, or baseline-only once the
    premium layer has decayed (Mechanism #1, docs/PROTECTION-MODEL.md). Without
    one, returns the open baseline — preserving pre-Mechanism-#1 behavior for
    every existing caller.
    """
    from ..intelligence.catalog import active_patterns
    if tenant_id is None:
        return active_patterns(None)
    try:
        return active_patterns(tenant_id)
    except Exception:
        # Premium-catalog store (DB) momentarily unavailable -> degrade to the
        # open baseline. A discovery sensor must never crash on a catalog blip.
        return active_patterns(None)


def lookup_pattern(pattern_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    for p in list_patterns(tenant_id):
        if p["pattern_id"] == pattern_id:
            return p
    return None


def patterns_by_signal_type(signal_type: str, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    return [p for p in list_patterns(tenant_id) if p["signal_type"] == signal_type]


# ---------------------------------------------------------------------------
# Friendly display names (rename layer). The Coverage Map shows these so a
# non-technical operator recognises WHAT they are governing ("Claude", not
# "api.anthropic.com"), and can group a vendor's endpoints under one service.
# Unmapped pattern -> None -> the console falls back to the raw hostname.
# ---------------------------------------------------------------------------
FRIENDLY_NAMES: Dict[str, Dict[str, str]] = {
    "net-openai-saas":                {"name": "OpenAI",         "vendor": "OpenAI",      "service": "ChatGPT / GPT API"},
    "net-anthropic-saas":             {"name": "Claude",         "vendor": "Anthropic",   "service": "Claude API"},
    "net-gemini-saas":                {"name": "Google Gemini",  "vendor": "Google",      "service": "Gemini API"},
    "net-mistral-saas":               {"name": "Mistral",        "vendor": "Mistral AI",  "service": "Mistral API"},
    "net-cohere-saas":                {"name": "Cohere",         "vendor": "Cohere",      "service": "Cohere API"},
    "net-bedrock-saas":               {"name": "AWS Bedrock",    "vendor": "Amazon",      "service": "Bedrock"},
    "net-azure-openai":               {"name": "Azure OpenAI",   "vendor": "Microsoft",   "service": "Azure OpenAI"},
    "net-vertex-ai":                  {"name": "Vertex AI",      "vendor": "Google",      "service": "Vertex AI"},
    "net-huggingface-inference":      {"name": "Hugging Face",   "vendor": "Hugging Face","service": "Inference API"},
    "net-replicate-saas":             {"name": "Replicate",      "vendor": "Replicate",   "service": "Replicate"},
    "net-together-saas":              {"name": "Together AI",    "vendor": "Together",    "service": "Together API"},
    "net-fireworks-saas":             {"name": "Fireworks AI",   "vendor": "Fireworks",   "service": "Fireworks API"},
    "net-crypto-mining-pool":         {"name": "Crypto-mining pool", "vendor": "\u2014", "service": "mining pool (threat)"},
    "net-paste-exfil":                {"name": "Paste / dump site",  "vendor": "\u2014", "service": "exfil channel (threat)"},
    "net-webhook-exfil":             {"name": "Webhook sink",       "vendor": "\u2014", "service": "exfil channel (threat)"},
    "net-unsanctioned-ai":            {"name": "Unsanctioned AI","vendor": "\u2014",     "service": "shadow AI"},
    "self-vertirite-egress":          {"name": "Vertirite (this product)", "vendor": "SurgeXi", "service": "control / AI / heartbeat"},
    "net-unrecognized-external-egress": {"name": "Unrecognized egress", "vendor": "\u2014", "service": "unknown external"},
}


def friendly_name(pattern_id: Optional[str]) -> Optional[Dict[str, str]]:
    """Human display for a pattern: {name, vendor, service}, or None if unmapped
    (the console then shows the raw hostname). First layer of the rename feature."""
    if not pattern_id:
        return None
    return FRIENDLY_NAMES.get(pattern_id)
