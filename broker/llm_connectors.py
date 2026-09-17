# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""
Vertirite — BYO-cloud key connectors

The publishable broker contains NO model and calls none on its own behalf.
This module supports *bring-your-own-cloud*: it validates a customer's OWN
provider API key (a non-generating GET against the provider's model-list
endpoint) and publishes provider metadata so the operator can configure the
governed passthrough at /v1/proxy/openai. There is no local-model reach, no
provider/tier routing, and no inference call — the broker governs the calls
the customer's own agents make to the customer's own providers; it does not
make them.

NEVER logs API key values.
"""

from __future__ import annotations

import httpx

ANTHROPIC_VERSION = "2023-06-01"

# Provider metadata for BYO-cloud setup (config/catalog only — the broker
# never selects or calls any of these; size_gb=0 = cloud, not resident).
PAID_MODEL_PROVIDERS = {
    "gpt-4o": "openai",
    "gpt-4o-mini": "openai",
    "claude-sonnet-4-20250514": "anthropic",
    "claude-haiku-4-5-20251001": "anthropic",
    "gemini-2.5-flash": "google",
}

PAID_MODELS_CATALOG = [
    {"id": "gpt-4o", "provider": "openai", "size_gb": 0, "family": "gpt", "parameters": "cloud", "tier": "premium", "label": "ChatGPT 4o"},
    {"id": "gpt-4o-mini", "provider": "openai", "size_gb": 0, "family": "gpt", "parameters": "cloud", "tier": "pro", "label": "ChatGPT 4o Mini"},
    {"id": "claude-sonnet-4-20250514", "provider": "anthropic", "size_gb": 0, "family": "claude", "parameters": "cloud", "tier": "premium", "label": "Claude Sonnet 4"},
    {"id": "claude-haiku-4-5-20251001", "provider": "anthropic", "size_gb": 0, "family": "claude", "parameters": "cloud", "tier": "pro", "label": "Claude Haiku 4.5"},
    {"id": "gemini-2.5-flash", "provider": "google", "size_gb": 0, "family": "gemini", "parameters": "cloud", "tier": "pro", "label": "Gemini 2.5 Flash"},
]


async def test_external_key(provider: str, api_key: str) -> dict:
    """Validate a customer's OWN BYO-cloud key with a non-generating GET
    against the provider's model-list endpoint. Returns {"ok": bool, "detail": str}.
    This makes no inference call and stores nothing."""
    try:
        if provider == "openai":
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if resp.status_code == 200:
                    return {"ok": True, "detail": "OpenAI key is valid"}
                return {"ok": False, "detail": f"OpenAI returned {resp.status_code}"}
        elif provider == "anthropic":
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    "https://api.anthropic.com/v1/models",
                    headers={"x-api-key": api_key, "anthropic-version": ANTHROPIC_VERSION},
                )
                if resp.status_code == 200:
                    return {"ok": True, "detail": "Anthropic key is valid"}
                return {"ok": False, "detail": f"Anthropic returned {resp.status_code}"}
        elif provider == "google":
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}",
                )
                if resp.status_code == 200:
                    return {"ok": True, "detail": "Google key is valid"}
                return {"ok": False, "detail": f"Google returned {resp.status_code}"}
        else:
            return {"ok": False, "detail": f"Unknown provider: {provider}"}
    except Exception as e:
        return {"ok": False, "detail": str(e)}
