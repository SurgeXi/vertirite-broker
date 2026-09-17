# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""CI import-guard for the publishable Vertirite broker.

One guard, three properties — enforced at build time so the "no model, no
node-exec, no internal topology" claim holds under a line-by-line audit and
cannot silently regress:

  1. MODEL   — no inference/model SDK is imported anywhere in the package.
  2. EXEC    — no node-exec / fleet-ops module is imported (the modules that
               were removed when the broker was made record-only).
  3. TOPOLOGY— no real internal hostname, user, or filesystem path appears
               in the source tree; fixtures use example.com / node-01 only.

Run under pytest, or standalone:  python broker/import_guard_test.py
"""

from __future__ import annotations

import ast
import pathlib
import re

_PKG_DIR = pathlib.Path(__file__).resolve().parent

# ── Property 1: MODEL — inference/model SDKs must never be imported ──────────
_FORBIDDEN_MODEL_MODULES = {
    "openai", "anthropic", "ollama", "llama_cpp", "llama_index",
    "transformers", "torch", "sentence_transformers", "sentencetransformers",
    "litellm", "vllm", "cohere", "google.generativeai", "tiktoken",
    "huggingface_hub", "accelerate", "onnxruntime",
}

# ── Property 2: EXEC — node-exec / fleet-ops modules were removed; keep out ──
_FORBIDDEN_EXEC_MODULES = {
    "executors", "surge_tools", "surge_capabilities", "surge_dispatch",
    "filesystem", "search_backends", "knowledge", "execution_learner",
    "paramiko", "asyncssh", "fabric",
}

# ── Property 3: TOPOLOGY — no real internal identifiers in the tree ──────────
# Fixtures must use example.com / node-01. These tokens are real-estate leaks.
# NB: `worker-node` has no trailing \b so it also catches "worker-noded".
# The generic CGNAT range (100.64/10, RFC 6598) is NOT banned — the discovery
# network-sensor legitimately uses it to classify internal traffic, exactly
# like RFC1918. Only the real fleet LAN (10.99.x) is a leak.
_FORBIDDEN_TOPOLOGY = [
    r"\bsurge-ai\b", r"\bsurgecore\b", r"\bsurge-storage\b", r"\bgodaddy-vps\b",
    r"\bcore-node\b", r"\bgpu-node\b", r"\bdb-host\b", r"worker-node",
    r"\bingress-node\b", r"\bsvcuser\b", r"[Tt]ailscale", r"/srv/ai-stack",
    r"\b10\.99\.\d+\.\d+\b",
]

_SELF = pathlib.Path(__file__).name


def _py_files() -> list[pathlib.Path]:
    return [p for p in _PKG_DIR.rglob("*.py") if p.name != _SELF and "__pycache__" not in p.parts]


def _imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:  # absolute import
                mods.add(node.module)
            # Also record the imported *names* so that `from . import X` and
            # `from ...pkg import X` (relative, any depth) are caught when X is
            # itself a forbidden module — the ast form the regex pass misses.
            for alias in node.names:
                mods.add(alias.name)
    return mods


def test_no_model_imports() -> None:
    offenders = []
    for path in _py_files():
        for mod in _imported_modules(path):
            top = mod.split(".")[0]
            if top in _FORBIDDEN_MODEL_MODULES or mod in _FORBIDDEN_MODEL_MODULES:
                offenders.append(f"{path.name}: imports {mod}")
    assert not offenders, "MODEL guard — inference SDK import(s) found:\n" + "\n".join(offenders)


def test_no_exec_imports() -> None:
    offenders = []
    for path in _py_files():
        for mod in _imported_modules(path):
            top = mod.split(".")[0]
            # relative imports (from . import X) surface as the bare name via ast? no —
            # ImportFrom with level>0 is skipped above; catch `from .executors import`
            # by also scanning the raw source for the removed local modules.
            if top in _FORBIDDEN_EXEC_MODULES:
                offenders.append(f"{path.name}: imports {mod}")
    # relative-import catch for removed local modules
    rel_pat = re.compile(r"from\s+\.(" + "|".join(sorted(_FORBIDDEN_EXEC_MODULES)) + r")\b")
    for path in _py_files():
        for m in rel_pat.finditer(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.name}: relative import .{m.group(1)}")
    assert not offenders, "EXEC guard — node-exec/fleet-ops import(s) found:\n" + "\n".join(offenders)


# ── Property 1b: MODEL (reach) — no inference call via httpx/gateway either ──
# The SDK-import ban above misses inference reached over HTTP (httpx to a
# gateway or a provider's chat/embeddings endpoint, or settings.ollama_*).
# This closes that gap. BYO-cloud KEY VALIDATION against a provider's
# model-LIST endpoint is allowed (non-generating); generation endpoints are not.
_FORBIDDEN_INFERENCE_REACH = [
    r"/chat/completions", r"/v1/embeddings", r"/api/generate", r"/api/chat",
    r"settings\.ollama", r"settings\.gateway_url", r"settings\.brain_url",
    r":11434", r":11435",
]


# The broker's whole purpose is to GOVERN AI calls, so two subpackages
# legitimately name inference endpoints: `discovery/` holds exposure-scanner
# detection patterns (it *finds* ungoverned Ollama/vLLM to recommend fronting
# them with the broker), and `enforcement/` is the BYO-cloud passthrough that
# gates→audits→forwards the customer's OWN call. Neither originates inference.
# The reach ban targets the CORE broker calling a model for its own reasoning.
_INFERENCE_REACH_EXEMPT_DIRS = {"discovery", "enforcement"}


def test_no_inference_reach() -> None:
    pats = [re.compile(p) for p in _FORBIDDEN_INFERENCE_REACH]
    offenders = []
    for path in _py_files():
        if _INFERENCE_REACH_EXEMPT_DIRS & set(path.relative_to(_PKG_DIR).parts):
            continue
        text = path.read_text(encoding="utf-8")
        for pat in pats:
            for m in pat.finditer(text):
                offenders.append(f"{path.name}: inference reach {m.group(0)!r}")
    assert not offenders, "MODEL-reach guard — inference call/endpoint found:\n" + "\n".join(offenders)


def test_no_topology_leaks() -> None:
    pats = [re.compile(p) for p in _FORBIDDEN_TOPOLOGY]
    offenders = []
    for path in _py_files():
        text = path.read_text(encoding="utf-8")
        for pat in pats:
            for m in pat.finditer(text):
                offenders.append(f"{path.name}: topology token {m.group(0)!r}")
    assert not offenders, "TOPOLOGY guard — internal identifier(s) found:\n" + "\n".join(offenders)


if __name__ == "__main__":
    failures = 0
    for name, fn in [
        ("MODEL", test_no_model_imports),
        ("MODEL-reach", test_no_inference_reach),
        ("EXEC", test_no_exec_imports),
        ("TOPOLOGY", test_no_topology_leaks),
    ]:
        try:
            fn()
            print(f"[PASS] {name} guard")
        except AssertionError as exc:
            failures += 1
            print(f"[FAIL] {name} guard\n{exc}")
    raise SystemExit(1 if failures else 0)
