# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company.
# Licensed under the Business Source License 1.1 — see LICENSE.
"""
Vertirite Broker — Context Engine

Loads identity, owner profile, and product context from markdown files and
injects this knowledge into LLM prompts so the assistant knows who it is and
what it manages.

Operational context is loaded from a HOST-LOCAL directory named by the
``SURGE_OPERATOR_CONTEXT_DIR`` environment variable. The published image ships
only sanitized ``context/*.md.example`` fixtures — never real operational
intel. When no host-local override is configured (or it holds no ``*.md``
files), the engine falls back to those sanitized fixtures and reports its
source as ``"fixtures"`` so the deployment never *silently* looks healthy
while running on placeholder data.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

logger = logging.getLogger("vertirite.context")

# Host-local override: operators point this at a directory of real *.md files
# that never enters the image/repo. Absent → fall back to shipped fixtures.
_OVERRIDE = os.environ.get("SURGE_OPERATOR_CONTEXT_DIR")

# The directory shipped inside the package (holds *.md.example fixtures).
_SHIPPED_DIR = Path(__file__).parent.parent / "context"

# The directory context is loaded from: the host-local override if set, else
# the shipped fixture directory.
CONTEXT_DIR = Path(_OVERRIDE) if _OVERRIDE else _SHIPPED_DIR

# Files loaded first, in priority order.
_PRIORITY = ["identity.md", "owner.md", "fleet.md", "products.md"]

_cached_context: str | None = None
_cache_time: float = 0.0
# "operational" (real host-local intel) or "fixtures" (sanitized placeholders).
_context_source: str = "fixtures"


def _has_real_context() -> bool:
    """True only when a host-local override is configured AND it actually
    contains at least one real ``*.md`` file. This is the structural test that
    distinguishes an operational deployment from one running on fixtures."""
    if not _OVERRIDE:
        return False
    d = Path(_OVERRIDE)
    return d.exists() and any(d.glob("*.md"))


def _load_from(directory: Path, suffix: str) -> str:
    """Concatenate context files (``<name>{suffix}``) from a directory in
    priority order, then any remaining files with that suffix."""
    if not directory.exists():
        return ""
    parts: list[str] = []
    loaded: set[str] = set()
    for name in _PRIORITY:
        fp = directory / f"{name}{suffix}"
        if fp.exists():
            content = fp.read_text(encoding="utf-8").strip()
            if content:
                parts.append(content)
                loaded.add(fp.name)
    for fp in sorted(directory.glob(f"*{suffix}")):
        if fp.name not in loaded:
            content = fp.read_text(encoding="utf-8").strip()
            if content:
                parts.append(content)
    return "\n\n---\n\n".join(parts)


def load_context() -> str:
    """Load all context files and return as a single string for LLM injection.

    Prefers real host-local operational context; otherwise degrades to the
    sanitized shipped fixtures, and to ``""`` if neither is present.
    Cache refreshes every 5 minutes so edits are picked up.
    """
    global _cached_context, _cache_time, _context_source
    if _cached_context is not None and (time.time() - _cache_time) < 300:
        return _cached_context

    if _has_real_context():
        text = _load_from(Path(_OVERRIDE), ".md")
        _context_source = "operational"
    else:
        # Sanitized fixtures shipped with the image (*.md.example).
        text = _load_from(_SHIPPED_DIR, ".md.example")
        _context_source = "fixtures"

    _cached_context = text
    _cache_time = time.time()
    logger.info(
        "Context loaded: %d chars (source=%s, dir=%s)",
        len(text), _context_source, CONTEXT_DIR,
    )
    return _cached_context


def context_source() -> str:
    """Return "operational" or "fixtures" for the CURRENTLY loaded context.

    Ensures context has been loaded at least once so the answer is accurate.
    """
    if _cached_context is None:
        load_context()
    return _context_source


def warn_if_fixtures() -> None:
    """Emit a startup WARN when the broker is serving sanitized fixtures rather
    than real operational context. Same discipline as the ungoverned-mode
    warning: never let a placeholder deployment look healthy."""
    if context_source() != "operational":
        logger.warning(
            "context: serving sanitized fixtures, not operational context — "
            "set SURGE_OPERATOR_CONTEXT_DIR to a host-local directory of real "
            "*.md context files to run operationally."
        )


def reload_context() -> str:
    """Force reload context files (useful after editing)."""
    global _cached_context
    _cached_context = None
    return load_context()


def get_context_files() -> list[dict]:
    """List all loaded context files with metadata."""
    directory = Path(_OVERRIDE) if _has_real_context() else _SHIPPED_DIR
    suffix = ".md" if _has_real_context() else ".md.example"
    if not directory.exists():
        return []
    files = []
    for filepath in sorted(directory.glob(f"*{suffix}")):
        stat = filepath.stat()
        files.append({
            "name": filepath.name,
            "path": str(filepath),
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "source": "operational" if suffix == ".md" else "fixtures",
        })
    return files
