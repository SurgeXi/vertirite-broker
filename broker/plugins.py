# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Plugin registry for the Vertirite broker.

Plugins are JSON manifests that declare commands and quick-match patterns.
They are loaded from a directory on startup and exposed through the
control-plane API for listing/inspection. The publishable broker does NOT
execute plugin commands — it authorizes, records, and audits; executing an
approved command is the integrating system's responsibility.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("maestro.plugins")

# ---------------------------------------------------------------------------
# Internal registry
# ---------------------------------------------------------------------------

_plugins: Dict[str, Dict[str, Any]] = {}  # keyed by plugin name


def load_plugins(plugin_dir: str | Path | None = None) -> int:
    """Scan *plugin_dir* for JSON plugin manifests and register each one.

    Returns the number of plugins successfully loaded.
    """
    if plugin_dir is None:
        plugin_dir = Path(__file__).resolve().parent.parent / "plugins"
    else:
        plugin_dir = Path(plugin_dir)

    if not plugin_dir.is_dir():
        logger.warning("Plugin directory does not exist: %s", plugin_dir)
        return 0

    count = 0
    for manifest_path in sorted(plugin_dir.glob("*.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            register_plugin(manifest)
            count += 1
            logger.info(
                "Loaded plugin '%s' v%s (%d commands)",
                manifest.get("name", manifest_path.stem),
                manifest.get("version", "0.0.0"),
                len(manifest.get("commands", [])),
            )
        except Exception as exc:
            logger.error("Failed to load plugin %s: %s", manifest_path.name, exc)

    logger.info("Plugin loader finished: %d plugin(s) loaded from %s", count, plugin_dir)
    return count


def register_plugin(manifest: Dict[str, Any]) -> None:
    """Register a single plugin manifest into the global registry.

    Required manifest keys: ``name``, ``version``, ``commands``.
    """
    name = manifest.get("name")
    if not name:
        raise ValueError("Plugin manifest missing required 'name' field")
    if not manifest.get("commands"):
        raise ValueError(f"Plugin '{name}' has no commands defined")

    # Index commands by name for fast lookup
    cmd_index: Dict[str, Dict[str, Any]] = {}
    for cmd in manifest["commands"]:
        cmd_name = cmd.get("name")
        if not cmd_name:
            logger.warning("Plugin '%s' has a command without a name — skipping", name)
            continue
        cmd_index[cmd_name] = cmd

    _plugins[name] = {
        "manifest": manifest,
        "commands": cmd_index,
    }


def get_all_plugins() -> List[Dict[str, Any]]:
    """Return a list of all loaded plugin manifests (safe for JSON serialisation)."""
    return [entry["manifest"] for entry in _plugins.values()]


def get_plugin(name: str) -> Optional[Dict[str, Any]]:
    """Return a single plugin manifest by name, or ``None``."""
    entry = _plugins.get(name)
    return entry["manifest"] if entry else None


def get_plugin_commands() -> List[Dict[str, Any]]:
    """Return a flat list of every command across all loaded plugins.

    Each dict includes the owning plugin name under ``plugin``.
    """
    all_cmds: List[Dict[str, Any]] = []
    for name, entry in _plugins.items():
        for cmd in entry["commands"].values():
            all_cmds.append({**cmd, "plugin": name})
    return all_cmds


# NOTE: The publishable broker deliberately has no plugin *execution* path.
# The registry above (load/list/inspect) is the entire plugin surface a
# governance control plane needs. Executing an approved plugin command is
# the integrating system's responsibility.
