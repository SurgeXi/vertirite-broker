# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Playbook loader. Reads Markdown playbooks from
/etc/vertirite/playbooks/ (canonical) or a fallback dev path,
parses their YAML front-matter, and exposes match() / get() / index()
for the invoke layer.

Why no PyYAML dependency: front-matter parsing is small enough to do
by hand and we keep the broker's runtime deps unchanged.
"""
from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("maestro.surge_playbooks")

# Search order. First existing directory wins.
def _repo_relative_fallback() -> Path | None:
    """Repo-relative playbooks checkout (dev only). The container layout
    is too shallow for `parents[3]` to work, so we guard it. Returns None
    inside the container."""
    try:
        return Path(__file__).resolve().parents[3] / "vertirite" / "config" / "playbooks"
    except IndexError:
        return None


PLAYBOOK_DIRS: list[Path] = [
    Path(os.environ.get("SURGE_PLAYBOOKS_DIR", "/etc/vertirite/playbooks")),
    # Dev / scenario fallback — playbooks checkout next to the broker
    Path("/tmp/vertirite/playbooks"),
]
_repo_fallback = _repo_relative_fallback()
if _repo_fallback is not None:
    PLAYBOOK_DIRS.append(_repo_fallback)

_RELOAD_MIN_INTERVAL_S = 5  # don't re-stat the dir more than once / 5s
_cache: dict[str, Any] = {"loaded_at": 0.0, "playbooks": {}, "dir": None}


def _skip_leading_noise(text: str) -> str:
    """Drop leading blank lines and ``<!-- ... -->`` HTML comment blocks so a
    copyright/license header above the front matter does not hide it."""
    s = text.lstrip()
    while s.startswith("<!--"):
        close = s.find("-->")
        if close < 0:
            break
        s = s[close + 3:].lstrip()
    return s


def _front_matter_split(text: str) -> tuple[dict, str]:
    """Returns (metadata, body). Metadata is parsed from a leading
    `---\\n...\\n---\\n` block; body is everything after."""
    text = _skip_leading_noise(text)
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    raw = text[3:end].strip()
    body = text[end + 4:].lstrip("\n")
    meta = _parse_front_matter(raw)
    return meta, body


_KV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$")
_LIST_ITEM_RE = re.compile(r"^\s*-\s+(.+)$")


def _parse_front_matter(raw: str) -> dict:
    """A small-but-careful subset of YAML: scalars, single-line scalars,
    multi-line list-of-strings (`- item`). No nested maps."""
    out: dict[str, Any] = {}
    current_key: Optional[str] = None
    current_list: list[str] = []
    for line in raw.splitlines():
        if not line.strip():
            current_key = None
            continue
        m = _LIST_ITEM_RE.match(line)
        if m and current_key:
            current_list.append(_strip_quotes(m.group(1)))
            out[current_key] = current_list
            continue
        m = _KV_RE.match(line)
        if not m:
            continue
        key = m.group(1).strip()
        val_raw = m.group(2).strip()
        if val_raw == "":
            current_key = key
            current_list = []
            out[key] = current_list
            continue
        # scalar
        out[key] = _coerce_scalar(_strip_quotes(val_raw))
        current_key = None
        current_list = []
    return out


def _strip_quotes(s: str) -> str:
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    return s


def _coerce_scalar(s: str) -> Any:
    sl = s.lower()
    if sl in ("true", "yes"): return True
    if sl in ("false", "no"): return False
    if sl in ("null", "~", ""): return None
    if s.lstrip("-").isdigit():
        try:
            return int(s)
        except ValueError:
            return s
    return s


def _resolve_dir() -> Optional[Path]:
    for d in PLAYBOOK_DIRS:
        if d.is_dir():
            return d
    return None


def _load_all() -> dict[str, dict]:
    """Refresh the cache. Returns {playbook_name: parsed_dict}."""
    d = _resolve_dir()
    out: dict[str, dict] = {}
    if d is None:
        log.info("no playbook dir found in any of %s", [str(x) for x in PLAYBOOK_DIRS])
        return out
    for p in sorted(d.glob("*.md")):
        if p.name.lower() == "readme.md":
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except Exception as e:
            log.warning("playbook %s unreadable: %s", p, e)
            continue
        meta, body = _front_matter_split(text)
        name = str(meta.get("name") or p.stem)
        keywords = meta.get("intent_keywords") or []
        if isinstance(keywords, str):
            keywords = [keywords]
        out[name] = {
            "name": name,
            "path": str(p),
            "approval_class": meta.get("approval_class", "gated"),
            "intent_keywords": [k.lower() for k in keywords if isinstance(k, str)],
            "required_capabilities": meta.get("required_capabilities") or [],
            "tags": meta.get("tags") or [],
            "disabled": bool(meta.get("disabled", False)),
            "description": _first_paragraph(body),
            "body": body,
        }
    return out


def _first_paragraph(body: str) -> str:
    # Skip the leading H1 if present, then take everything up to the next blank line
    lines = []
    seen_content = False
    for line in body.splitlines():
        s = line.strip()
        if not seen_content and (s.startswith("# ") or s == ""):
            continue
        if s == "":
            if seen_content:
                break
            continue
        seen_content = True
        lines.append(s)
    return " ".join(lines)[:400]


def _maybe_refresh() -> None:
    now = time.time()
    if now - _cache["loaded_at"] < _RELOAD_MIN_INTERVAL_S and _cache["playbooks"]:
        return
    _cache["playbooks"] = _load_all()
    _cache["loaded_at"] = now
    _cache["dir"] = str(_resolve_dir())


def index() -> list[dict]:
    """Public: return a stripped list of playbooks for the products SDK."""
    _maybe_refresh()
    return [
        {k: v for k, v in p.items() if k != "body"}
        for p in _cache["playbooks"].values()
        if not p.get("disabled")
    ]


def get(name: str) -> Optional[dict]:
    _maybe_refresh()
    return _cache["playbooks"].get(name)


def match(intent: str) -> Optional[dict]:
    """Substring-match on intent_keywords. Returns the playbook dict
    plus a `matched_keyword` field, or None if no match."""
    _maybe_refresh()
    low = intent.lower()
    for pb in _cache["playbooks"].values():
        if pb.get("disabled"):
            continue
        for kw in pb.get("intent_keywords", []):
            if kw and kw in low:
                out = dict(pb)
                out["matched_keyword"] = kw
                return out
    return None
