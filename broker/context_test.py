# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company.
# Licensed under the Business Source License 1.1 — see LICENSE.
"""Context engine: fixture-vs-operational source detection.

Same silent-safe-default discipline as the ungoverned-mode flag — a broker
running on sanitized fixtures must SAY SO (context_source == "fixtures" + a
startup WARN), never look healthy on placeholder data.
"""
from __future__ import annotations

import logging
from pathlib import Path

from broker import context as ctx


def _reset(monkeypatch, override, shipped):
    monkeypatch.setattr(ctx, "_OVERRIDE", override)
    monkeypatch.setattr(ctx, "_SHIPPED_DIR", shipped)
    monkeypatch.setattr(ctx, "_cached_context", None)
    monkeypatch.setattr(ctx, "_context_source", "fixtures")


def test_shipped_fixtures_only_reports_fixtures(monkeypatch, tmp_path):
    """No override, only *.md.example present → source is 'fixtures'."""
    shipped = tmp_path / "context"
    shipped.mkdir()
    (shipped / "identity.md.example").write_text("# Fixture identity\nplaceholder")
    _reset(monkeypatch, None, shipped)

    text = ctx.load_context()
    assert "Fixture identity" in text          # fixtures ARE loaded (not empty)
    assert ctx.context_source() == "fixtures"  # ...but it says so


def test_host_local_override_reports_operational(monkeypatch, tmp_path):
    """Override dir with real *.md files → source is 'operational'."""
    shipped = tmp_path / "context"
    shipped.mkdir()
    (shipped / "identity.md.example").write_text("# Fixture identity\nplaceholder")
    real = tmp_path / "host-local"
    real.mkdir()
    (real / "identity.md").write_text("# Real identity\noperational")
    _reset(monkeypatch, str(real), shipped)

    text = ctx.load_context()
    assert "Real identity" in text
    assert "Fixture identity" not in text
    assert ctx.context_source() == "operational"


def test_override_set_but_empty_falls_back_to_fixtures(monkeypatch, tmp_path):
    """Override set but holds no *.md → not operational; back to fixtures."""
    shipped = tmp_path / "context"
    shipped.mkdir()
    (shipped / "identity.md.example").write_text("# Fixture identity\nplaceholder")
    empty = tmp_path / "empty"
    empty.mkdir()
    _reset(monkeypatch, str(empty), shipped)

    ctx.load_context()
    assert ctx.context_source() == "fixtures"


def test_warn_if_fixtures_logs_warning(monkeypatch, tmp_path, caplog):
    shipped = tmp_path / "context"
    shipped.mkdir()
    (shipped / "identity.md.example").write_text("# Fixture identity\nplaceholder")
    _reset(monkeypatch, None, shipped)

    with caplog.at_level(logging.WARNING, logger="vertirite.context"):
        ctx.warn_if_fixtures()
    assert any("sanitized fixtures" in r.message for r in caplog.records)


def test_warn_if_operational_is_silent(monkeypatch, tmp_path, caplog):
    shipped = tmp_path / "context"
    shipped.mkdir()
    real = tmp_path / "host-local"
    real.mkdir()
    (real / "identity.md").write_text("# Real identity\noperational")
    _reset(monkeypatch, str(real), shipped)

    with caplog.at_level(logging.WARNING, logger="vertirite.context"):
        ctx.warn_if_fixtures()
    assert not any("sanitized fixtures" in r.message for r in caplog.records)
