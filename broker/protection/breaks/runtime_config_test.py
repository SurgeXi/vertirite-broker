# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Runtime feature-flag override — DB override wins over env; cache invalidates."""
import os
import tempfile

_db_fd, _db_path = tempfile.mkstemp(suffix="-runtime-flags.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from broker.protection.breaks import runtime_config as rc  # noqa: E402


def _schema():
    from broker.db import Base, engine, init_db
    init_db(); Base.metadata.create_all(bind=engine)


_schema()


def test_env_fallback_when_no_override(monkeypatch):
    monkeypatch.setenv("VERTIRITE_BREAK_DETECTION", "0")
    rc._CACHE.clear()
    assert rc.effective("break_detection") is False
    monkeypatch.setenv("VERTIRITE_BREAK_DETECTION", "1")
    rc._CACHE.clear()
    assert rc.effective("break_detection") is True


def test_override_wins_and_takes_effect_immediately(monkeypatch):
    monkeypatch.setenv("VERTIRITE_DETECT_CONTAIN", "0")   # env says off
    rc._CACHE.clear()
    assert rc.effective("detect_contain") is False
    rc.set_flag("detect_contain", True, actor="op")        # override on
    assert rc.effective("detect_contain") is True          # cache was invalidated
    rc.set_flag("detect_contain", False, actor="op")       # override off (even though env off)
    assert rc.effective("detect_contain") is False


def test_status_reports_source(monkeypatch):
    monkeypatch.setenv("VERTIRITE_BREAK_DETECTION", "0")
    rc._CACHE.clear()
    rc.set_flag("break_detection", True, actor="op")
    st = rc.status()
    assert st["break_detection"]["enabled"] is True
    assert st["break_detection"]["source"] == "override"
    assert st["break_detection"]["env_default"] is False


def test_unknown_flag_rejected():
    import pytest
    with pytest.raises(ValueError):
        rc.set_flag("nope", True, actor="op")
