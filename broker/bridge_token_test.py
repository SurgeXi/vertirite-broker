# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The service-plane (bridge) token has no default, and the once-published default is
never accepted in production."""
from __future__ import annotations

import os
import tempfile

import pytest

_db_fd, _db_path = tempfile.mkstemp(suffix="-bridge.db")
os.close(_db_fd)
os.environ.setdefault("SURGE_OPERATOR_DATABASE_URL", f"sqlite+pysqlite:///{_db_path}")

from fastapi import HTTPException  # noqa: E402

from . import main  # noqa: E402
from .auth import require_bearer_token  # noqa: E402
from .config import settings  # noqa: E402

PUBLISHED = "surge-openwebui-bridge-token"


def test_no_bridge_role_by_default(monkeypatch):
    monkeypatch.setattr(settings, "bridge_api_token", "")
    assert type(settings)().bridge_api_token == ""            # the shipped default
    with pytest.raises(HTTPException) as e:
        require_bearer_token(f"Bearer {PUBLISHED}")
    assert e.value.status_code in (401, 403)
    with pytest.raises(HTTPException):
        require_bearer_token("Bearer ")                       # empty never matches empty


def test_configured_bridge_token_is_service(monkeypatch):
    monkeypatch.setattr(settings, "bridge_api_token", "bridge-token-fixture")
    assert require_bearer_token("Bearer bridge-token-fixture").role == "service"


def test_production_refuses_the_published_token(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "broker_api_token", "a-unique-admin-secret-0123456789")
    monkeypatch.setattr(settings, "bridge_api_token", PUBLISHED)
    with pytest.raises(RuntimeError, match="BRIDGE_API_TOKEN"):
        main._assert_admin_token_configured()
    monkeypatch.setattr(settings, "bridge_api_token", "")
    main._assert_admin_token_configured()                       # empty = bridge disabled = OK
