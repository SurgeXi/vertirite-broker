# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Web console — drift guard + asset integrity + static serving.

The broker serves the operator UI at /console (docs/DEPLOY-CUSTOMER-NODE.md). The
shared assets (app.js, styles.css) are copied from apps/desktop/renderer by
scripts/sync-webconsole.sh; these tests fail if they drift, so the desktop app
and the browser console can never diverge silently.
"""
import os

import pytest

_HERE = os.path.dirname(__file__)
_WEBCONSOLE = os.path.join(_HERE, "webconsole")
_RENDERER = os.path.normpath(os.path.join(_HERE, "..", "..", "desktop", "renderer"))


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


@pytest.mark.parametrize("asset", ["app.js", "styles.css"])
def test_shared_asset_in_sync_with_renderer(asset):
    """The served copy must byte-match the canonical desktop renderer."""
    served = os.path.join(_WEBCONSOLE, asset)
    canonical = os.path.join(_RENDERER, asset)
    assert os.path.isfile(served), f"missing served asset: {asset}"
    if not os.path.isfile(canonical):
        pytest.skip("desktop renderer not present in this checkout")
    assert _read(served) == _read(canonical), (
        f"{asset} drifted from apps/desktop/renderer — run scripts/sync-webconsole.sh"
    )


def test_required_assets_present():
    for f in ("index.html", "web-bridge.js", "web.css", "manifest.webmanifest",
              "icon-192.png", "icon-512.png"):
        assert os.path.isfile(os.path.join(_WEBCONSOLE, f)), f"missing web asset: {f}"


def test_index_loads_bridge_before_app():
    html = _read(os.path.join(_WEBCONSOLE, "index.html")).decode("utf-8")
    bridge_tag = '<script src="./web-bridge.js">'
    app_tag = '<script src="./app.js">'
    assert bridge_tag in html and app_tag in html
    # the bridge must define window.surgeDesktop before app.js consumes it
    assert html.index(bridge_tag) < html.index(app_tag)
    assert "manifest.webmanifest" in html  # PWA installable on tablets


def test_web_bridge_is_electron_safe_and_complete():
    js = _read(os.path.join(_WEBCONSOLE, "web-bridge.js")).decode("utf-8")
    # no-op under Electron (preload already provided the bridge)
    assert "if (window.surgeDesktop) return;" in js
    assert "window.surgeDesktop =" in js
    # the core governance reads the views depend on must be present
    for method in ("getBrokerHealth", "getCoverage", "getLicense",
                   "getProtection", "getApprovals", "getAuditEvents"):
        assert method in js, f"web bridge missing {method}"


def test_main_mounts_console():
    main_src = _read(os.path.join(_HERE, "main.py")).decode("utf-8")
    assert 'app.mount("/console"' in main_src
    assert "StaticFiles(directory=_webconsole_dir, html=True)" in main_src


def test_staticfiles_serves_console_index():
    """StaticFiles(html=True) serves index.html at /console/ — proven against the
    real asset dir without importing the heavy broker app."""
    pytest.importorskip("httpx")
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    from fastapi.testclient import TestClient

    probe = FastAPI()
    probe.mount("/console", StaticFiles(directory=_WEBCONSOLE, html=True), name="console")
    client = TestClient(probe)

    r = client.get("/console/")
    assert r.status_code == 200
    assert "VERTI" in r.text and "RITE" in r.text

    for asset in ("web-bridge.js", "app.js", "web.css", "manifest.webmanifest"):
        assert client.get(f"/console/{asset}").status_code == 200
