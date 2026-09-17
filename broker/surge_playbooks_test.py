# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Regression tests for the playbook front-matter loader.

The org-wide "All Rights Reserved" commit prepended an HTML copyright comment
to every ``.md`` file, including the playbook fixtures. The loader required the
file to *start* with ``---``, so the comment silently hid every playbook's
``name``/``intent_keywords`` — which is why agent-node-day's two
``surge_invoke`` intent-match events regressed to 0/1. These lock the fix.
"""
from broker import surge_playbooks as sp

COPYRIGHT = ("<!-- Copyright © 2026 SurgeXi Business Intelligence, "
             "a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE. -->\n")

PB = """---
name: check-fleet-health
intent_keywords:
  - "fleet health"
  - "check fleet"
required_capabilities:
  - fleet_ssh
---
# Check fleet health
Body text.
"""


def test_plain_front_matter_still_parses():
    meta, body = sp._front_matter_split(PB)
    assert meta["name"] == "check-fleet-health"
    assert "fleet health" in meta["intent_keywords"]
    assert "Check fleet health" in body


def test_copyright_header_does_not_hide_front_matter():
    meta, body = sp._front_matter_split(COPYRIGHT + PB)
    assert meta.get("name") == "check-fleet-health"
    assert "fleet health" in meta.get("intent_keywords", [])
    assert "Check fleet health" in body


def test_multiple_leading_comments_and_blank_lines():
    noisy = "\n<!-- one -->\n\n<!-- two -->\n" + PB
    meta, _ = sp._front_matter_split(noisy)
    assert meta.get("name") == "check-fleet-health"


def test_no_front_matter_returns_empty_meta():
    meta, body = sp._front_matter_split("just some text\n")
    assert meta == {}
    assert "just some text" in body
