# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Tiny smoke test for peer_stream — runs against a live broker.
Run from the broker host: python3 peer_stream_test.py"""
import json
import os
import sys
import time
import urllib.request

BROKER_URL = os.environ.get("BROKER_URL", "http://127.0.0.1:8220")
PEER_TOKEN = os.environ.get("SURGE_OPERATOR_BRAIN_PEER_TOKEN", "")
USER_TOKEN = os.environ.get("USER_BEARER_TOKEN", "")


def post_unprompted():
    if not PEER_TOKEN:
        print("set SURGE_OPERATOR_BRAIN_PEER_TOKEN")
        sys.exit(2)
    body = {
        "user_id": os.environ.get("TEST_USER", "operator"),
        "tenant_id": "creator",
        "content": f"Test unprompted message — {time.strftime('%H:%M:%S')}",
        "trigger_kind": "manual",
    }
    req = urllib.request.Request(
        f"{BROKER_URL}/v1/peer-stream/post",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {PEER_TOKEN}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        print("post:", r.status, json.loads(r.read()))


def listen_briefly():
    if not USER_TOKEN:
        print("set USER_BEARER_TOKEN to listen")
        return
    req = urllib.request.Request(
        f"{BROKER_URL}/v1/peer-stream",
        headers={"Authorization": f"Bearer {USER_TOKEN}"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        print("listening for 8s...")
        deadline = time.time() + 8
        while time.time() < deadline:
            line = r.readline().decode().strip()
            if line:
                print("  recv:", line)


if __name__ == "__main__":
    if "post" in sys.argv:
        post_unprompted()
    elif "listen" in sys.argv:
        listen_briefly()
    else:
        post_unprompted()
        listen_briefly()
