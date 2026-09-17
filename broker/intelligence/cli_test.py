# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""The vertirite-intel operator workflow: keygen → mint → verify (round-trip)."""
import json

import broker.intelligence.cli as cli


def test_keygen_mint_verify_workflow(tmp_path):
    keys = tmp_path / "mint-keys"
    assert cli.main(["keygen", "--out-dir", str(keys)]) == 0
    assert (keys / "private.pem").exists()
    assert (keys / "public.pem").exists()
    # private key is 0600
    assert oct((keys / "private.pem").stat().st_mode)[-3:] == "600"

    patterns = tmp_path / "patterns.json"
    patterns.write_text(json.dumps([{
        "pattern_id": "premium-x", "name": "X", "signal_type": "network",
        "match": {"host_re": "x"}, "confidence": "high",
        "category": "service-endpoint", "remediation": "y",
    }]))
    bundle = tmp_path / "cat.json"
    assert cli.main(["mint", "--patterns", str(patterns), "--version", "2",
                     "--private", str(keys / "private.pem"), "--out", str(bundle)]) == 0

    signed = json.loads(bundle.read_text())
    assert signed["catalog_version"] == 2 and "signature" in signed

    # verify against the matching public key → VALID (exit 0)
    assert cli.main(["verify", "--bundle", str(bundle), "--public", str(keys / "public.pem")]) == 0


def test_verify_rejects_wrong_key(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    cli.main(["keygen", "--out-dir", str(a)])
    cli.main(["keygen", "--out-dir", str(b)])
    patterns = tmp_path / "p.json"
    patterns.write_text("[]")
    bundle = tmp_path / "cat.json"
    cli.main(["mint", "--patterns", str(patterns), "--version", "1",
              "--private", str(a / "private.pem"), "--out", str(bundle)])
    # verify with B's public key → INVALID (exit 1)
    assert cli.main(["verify", "--bundle", str(bundle), "--public", str(b / "public.pem")]) == 1
