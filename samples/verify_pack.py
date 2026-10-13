#!/usr/bin/env python3
# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company.
"""Verify a Vertirite compliance evidence pack, standalone (no Vertirite code needed).

  python3 verify_pack.py compliance-pack-soc2.sample.json
  python3 verify_pack.py <sealed-report.json> <node-public-key.pem>   # a report from a node with a signing key

1. Fingerprint: sha256 of the pack's canonical JSON (sorted keys, separators "," and ":"),
   computed over every field except "fingerprint", "seal" and "signature". A changed byte in the
   evidence changes the fingerprint.
2. Seal (when present): an Ed25519 signature over the canonical JSON of every field except
   "signature", checked with the node's public key. Needs: pip install cryptography.

What this does and does not prove: the fingerprint shows the pack was not altered after it was
generated; the seal shows which node generated it. Neither proves the underlying audit log was
complete. Hash-chained, signed audit records are in progress and not shipped.
"""
import hashlib
import json
import sys


def canonical(obj, drop):
    body = {k: v for k, v in obj.items() if k not in drop}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


pack = json.load(open(sys.argv[1]))
fp = hashlib.sha256(canonical(pack, {"fingerprint", "seal", "signature"})).hexdigest()
ok_fp = fp == pack.get("fingerprint")
print(f"fingerprint: {'OK' if ok_fp else 'MISMATCH'} ({fp})")
ok_sig = True
if "signature" in pack:
    if len(sys.argv) < 3:
        sys.exit("sealed pack: pass the node public key (PEM) as the second argument")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_public_key(open(sys.argv[2], "rb").read())
    try:
        key.verify(bytes.fromhex(pack["signature"]), canonical(pack, {"signature"}))
        print("seal: OK (Ed25519)")
    except (InvalidSignature, ValueError):
        ok_sig = False
        print("seal: INVALID")
sys.exit(0 if ok_fp and ok_sig else 1)
