# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""vertirite-intel — mint + sign perishable intelligence catalogs.

SurgeXi-INTERNAL operator tooling for Mechanism #1 (docs/PROTECTION-MODEL.md).
The private mint key produced/used here NEVER ships to a broker.

    vertirite-intel keygen  --out-dir ./mint-keys
    vertirite-intel pubkey  --private mint-keys/private.pem
    vertirite-intel mint    --patterns patterns.json --version 3 \
                            --private mint-keys/private.pem --valid-days 30 \
                            --out catalog-v3.json
    vertirite-intel verify  --bundle catalog-v3.json --public mint-keys/public.pem

Deliver the signed catalog to a broker via POST /v1/intelligence/catalog/install
(Sovereign / air-gap path) or, later, the Connected auto-pull feed (PR3).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from . import mint as mintlib
from . import signing


def _keygen(args) -> int:
    priv_pem, pub_pem = mintlib.generate_keypair()
    os.makedirs(args.out_dir, exist_ok=True)
    priv_path = os.path.join(args.out_dir, "private.pem")
    pub_path = os.path.join(args.out_dir, "public.pem")
    # Private key 0600 — KEEP SECRET, never ship.
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(priv_pem)
    with open(pub_path, "w") as f:
        f.write(pub_pem)
    print(f"wrote {priv_path}  (0600 — KEEP SECRET, never ship to a broker)")
    print(f"wrote {pub_path}   (embed in broker SURGE_OPERATOR_INTELLIGENCE_PUBLIC_KEY)")
    return 0


def _mint(args) -> int:
    with open(args.patterns) as f:
        patterns = json.load(f)
    if not isinstance(patterns, list):
        print("ERROR: --patterns must be a JSON list of pattern objects", file=sys.stderr)
        return 2
    with open(args.private) as f:
        priv = mintlib.load_private_key(f.read())
    bundle = mintlib.mint(
        patterns=patterns, catalog_version=args.version, private_key=priv,
        valid_days=args.valid_days, tenant_scope=args.tenant_scope,
    )
    out = json.dumps(bundle, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out)
        print(f"signed catalog v{args.version} ({len(patterns)} patterns, "
              f"valid {args.valid_days}d) -> {args.out}")
    else:
        print(out)
    return 0


def _verify(args) -> int:
    with open(args.bundle) as f:
        bundle = json.load(f)
    with open(args.public) as f:
        key = serialization.load_pem_public_key(f.read().encode())
    try:
        key.verify(bytes.fromhex(bundle.get("signature", "")), signing.canonical_bytes(bundle))
        print("VALID")
        return 0
    except (InvalidSignature, ValueError):
        print("INVALID")
        return 1


def _pubkey(args) -> int:
    with open(args.private) as f:
        priv = mintlib.load_private_key(f.read())
    print(signing.load_public_pem(priv.public_key()))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="vertirite-intel",
        description="Mint + sign perishable intelligence catalogs (SurgeXi-internal).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate an Ed25519 mint keypair")
    g.add_argument("--out-dir", default="./mint-keys")
    g.set_defaults(fn=_keygen)

    m = sub.add_parser("mint", help="build + sign a catalog bundle")
    m.add_argument("--patterns", required=True, help="JSON list of pattern objects")
    m.add_argument("--version", type=int, required=True, help="catalog_version (must increase)")
    m.add_argument("--private", required=True, help="mint private key PEM")
    m.add_argument("--valid-days", type=int, default=30)
    m.add_argument("--tenant-scope", default="*")
    m.add_argument("--out", default=None, help="write bundle here (default: stdout)")
    m.set_defaults(fn=_mint)

    v = sub.add_parser("verify", help="verify a bundle against a public key")
    v.add_argument("--bundle", required=True)
    v.add_argument("--public", required=True)
    v.set_defaults(fn=_verify)

    k = sub.add_parser("pubkey", help="print the public key for a private key")
    k.add_argument("--private", required=True)
    k.set_defaults(fn=_pubkey)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
