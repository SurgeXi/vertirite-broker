# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""vertirite-license — mint + sign Vertirite licenses (SurgeXi-INTERNAL).

    vertirite-license keygen --out-dir ./license-keys
    vertirite-license mint --customer "Acme Health" --sku connected \
        --features intelligence,enforcement,federation --valid-days 365 \
        --private license-keys/private.pem --out acme.license.json
    vertirite-license verify --license acme.license.json --public license-keys/public.pem
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from ..intelligence.signing import canonical_bytes
from . import mint as mintlib


def _keygen(args) -> int:
    priv_pem, pub_pem = mintlib.generate_keypair()
    os.makedirs(args.out_dir, exist_ok=True)
    priv_path = os.path.join(args.out_dir, "private.pem")
    pub_path = os.path.join(args.out_dir, "public.pem")
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(priv_pem)
    with open(pub_path, "w") as f:
        f.write(pub_pem)
    print(f"wrote {priv_path}  (0600 — KEEP SECRET, never ship to a broker)")
    print(f"wrote {pub_path}   (embed in broker SURGE_OPERATOR_LICENSE_PUBLIC_KEY)")
    return 0


def _mint(args) -> int:
    from .skus import features_for_sku
    with open(args.private) as f:
        priv = mintlib.load_private_key(f.read())
    # explicit --features override the SKU's default bundle.
    features = ([s.strip() for s in args.features.split(",") if s.strip()]
                if args.features else features_for_sku(args.sku))
    lic = mintlib.mint(customer=args.customer, sku=args.sku, features=features,
                       valid_days=args.valid_days, private_key=priv)
    out = json.dumps(lic, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out)
        print(f"signed license for {args.customer} ({args.sku}, {args.valid_days}d, "
              f"features={features}) -> {args.out}")
    else:
        print(out)
    return 0


def _verify(args) -> int:
    with open(args.license) as f:
        lic = json.load(f)
    with open(args.public) as f:
        key = serialization.load_pem_public_key(f.read().encode())
    try:
        key.verify(bytes.fromhex(lic.get("signature", "")), canonical_bytes(lic))
        print("VALID")
        return 0
    except (InvalidSignature, ValueError):
        print("INVALID")
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="vertirite-license",
                                description="Mint + sign Vertirite licenses (SurgeXi-internal).")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate an Ed25519 license keypair")
    g.add_argument("--out-dir", default="./license-keys")
    g.set_defaults(fn=_keygen)

    m = sub.add_parser("mint", help="mint a signed license")
    m.add_argument("--customer", required=True)
    m.add_argument("--sku", required=True)
    m.add_argument("--features", default="", help="csv of granted features")
    m.add_argument("--valid-days", type=int, required=True)
    m.add_argument("--private", required=True)
    m.add_argument("--out", default=None)
    m.set_defaults(fn=_mint)

    v = sub.add_parser("verify", help="verify a license against a public key")
    v.add_argument("--license", required=True)
    v.add_argument("--public", required=True)
    v.set_defaults(fn=_verify)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
