# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Perishable intelligence catalog — Mechanism #1 of the Vertirite protection
model (docs/PROTECTION-MODEL.md, "the living organism, not the vault").

The discovery pattern catalog becomes a SIGNED, VERSIONED, DATED feed layered on
top of the open baseline (discovery/patterns.py). The premium layer DECAYS: past
its signed expiry + grace it drops out and the engine falls back to baseline-only
— a stolen/disconnected copy runs a frozen, rotting brain while the open broker
keeps working. The anti-theft mechanism and the #1 product feature (fresh
intelligence) are one build.

Submodules:
  * signing.py  — Ed25519 verify against SurgeXi's mint public key (broker never
                  signs; the private mint key lives off-box).
  * catalog.py  — bundle schema + freshness/anti-rollback decay + the
                  baseline+premium resolver.
  * store.py    — persistence (installed catalogs + the clock high-water-mark).
"""
from . import store  # noqa: F401 — registers ORM tables for init_db()
