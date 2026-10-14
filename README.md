<!-- Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. -->
# Vertirite

> **Control plane for AI agents.** Every AI action authenticated, classified by risk, gated
> through policy, held for a human when it matters, and recorded in an audit trail.

Vertirite runs on your own node. Your data never leaves it. The control plane contains no model
and calls none: it authorizes and records; it does not execute.

This public repository shows Vertirite's architecture, documentation and SDK, with a sample of
the evidence an auditor receives. Pilot customers' security teams review the full source under
NDA.

## What it does

- **Discovery:** finds the AI and automation already touching your systems and maps coverage:
  what is governed, what is not, and what an ungoverned caller can reach.
- **Approval gate:** an action that can hurt you waits for a person. The request is announced
  (console, email, chat webhook), re-announced while unanswered, and **denied at its deadline**.
  The safe default is always "no", and it is not configurable.
- **Containment:** governed by the chokepoint an action crosses (egress, irreversible change,
  credential use), not by tool name.
- **Mode authority:** AUTONOMOUS / CONTROLLED / ESCALATION_REQUIRED / LOCKDOWN, set out of band.
  The AI cannot change its own mode.
- **Audit:** every approval request and decision is recorded: who asked, who decided, what,
  when, and under which mode. Evidence packs map that record to SOC 2 and HIPAA controls.

## What is true today, and what is not yet

| | |
|---|---|
| Audit records | Every request and decision recorded with the authenticated actor, the action and the time. |
| Evidence pack | Carries a sha256 fingerprint of its contents, so any later change to the pack is detectable. See [`samples/`](samples/). |
| Compliance report seal | Ed25519 signature by the node, when the node has a signing key configured. No deployed node has one yet; until then reports carry the sha256 fingerprint only. |
| Tamper-evident audit log | **In progress, not shipped.** Audit rows are plain database records today. Hash-chained, signed rows and a verification tool for auditors are being built. |

## In this repository

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): how Vertirite is built and the invariants it
  keeps.
- [`docs/openapi-governance.json`](docs/openapi-governance.json): the governance API (approval
  gate, your audit feed, mode, health), generated from the product source.
- [`sdk/python/vertirite_client.py`](sdk/python/vertirite_client.py): a small client for that
  API: request an approval, wait for the decision, read your audit feed.
- [`samples/`](samples/): a sample SOC 2 evidence pack built by the product from synthetic data,
  and a standalone script that verifies its fingerprint (and a report seal, where one exists).

## Get Vertirite

Request a demo at [vertirite.com/demo](https://vertirite.com/demo). Evaluations, pilots and subscriptions:
[vertirite.com/pricing](https://vertirite.com/pricing).

## License

Copyright © 2026 Teamsmith Enterprises LLC, doing business as SurgeXi Business Intelligence. All rights reserved.

**Showcase content.** The documentation, architecture description, API description and samples in this repository are provided so you can understand and evaluate Vertirite. You may read them and link to them. No other rights are granted, and nothing here grants any right to use the Vertirite software, which is available only under the Vertirite Software License after an approved request at vertirite.com.

**Client library.** The client library in `sdk/` is licensed under the Apache License, Version 2.0, so you can use it to connect your own systems to a licensed Vertirite installation.

**Earlier versions.** Earlier commits in this repository's history were published under the Business Source License 1.1. Those grants continue to apply to those earlier versions only. They do not apply to anything published after October 13, 2026, to the Vertirite software we distribute today, or to any later version.
