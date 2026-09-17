<!-- Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE. -->
# Vertirite Broker

> **Control plane for AI agents.** Every AI action authenticated, classified by
> risk, gated through policy, optionally held for human approval, and recorded
> in a cryptographically attributable audit trail.

This is the open-source (BSL 1.1) broker at the core of Vertirite. It runs on
the customer's own node; their data never leaves. It is a Python / FastAPI
service providing:

- sessions, per-tenant project context, and capability registry
- deterministic **containment** (govern by the chokepoint an action crosses —
  egress / irreversible / credential — not by tool name)
- **discovery**: coverage map, exposure report, witnessed-finding intake, network sensors
- **compliance** report packs and framework controls
- **licensing** / entitlements (governance is always free; premium modules are gated)
- an **approval queue** (local, fail-open) with a signed **audit** trail
- **local mode authority** (`/v1/mode`) with an optional tighten-only upstream client

> This broker is extracted from the SurgeXi monorepo with all fleet-operations
> tooling removed (SSH/exec/filesystem operator surface, agent executor,
> self-heal, tunnel, node orchestration), contains no model, and is
> record-only. It boots and serves the full governance surface standalone.

## Design invariants: authorizes, does not execute — and contains no model

- **The broker records and audits decisions; it does not execute them.**
  Approving a request records the decision (actor, notes, timestamp) and writes a
  signed audit event — it does not run the action. Executing an approved action is
  the integrating system's responsibility. There is no node-exec, shell, SSH,
  terminal, or filesystem operator surface in this tree.
- **The broker contains no model and calls none on its own behalf.** No local
  model, no inference SDK, no gateway/RAG reach. Bring-your-own-cloud is *governed
  passthrough* only: point an app's SDK `base_url` at `/v1/proxy/openai/v1` and the
  broker gates → audits → forwards the call the customer's own agent makes to the
  customer's own provider. `/v1/keys/{provider}/test` validates a customer's own
  key (a non-generating GET); `/v1/models` is a static provider catalog. The broker
  governs the calls; it does not make them.
- These invariants are enforced at build time by `broker/import_guard_test.py`
  (model + model-reach + exec + topology) — a regression fails CI.

## Outbound network calls

The default posture is **Sovereign / no phone-home**: out of the box the broker
makes **no outbound calls**, and in particular **none to SurgeXi**. Every outbound
path below is off by default and is turned on, and pointed, by the operator — the
broker never calls a destination the operator did not configure.

| Destination | When | Default | Configured by | What is sent |
|---|---|---|---|---|
| **Any SurgeXi-operated endpoint** | **never** | — | — | **nothing — the broker does not phone home** |
| Your own `surge-core` governor (optional upstream) | mode read-through / approval forward, if enabled | loopback (`127.0.0.1`); forwarding **off** | `SURGE_OPERATOR_SURGE_CORE_URL`, `…_FORWARD_APPROVALS_TO_SURGE_CORE` | governance state (mode, approval decision) |
| Your own cloud provider, via `/v1/proxy/openai` | when *your* agent calls the governed passthrough | disabled unless enabled | `SURGE_OPERATOR_PROXY_*` (your BYO key) | your agent's own request, forwarded |
| A provider's model-list endpoint, via `/v1/keys/{provider}/test` | operator validates a BYO key | on-demand only | operator action (your key) | nothing — a non-generating auth check |
| Your own alert channel (e.g. Pushover) | on an alert, if enabled | **off** | `SURGE_OPERATOR_ALERT_*` | alert text |
| A coverage **beacon** / intelligence feed | periodic, if a URL is set | **empty = disabled** | `SURGE_OPERATOR_PROTECTION_BEACON_URL`, `…_INTELLIGENCE_FEED_URL` | coverage counts (you choose the destination) |

There is no telemetry, license-server call, or hardcoded remote in the tree — the
beacon has no default URL, so it is dark until you point it somewhere you control.

## Local setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install .
cp .env.example .env   # then edit
SURGE_OPERATOR_DATABASE_URL="sqlite+pysqlite:////absolute/path/to/broker.db" \
SURGE_OPERATOR_BROKER_API_TOKEN="change-me-broker-token" \
  python -m uvicorn broker.main:app --host 127.0.0.1 --port 8220
```

## Governance endpoints (selected)

- `GET  /health`, `GET /v1/me`, `GET /v1/entitlements`
- `GET  /v1/mode`, `POST /v1/mode` (governor-credential gated)
- `GET  /v1/discovery/coverage`, `GET /v1/discovery/exposure.json|.pdf`
- `POST /v1/discovery/ingest/egress|dns|flow`, `POST /v1/agent/witnessed`
- `POST /v1/containment/classify`, `GET /v1/integrity/*`
- `GET  /v1/compliance/pack|report|controls`
- `GET  /v1/approvals`, `POST /v1/approvals/{id}/approve|deny`
- `GET  /v1/audit/me`, `GET /v1/audit-events`

All `/v1/*` endpoints require `Authorization: Bearer <token>`.

## Provisioning visibility (fail-loud defaults)

The broker never *silently* looks healthy when it is running on defaults:

- **`governed`** (in `/v1/entitlements`): `false` until a governor credential
  (`SURGE_OPERATOR_GOVERNOR_TOKEN`) is provisioned — `POST /v1/mode` returns 503 until then.
- **`context_source`** (in `/v1/entitlements`): `"fixtures"` until
  `SURGE_OPERATOR_CONTEXT_DIR` points at a host-local directory of real `*.md`
  context files; a startup WARNING is logged while serving fixtures. See `context/README.md`.

Approval forwarding is opt-in (`SURGE_OPERATOR_FORWARD_APPROVALS_TO_SURGE_CORE=false`
by default); when enabled, guarded requests also submit a task to the upstream core.

## Migrations

PostgreSQL is the target runtime database; local validation runs on SQLite.

```bash
env SURGE_OPERATOR_DATABASE_URL="sqlite+pysqlite:////absolute/path/to/broker.db" \
  .venv/bin/alembic upgrade head
```

## Known limitations

Called out plainly so a reader isn't surprised:

- **The approval queue has no built-in intake route in this cut.** `GET /v1/approvals`
  and `POST /v1/approvals/{id}/approve|deny` are the record-only decision surface,
  but this extracted broker does not itself create approvals — the integrating
  system is expected to populate the queue. A first-party intake path is planned.
- **The bundled console's "capabilities" tab is inert here.** It targeted the
  surge agent-tasking surface, which is not part of this governance-only broker;
  the tab degrades gracefully to "unavailable." The live governance flow is
  discovery → containment classify → govern → audit.
- **BYO-cloud is passthrough only.** The broker validates and governs calls to a
  provider you configure with your own key; it ships with no model and no provider
  credentials of its own.

## License

Business Source License 1.1 — see `LICENSE`. Converts to Apache 2.0 on the Change Date.
