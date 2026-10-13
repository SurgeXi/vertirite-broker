<!-- Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. -->
# Vertirite architecture

Vertirite's control plane (the **broker**) is a Python / FastAPI service with PostgreSQL. It runs on
the customer's own node. Agents, bots and automations call it before an action; it classifies the
action, applies the mode and policy, holds it for a person when needed, and records the outcome.

## Design invariants: authorizes, does not execute — and contains no model

- **The broker records and audits decisions; it does not execute them.**
  Approving a request records the decision (actor, notes, timestamp) and writes an
  audit event — it does not run the action. Executing an approved action is
  the integrating system's responsibility. There is no node-exec, shell, SSH,
  terminal, or filesystem operator surface in the broker.
- **The broker contains no model and calls none on its own behalf.** No local
  model, no inference SDK, no gateway/RAG reach. Bring-your-own-cloud is *governed
  passthrough* only: point an app's SDK `base_url` at `/v1/proxy/openai/v1` and the
  broker gates → audits → forwards the call the customer's own agent makes to the
  customer's own provider. `/v1/keys/{provider}/test` validates a customer's own
  key (a non-generating GET); `/v1/models` is a static provider catalog. The broker
  governs the calls; it does not make them.
- These invariants are enforced by an import-guard test in the product's test suite
  (model, model-reach, exec and topology imports are refused).

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
| Your own alert channels: SMTP email, a webhook you own, Pushover | on an alert or an approval request / reminder / timeout, if enabled | **off** | `SURGE_OPERATOR_ALERT_*` | alert or approval text (summary, action name, approval id, deadline) |
| A coverage **beacon** / intelligence feed | periodic, if a URL is set | **empty = disabled** | `SURGE_OPERATOR_PROTECTION_BEACON_URL`, `…_INTELLIGENCE_FEED_URL` | coverage counts (you choose the destination) |

There is no telemetry, license-server call, or hardcoded remote in the broker — the
beacon has no default URL, so it is dark until you point it somewhere you control.

## Approval gate

`POST /v1/approvals` (`tool_name`, `summary`, optional `payload`, `timeout_s`) stores a
**pending** request and announces it on every alert channel the operator enabled. While it
waits it is re-announced every `SURGE_OPERATOR_APPROVAL_RENOTIFY_S` (default 900 s), at most
`…_APPROVAL_MAX_REMINDERS` times (default 3). At its deadline (`timeout_s`, default
`…_APPROVAL_TIMEOUT_S` = 3600 s, capped at `…_APPROVAL_TIMEOUT_MAX_S`) it is **denied**
automatically. That default is not configurable: an unanswered request is never approved.
Only a pending request can be decided, so a late answer cannot overturn a timeout or an
earlier decision (HTTP 409). Each step is audited: `approval.requested`, `approval.notified`
(with the channels that took it), `approval.approved` / `approval.denied` (with who decided),
and `approval.timeout_denied`. Set `…_APPROVAL_CONSOLE_URL` to your own console's address so
the notification says where to decide.

## Provisioning visibility (fail-loud defaults)

The broker never *silently* looks healthy when it is running on defaults:

- **`governed`** (in `/v1/entitlements`): `false` until a governor credential
  (`SURGE_OPERATOR_GOVERNOR_TOKEN`) is provisioned — `POST /v1/mode` returns 503 until then.
- **`context_source`** (in `/v1/entitlements`): `"fixtures"` until
  `SURGE_OPERATOR_CONTEXT_DIR` points at a host-local directory of real `*.md`
  context files; a startup WARNING is logged while serving fixtures. See `context/README.md`.

Approval forwarding is opt-in (`SURGE_OPERATOR_FORWARD_APPROVALS_TO_SURGE_CORE=false`
by default); when enabled, guarded requests also submit a task to the upstream core.

## Known limitations

Called out plainly so a reader isn't surprised:

- **Approvals are notified on the channels you configure on this broker:** the console,
  SMTP email, a webhook you own, and Pushover. There is no mobile push app yet. A
  phone-push companion is planned and is **not** a channel today.
- **The bundled console's "capabilities" tab is inert here.** It targeted the
  surge agent-tasking surface, which is not part of this governance-only broker;
  the tab degrades gracefully to "unavailable." The live governance flow is
  discovery → containment classify → govern → audit.
- **BYO-cloud is passthrough only.** The broker validates and governs calls to a
  provider you configure with your own key; it ships with no model and no provider
  credentials of its own.

## Audit integrity: today and next

Today every approval request and decision is an audit row with the authenticated actor, the action
and the time; evidence packs carry a sha256 fingerprint of their contents, and compliance reports
are Ed25519-sealed when the node has a signing key. The audit rows themselves are plain database
records: **not yet tamper-evident**. Hash-chained, signed audit rows and a verification tool for
auditors are in progress.
