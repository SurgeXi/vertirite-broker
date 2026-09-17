<!-- Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. -->
<!-- Licensed under the Business Source License 1.1 — see ../LICENSE. -->
# Context fixtures

The broker's context engine (`broker/context.py`) injects operator context into
LLM prompts. This directory ships **only sanitized `*.md.example` fixtures** —
never real operational intel.

## Operational context (host-local)

Point `SURGE_OPERATOR_CONTEXT_DIR` at a host-local directory containing real
`*.md` files (copy the `*.md.example` files below and fill them in). That
directory must live **outside** this repo/image so real topology and profiles
never get committed or published.

- If `SURGE_OPERATOR_CONTEXT_DIR` is set and contains `*.md` files, the broker
  loads them and reports `context_source: "operational"`.
- Otherwise the broker falls back to these fixtures and reports
  `context_source: "fixtures"` (and logs a startup WARNING) so a placeholder
  deployment never silently looks healthy. See `GET /v1/entitlements`.

Priority load order: `identity`, `owner`, `fleet`, `products`, then any other
files, joined with `---` separators.
