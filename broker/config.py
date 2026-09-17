# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "surge-operator-broker"
    environment: str = "development"
    database_url: str = "sqlite+pysqlite:///.data/broker.db"
    # Production: set DATABASE_URL, e.g. postgresql+psycopg://USER:PASSWORD@example-db:5432/vertirite
    surge_core_url: str = "http://127.0.0.1:7070"
    # Fail-CLOSED governance (Vertirite default): when surge-core (the
    # governor-of-record) is unreachable, deny by defaulting to LOCKDOWN
    # rather than the permissive cached/CONTROLLED mode. Set False only for
    # deployments that intentionally run autonomously without a live governor.
    governor_fail_closed: bool = True
    # --- Gate 01: local mode authority (auth-separated) ---
    # A LOCAL set-path for the SurgeMode of record lives inside the broker so
    # LOCKDOWN can be engaged even when surge-core (the optional upstream) is
    # unreachable fleet-wide. The credential that authorizes a mode change is a
    # SEPARATE trust domain from broker_api_token / demo_api_token / SaaS keys:
    # the agent plane can never hold it, keeping mode authority out-of-band.
    # Env: SURGE_OPERATOR_GOVERNOR_TOKEN. Empty (default) = local set-path
    # DISABLED — POST /v1/mode → 503 and behavior is exactly as before this
    # setting existed (surge-core-only, read-through). Provision a governor
    # credential to enable local mode authority.
    governor_token: str = ""
    # No inference/model/RAG config: the publishable broker contains no model
    # and calls none on its own behalf (no local-model, inference-gateway, or
    # vector/search backends). BYO-cloud is governed passthrough only — see
    # /v1/proxy/openai.
    allow_sqlite_dev: bool = True
    broker_api_token: str = "surge-operator-dev-token"
    bridge_api_token: str = "surge-openwebui-bridge-token"
    # Public-demo token (try.vertirite.com console). SEPARATE from
    # broker_api_token so the key printed in the demo URL fragment maps to a
    # locked-down role="demo" (product surface only) instead of platform_admin.
    # Env: SURGE_OPERATOR_DEMO_API_TOKEN. Empty (default) = no demo role exists;
    # behavior is exactly as before this setting was introduced.
    demo_api_token: str = ""
    bootstrap_user_id: str = "operator"

    # --- Stage 2 enforcement: the ROUTE primitive (forward-proxy) ---
    # docs/GOVERNANCE-ENFORCEMENT.md. The broker can sit on the call path as an
    # OpenAI-compatible endpoint: an app points its SDK at the broker, every
    # call is policy-gated + audited, then forwarded to the real provider. This
    # makes "Route through Vertirite" real instead of advisory.
    #
    # Fail-SAFE: OFF by default. The proxy carries live customer AI traffic, so
    # it stays inert until an operator explicitly enables it (env override),
    # mirroring REGISTRATION_ENABLED discipline. A disabled proxy returns 503.
    proxy_enabled: bool = False
    # Where allowed calls go: the real upstream AI provider (the customer's own
    # account). OpenAI-compatible; swap per provider via env.
    proxy_openai_upstream: str = "https://api.openai.com"
    # Server-side upstream credential. When set, the broker injects THIS key and
    # the calling app never holds the provider secret (the secure posture — the
    # app authenticates to the broker, the broker holds the provider key). When
    # empty, the app's own Authorization header is passed through unchanged.
    proxy_openai_api_key: str = ""
    # What to do with a destination/model that is neither a known threat nor on
    # the sanctioned allowlist: "route" = allow but audit + flag unsanctioned
    # (non-disruptive, selective/fail-open per the locked doc); "block" = deny.
    proxy_default_decision: str = "route"
    # Optional sanctioned-model allowlist (csv of model-name prefixes). Empty =
    # no explicit allowlist; default_decision governs the unlisted case.
    proxy_sanctioned_models: str = ""
    # Upstream request timeout (seconds).
    proxy_request_timeout_s: float = 60.0
    # --- Real BLOCK connectors (Stage 2, docs/GOVERNANCE-ENFORCEMENT.md) ---
    # Master safety: even with dry_run=false, a connector applies NOTHING unless
    # this is explicitly enabled. "Brain not the wire" — advisory by default.
    enforcement_apply_enabled: bool = False
    # webhook connector: POST the block to the customer's automation.
    enforcement_webhook_url: str = ""
    enforcement_webhook_token: str = ""
    # dns-rpz connector: append a sinkhole rule to a Response-Policy-Zone file.
    enforcement_dns_rpz_path: str = ""

    # --- Mechanism #1: the perishable intelligence catalog ---
    # docs/PROTECTION-MODEL.md. The discovery pattern catalog is a signed, dated
    # feed layered on the open baseline; the premium layer DECAYS without renewal
    # so a stolen/disconnected copy runs a rotting brain. Inert until a catalog
    # is installed (no catalog → baseline-only, fail-safe).
    intelligence_enabled: bool = True
    # SurgeXi's mint PUBLIC key (PEM) — the trust anchor. The broker only
    # verifies; the private mint key never ships. Provide inline or via path.
    intelligence_public_key: str = ""
    intelligence_public_key_path: str = ""
    # Break Detection follow-ons:
    #  - compliance_signing_key(_path): per-node Ed25519 PRIVATE key (PEM) used to
    #    sign compliance evidence reports. Empty = sha256 integrity anchor only.
    #  - tenant_verticals: JSON map {tenant_id: "medical"|"accounting"|"manufacturing"}
    #    used to seed per-vertical priors into a new agent's cold-start baseline.
    compliance_signing_key: str = ""
    compliance_signing_key_path: str = ""
    tenant_verticals: str = ""
    # Grace window after a catalog's signed expiry during which the premium layer
    # is still trusted (STALE) before it drops to baseline-only (EXPIRED).
    intelligence_grace_days: int = 14

    # --- Connected-tier metabolism: auto-pull fresh intelligence (PR3) ---
    # OFF by default = the Sovereign / no-phone-home posture. When enabled with a
    # feed URL, a background thread draws down the latest SIGNED catalog on a
    # cadence and installs it (verify + version-monotonic). A disconnected copy
    # can't pull → its catalog rots → baseline-only. This IS the transparent
    # phone-home of docs/PROTECTION-MODEL.md.
    intelligence_feed_enabled: bool = False
    intelligence_feed_url: str = ""
    intelligence_feed_token: str = ""           # optional bearer auth to the feed
    intelligence_feed_tenants: str = "default"  # csv of tenants to refresh
    intelligence_refresh_interval_s: int = 3600
    intelligence_feed_timeout_s: float = 15.0

    # --- Mechanism #2: self-narcs-theft (docs/PROTECTION-MODEL.md) ---
    # The product watches its OWN phone-home channel (the feed). If it goes
    # unreachable for N consecutive pulls, it raises a 'self-egress-suppressed'
    # finding — a thief who firewalls the channel to hide a stolen copy trips
    # Vertirite's own egress detector. Watches the EXISTING feed (no new
    # phone-home), so on by default is safe; only meaningful Connected-tier.
    protection_enabled: bool = True
    protection_suppression_threshold: int = 3
    # A persistently firewalled feed keeps failing every pull; the finding
    # dedupes (upsert) but the critical alert would re-fire each pull. Re-raise
    # (and re-alert) at most once per this window; recovery clears the stamp so
    # a NEW suppression episode alerts immediately.
    protection_suppression_realert_minutes: int = 360
    # Mechanism #2 PR2 — the edge beacon. On the Connected cadence the edge POSTs
    # a metadata-only beacon (instance_id + canary + fingerprint + catalog/
    # suppression state) to this ingress (the godaddy relay, or the control plane
    # directly). Empty URL → no beacon (Sovereign / no phone-home default).
    protection_beacon_url: str = ""
    protection_beacon_token: str = ""
    # Mechanism #3 — behavioral binding. The edge binds to its environment
    # fingerprint; a copy in a foreign environment is detected (and, when
    # enforced, withheld the premium catalog → baseline-only).
    # _enabled = record + detect drift (safe default, on). _enforce = actually
    # withhold premium on mismatch (opt-in; recommended on fixed-hardware nodes,
    # NOT containers where a recreate can change the fingerprint).
    protection_binding_enabled: bool = True
    protection_binding_enforce: bool = False
    # Mechanism #4 — federated immune system. Opt-in: when on, the beacon also
    # carries metadata-only discovery COUNTS (no hostnames/findings) so the
    # control plane can build a collective fleet view. Off = identity-only beacon.
    protection_federation_enabled: bool = False

    # --- License-token layer (commercial keystone, docs/PROTECTION-MODEL.md §3) ---
    # Gates PREMIUM features (not broker startup). OFF by default = dev /
    # unlicensed-open mode (everything entitled). The shipped product sets this
    # True with the SurgeXi license PUBLIC key baked in; no valid license → free
    # baseline tier.
    license_enabled: bool = False
    license_public_key: str = ""
    license_public_key_path: str = ""

    forward_approvals_to_surge_core: bool = False
    stream_delay_ms: int = 20
    keyvault_secret: str = "maestro-dev-keyvault-secret-change-in-production"

    # Alert notification channels
    alert_email_enabled: bool = False
    alert_email_to: str = "owner@example.com"
    alert_email_smtp_host: str = ""
    alert_email_smtp_port: int = 587
    alert_email_smtp_user: str = ""
    alert_email_smtp_pass: str = ""
    alert_webhook_enabled: bool = False
    alert_webhook_url: str = ""
    # Closed-loop enforcement VERIFY: run a real prober (DNS resolution) to confirm
    # a block took. OFF by default (brain not the wire) — opt-in for lab/enforcing.
    enforcement_verify_enabled: bool = False
    # Finding categories that fire a real-time alert on FIRST sighting. Threats +
    # shadow-AI (suspicious-egress) by default; add "service-endpoint" to also alert
    # on every newly-seen sanctioned AI service.
    alert_categories: tuple = ("suspicious-egress",)
    alert_pushover_enabled: bool = False


    model_config = SettingsConfigDict(env_prefix="SURGE_OPERATOR_", extra="ignore")


settings = Settings()
