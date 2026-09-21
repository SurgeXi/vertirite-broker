<!-- Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE. -->
# SurgeXi Products SDK

Minimal async Python client every SurgeXi product uses to invoke Surge.

## Install (from a consumer repo)

While we're still bundling this with the broker, consumer repos pull the package via:

```bash
pip install "git+https://github.com/SurgeXi/vertirite-broker.git"
```

That's heavyweight (you get the whole broker). When usage stabilises (Day 5 of the roadmap), we'll extract this directory into a published `surgexi-products-sdk` package.

## Quickstart

```python
from broker.products_sdk import SurgeClient

surge = SurgeClient.from_env()  # SURGE_BROKER_URL + SURGE_TOKEN

# Free-form intent — let Surge figure it out
result = await surge.invoke(
    intent="add a tenant for Acme Plumbing, owner acme@example.com",
    tenant_id="creator",
)
print(result.matched, result.summary)
# 'playbook' "Matched playbook 'add-tenant'."

# Direct capability — when the product knows exactly what it wants
result = await surge.dispatch(
    capability="support_ticket_list",
    params={"status": "escalated"},
)
print(result.outcome, result.data["count"], "escalated tickets")

# Discovery
caps = await surge.list_capabilities()  # what can Surge do?
pbs  = await surge.list_playbooks()     # what recipes does Surge know?
```

## Environment variables

| Var | Default | Purpose |
|-----|---------|---------|
| `SURGE_BROKER_URL` | `http://127.0.0.1:8220` | Broker base URL |
| `SURGE_TOKEN` | `surge-operator-dev-token` | Bearer token for the broker |
| `SURGE_DEFAULT_TENANT_ID` | (none) | Default tenant for calls that don't specify one |
| `SURGE_PRODUCT_NAME` | `unknown` | Identifies the calling product in audit logs |

## Async vs sync

The client is async-first. For sync callers (scripts, cron jobs):

```python
from broker.products_sdk import dispatch_sync, invoke_sync

result = dispatch_sync("file_read", {"path": "/etc/hosts"})
```

Don't use the sync wrappers from inside an async event loop.

## Error handling

```python
from broker.products_sdk import (
    SurgeClient, AwaitingApproval, AwaitingCapability, SurgeUnreachable,
)

try:
    result = await surge.dispatch(
        capability="bash_exec",
        params={"command": "sudo systemctl restart something"},
        raise_on_awaiting=True,
    )
except AwaitingApproval as e:
    # Operator was paged. e.approval_id can be polled later via
    # client.list_pending_approvals(); the dispatch result lands in
    # the audit log when approved.
    flash_user(f"Surge proposed an action; operator review pending ({e.approval_id})")
except AwaitingCapability as e:
    flash_user("That feature isn't wired yet — surge has flagged it for the team.")
except SurgeUnreachable as e:
    flash_user("Surge is offline; please try again or use the public form.")
```

## Per-product integration patterns

### Pattern A — invoke from a backend route

```python
@app.post("/api/customer/feature-x")
async def feature_x(req: FeatureXRequest):
    surge = SurgeClient.from_env()
    result = await surge.invoke(
        intent=f"feature X for {req.customer_id}: {req.detail}",
        context={"customer_id": req.customer_id, "feature": "x"},
        tenant_id=req.tenant_id,
    )
    return {"surge": result.summary, "ok": result.dispatch.ok if result.dispatch else None}
```

### Pattern B — surface Surge's capabilities in an admin UI

```python
@app.get("/api/admin/surge/capabilities")
async def list_caps():
    return await SurgeClient.from_env().list_capabilities()
```

### Pattern C — propose a missing capability when the product can't proceed

```python
result = await surge.dispatch(
    "propose_new_tool",
    params={
        "proposed_name": "music_generate_stem",
        "description": "Generate a single instrument stem from a mix",
        "parameters_sketch": {"track_id": "string", "stem": "string"},
        "user_intent": req.original_text,
    },
)
```

## Cross-repo expectations

Consumer repos that integrate this SDK should:

1. Add a CROSS-REPO COORDINATION block to their CLAUDE.md describing the integration
2. Open a thin PR that adds `SurgeClient.from_env()` calls in 1-2 places
3. Add at least one playbook in your playbooks directory (e.g. `/etc/vertirite/playbooks`) if the product introduces a compound action surge should handle

The SDK contract is versioned (see `surge_capabilities.SCHEMA_VERSION` in the broker). Breaking changes to that schema bump the version; consumer pins move forward at their own pace.
