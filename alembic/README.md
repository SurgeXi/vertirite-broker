<!-- Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE. -->
# Alembic

This folder contains the PostgreSQL-ready migration scaffold for the broker.

Run migrations with the repo virtualenv:

```bash
cd "/Users/toddsmith/Documents/New project/Maestro/apps/broker"
../../.venv/bin/alembic upgrade head
```

Use the current broker env vars to control the DB target.
