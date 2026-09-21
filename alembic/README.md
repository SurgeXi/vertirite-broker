<!-- Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE. -->
# Alembic

This folder contains the PostgreSQL-ready migration scaffold for the broker.

Run migrations from the repository root using your virtualenv:

```bash
# from the vertirite-broker repo root, with your venv active
python -m alembic upgrade head
```

Use the current broker env vars to control the DB target.
