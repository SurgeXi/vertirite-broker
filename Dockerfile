# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
FROM python:3.12-slim

WORKDIR /app

# System deps: poppler-utils for PDF text extraction (broker/documents.py),
# curl for the container healthcheck. No ssh client — the broker does not
# execute or shell out (record-only, no node-exec).
RUN apt-get update && apt-get install -y --no-install-recommends \
    poppler-utils curl \
    && rm -rf /var/lib/apt/lists/*

# Copy all code first
COPY pyproject.toml .
COPY broker/ broker/
COPY plugins/ plugins/
COPY context/ context/

# Install the broker package (pinned deps come from pyproject.toml) plus the
# pinned optional document-processing extras used by broker/documents.py.
RUN pip install --no-cache-dir . \
    "openpyxl>=3.1,<4.0" "python-docx>=1.1,<2.0" "python-pptx>=0.6,<1.1" "PyMuPDF>=1.24,<1.27"

# Alembic assets — required so `alembic upgrade head` can run in-container.
# The product ships with a bundled Postgres; migrations run on start.
# NOTE: simulation/ (the demo engine) is intentionally NOT copied here — it is a
# separate, hosted-only package and never ships inside the product image.
COPY alembic.ini .
COPY alembic/ alembic/

# Data directory
RUN mkdir -p /data/logs

ENV SURGE_OPERATOR_ENVIRONMENT=production
ENV SURGE_OPERATOR_DATABASE_URL=sqlite+pysqlite:////data/broker.db
ENV SURGE_OPERATOR_BROKER_API_TOKEN=change-me-in-production
ENV SURGE_OPERATOR_BOOTSTRAP_USER_ID=operator
# The governor-of-record upstream (optional; the broker fails closed to
# LOCKDOWN when it is unreachable). Loopback default; override per deployment.
ENV SURGE_OPERATOR_SURGE_CORE_URL=http://127.0.0.1:7070
# Point this at a HOST-LOCAL directory of real *.md context files to run with
# operational context; unset ships the sanitized fixtures (context_source=fixtures).
# ENV SURGE_OPERATOR_CONTEXT_DIR=/operator-context

EXPOSE 8220

CMD ["uvicorn", "broker.main:app", "--host", "0.0.0.0", "--port", "8220"]
