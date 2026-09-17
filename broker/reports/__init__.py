# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Vertirite signed report exports — Pillar D.

The Inventory Report PDF is the auditor deliverable: a single document
that combines Coverage (Pillar A) + Witnessed findings (Pillar B) + an
audit-chain summary into a tamper-evident PDF.

Each report carries a SHA-256 fingerprint of its body bytes and a
pointer to the previous report's fingerprint, forming a chain that any
auditor can verify. The chain root is the first report generated for
a given tenant; subsequent reports link backward.
"""
from .runs import ReportRunTable  # noqa: F401 — register on import
