# Copyright © 2026 SurgeXi Business Intelligence, a Teamsmith Enterprises LLC company. Licensed under the Business Source License 1.1 — see LICENSE.
"""Simple in-memory rate limiter for Maestro broker."""
import time
from collections import defaultdict


class RateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window
        hits = self._hits[key]
        # Prune old entries
        self._hits[key] = [t for t in hits if t > cutoff]
        if len(self._hits[key]) >= self.max_requests:
            return False
        self._hits[key].append(now)
        return True


# Global instance: 60 requests per minute per user
limiter = RateLimiter(max_requests=60, window_seconds=60)
