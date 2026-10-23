"""Request rate limiting.

Why this exists: scan creation triggers outbound AWS calls. A caller with a
valid token could otherwise issue them without limit, which is a direct cost
and a way to get CloudPatrol throttled by AWS on the customer's behalf. Read
routes are cheap but still worth bounding, because every one of them queries
the store.

Design choices, and their limits:

* **Token bucket per key.** Allows a burst up to the bucket size while holding
  a steady average rate. A fixed window would let a caller send a full quota at
  the end of one window and again at the start of the next.
* **Keyed on the authenticated principal where available, else the client IP.**
  Keying on the raw token would mean storing credentials as map keys, so the
  key is a hash. Keying on IP alone would let one noisy tenant throttle
  another behind the same NAT.
* **In-process and per-instance.** This is deliberately the smallest thing that
  works for a single API process. It is *not* a distributed limiter: with N
  replicas the effective limit is N times the configured rate, and a restart
  clears the buckets. A shared store (Redis) is the upgrade path; it is not
  needed until there is more than one replica.
* **Bounded bucket count.** Without a cap, one bucket per distinct caller is an
  unbounded map an attacker can grow. The least-recently-used buckets are
  evicted past the cap.

The clock is injectable so tests advance time instead of sleeping.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from app.core.errors import RateLimitedError

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RateLimitRule:
    """A bucket size and refill rate for one class of request."""

    #: Maximum burst, in tokens.
    capacity: int
    #: Tokens added per second.
    refill_per_second: float

    def __post_init__(self) -> None:
        if self.capacity < 1:
            raise ValueError("capacity must be at least 1")
        if self.refill_per_second <= 0:
            raise ValueError("refill_per_second must be positive")


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated_at: float


class TokenBucketRateLimiter:
    """A bounded, thread-safe set of token buckets.

    ``max_keys`` caps memory. Eviction is least-recently-used, so an attacker
    cycling through keys can displace only the oldest idle buckets, not the
    active ones — and eviction grants a fresh bucket, which is why the cap is
    set high relative to the number of legitimate callers.
    """

    def __init__(
        self,
        rules: dict[str, RateLimitRule],
        *,
        max_keys: int = 10_000,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self._rules = dict(rules)
        self._max_keys = max_keys
        self._now = now
        self._lock = threading.Lock()
        self._buckets: OrderedDict[tuple[str, str], _Bucket] = OrderedDict()

    def _rule(self, limit_class: str) -> RateLimitRule | None:
        return self._rules.get(limit_class)

    def check(self, *, limit_class: str, key: str, cost: int = 1) -> None:
        """Consume ``cost`` tokens, or raise :class:`RateLimitedError`.

        An unknown class is not limited: a missing rule is a configuration gap,
        and failing open keeps a misconfiguration from taking the API down. It
        is logged so the gap is visible rather than silent.
        """
        rule = self._rule(limit_class)
        if rule is None:
            logger.warning("No rate limit rule for class", extra={"limit_class": limit_class})
            return

        now = self._now()
        bucket_key = (limit_class, key)

        with self._lock:
            bucket = self._buckets.get(bucket_key)
            if bucket is None:
                bucket = _Bucket(tokens=float(rule.capacity), updated_at=now)
                self._buckets[bucket_key] = bucket
            else:
                # Refill for the time elapsed, capped at capacity.
                elapsed = max(0.0, now - bucket.updated_at)
                bucket.tokens = min(
                    float(rule.capacity), bucket.tokens + elapsed * rule.refill_per_second
                )
                bucket.updated_at = now
                self._buckets.move_to_end(bucket_key)

            if bucket.tokens < cost:
                deficit = cost - bucket.tokens
                retry_after = max(1, int(deficit / rule.refill_per_second) + 1)
                raise RateLimitedError(
                    "Too many requests. Please retry later.",
                    details={"limit_class": limit_class, "retry_after_seconds": retry_after},
                )

            bucket.tokens -= cost
            self._evict_if_needed()

    def _evict_if_needed(self) -> None:
        """Drop the oldest idle buckets once the cap is exceeded.

        Called under the lock. Eviction is oldest-first so an active caller's
        bucket is never the one removed.
        """
        while len(self._buckets) > self._max_keys:
            self._buckets.popitem(last=False)


def rate_limit_key(*, principal_id: str | None, client_ip: str | None) -> str:
    """Derive a bucket key without storing a credential in it.

    The principal id is used when the request is authenticated. Otherwise the
    client IP is used, so unauthenticated floods are still bounded. Both are
    hashed so the map never holds a raw token or a raw IP.
    """
    basis = principal_id or client_ip or "anonymous"
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return digest[:32]


def build_default_rules() -> dict[str, RateLimitRule]:
    """The limits the API runs with by default.

    ``scan`` is the tightest because it is the only class that spends money:
    each permitted call can trigger dozens of AWS API calls.
    """
    return {
        # Scan creation: a burst of 5, sustained one every 30 seconds.
        "scan": RateLimitRule(capacity=5, refill_per_second=1 / 30),
        # Mutations (connect an account, review a finding, advance the ledger).
        "write": RateLimitRule(capacity=30, refill_per_second=1.0),
        # Reads: generous, because dashboards poll.
        "read": RateLimitRule(capacity=120, refill_per_second=5.0),
    }
