"""Rate limiting tests.

The limiter is exercised against a controlled clock, so the tests are exact
rather than timing-dependent: no sleeps, no flakiness.

The middleware is exercised through the real app with rate limiting enabled, to
prove the wiring — class selection, principal keying, the Retry-After header and
the health-check exemption — and not just the bucket arithmetic.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.rate_limit import (
    RateLimitRule,
    TokenBucketRateLimiter,
    rate_limit_key,
)
from app.core.rate_limit_middleware import classify_request
from app.core.security import StubTokenVerifier
from app.main import create_app
from tests.conftest import ALICE_ID, ALICE_TOKEN


class FakeClock:
    """A monotonic clock the test advances by hand."""

    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


# --- bucket arithmetic ---------------------------------------------------


def test_a_burst_up_to_capacity_is_allowed() -> None:
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        {"read": RateLimitRule(capacity=3, refill_per_second=1.0)}, now=clock
    )
    for _ in range(3):
        limiter.check(limit_class="read", key="k")


def test_exceeding_capacity_is_rejected() -> None:
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        {"read": RateLimitRule(capacity=2, refill_per_second=1.0)}, now=clock
    )
    limiter.check(limit_class="read", key="k")
    limiter.check(limit_class="read", key="k")

    from app.core.errors import RateLimitedError

    with pytest.raises(RateLimitedError) as excinfo:
        limiter.check(limit_class="read", key="k")
    assert excinfo.value.details["retry_after_seconds"] >= 1


def test_tokens_refill_over_time() -> None:
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        {"read": RateLimitRule(capacity=2, refill_per_second=1.0)}, now=clock
    )
    limiter.check(limit_class="read", key="k")
    limiter.check(limit_class="read", key="k")

    # One second restores exactly one token.
    clock.advance(1.0)
    limiter.check(limit_class="read", key="k")


def test_refill_is_capped_at_capacity() -> None:
    """A long idle period must not let a caller bank an unbounded burst."""
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        {"read": RateLimitRule(capacity=2, refill_per_second=1.0)}, now=clock
    )
    clock.advance(10_000)
    limiter.check(limit_class="read", key="k")
    limiter.check(limit_class="read", key="k")

    from app.core.errors import RateLimitedError

    with pytest.raises(RateLimitedError):
        limiter.check(limit_class="read", key="k")


def test_keys_are_independent() -> None:
    """One caller exhausting a bucket must not affect another."""
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        {"read": RateLimitRule(capacity=1, refill_per_second=0.001)}, now=clock
    )
    limiter.check(limit_class="read", key="alice")

    from app.core.errors import RateLimitedError

    with pytest.raises(RateLimitedError):
        limiter.check(limit_class="read", key="alice")
    # Bob still has his own full bucket.
    limiter.check(limit_class="read", key="bob")


def test_classes_are_independent() -> None:
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        {
            "read": RateLimitRule(capacity=1, refill_per_second=0.001),
            "scan": RateLimitRule(capacity=1, refill_per_second=0.001),
        },
        now=clock,
    )
    limiter.check(limit_class="read", key="k")

    from app.core.errors import RateLimitedError

    with pytest.raises(RateLimitedError):
        limiter.check(limit_class="read", key="k")
    # The scan class is untouched by the read exhaustion.
    limiter.check(limit_class="scan", key="k")


def test_an_unknown_class_fails_open() -> None:
    """A missing rule is a config gap, not a reason to reject traffic."""
    clock = FakeClock()
    limiter = TokenBucketRateLimiter({}, now=clock)
    for _ in range(100):
        limiter.check(limit_class="nonexistent", key="k")


def test_bucket_count_is_bounded() -> None:
    """An attacker cycling keys must not grow the map without limit."""
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        {"read": RateLimitRule(capacity=1, refill_per_second=0.001)},
        max_keys=10,
        now=clock,
    )
    for index in range(1000):
        limiter.check(limit_class="read", key=f"key-{index}")

    assert len(limiter._buckets) <= 10  # noqa: SLF001


def test_rate_limit_key_never_contains_the_raw_value() -> None:
    key = rate_limit_key(principal_id="user-secret-value", client_ip="10.0.0.1")
    assert "user-secret-value" not in key
    assert "10.0.0.1" not in key


def test_key_is_stable_for_the_same_principal() -> None:
    assert rate_limit_key(principal_id="u1", client_ip="1.1.1.1") == rate_limit_key(
        principal_id="u1", client_ip="2.2.2.2"
    )


# --- class selection -----------------------------------------------------


def test_scan_creation_has_its_own_class() -> None:
    assert classify_request("POST", "/api/v1/scans") == "scan"
    assert classify_request("POST", "/api/v1/scans/") == "scan"


def test_other_writes_are_not_scans() -> None:
    assert classify_request("POST", "/api/v1/aws/accounts") == "write"
    assert classify_request("PATCH", "/api/v1/findings/f1") == "write"
    assert classify_request("GET", "/api/v1/scans") == "read"


# --- middleware wiring ---------------------------------------------------


@pytest.fixture
def limited_app(settings: Settings, verifier: StubTokenVerifier):  # type: ignore[no-untyped-def]
    """An app with rate limiting enabled and a tiny scan quota."""
    limited = settings.model_copy(update={"rate_limit_enabled": True})
    application = create_app(limited)

    import app.core.dependencies as deps

    application.dependency_overrides[deps.get_token_verifier] = lambda: verifier
    application.state.token_verifier = verifier
    return application


def _install_tiny_rules(application, capacity: int = 2):  # type: ignore[no-untyped-def]
    """Replace the limiter with one whose scan quota is tiny and barely refills."""
    from app.core.rate_limit import TokenBucketRateLimiter, build_default_rules

    rules = build_default_rules()
    rules["scan"] = RateLimitRule(capacity=capacity, refill_per_second=0.0001)
    rules["read"] = RateLimitRule(capacity=capacity, refill_per_second=0.0001)

    middleware = None
    for item in application.user_middleware:
        if item.cls.__name__ == "RateLimitMiddleware":
            middleware = item
            break
    assert middleware is not None, "rate limit middleware not installed"
    middleware.kwargs["limiter"] = TokenBucketRateLimiter(rules)


def test_health_is_never_rate_limited(limited_app) -> None:  # type: ignore[no-untyped-def]
    with TestClient(limited_app) as client:
        for _ in range(50):
            assert client.get("/health").status_code == 200


def test_scan_creation_returns_429_with_retry_after(limited_app, alice_headers) -> None:  # type: ignore[no-untyped-def]
    _install_tiny_rules(limited_app, capacity=1)
    with TestClient(limited_app) as client:
        # First scan request consumes the only token. It 404s for the unknown
        # account, which is fine: the limiter runs before the route.
        first = client.post(
            "/api/v1/scans",
            headers=alice_headers,
            json={"aws_account_id": "00000000-0000-0000-0000-000000000000"},
        )
        assert first.status_code != 429

        second = client.post(
            "/api/v1/scans",
            headers=alice_headers,
            json={"aws_account_id": "00000000-0000-0000-0000-000000000000"},
        )
        assert second.status_code == 429
        assert second.headers["Retry-After"]
        body = second.json()
        assert body["error"]["code"] == "rate_limited"
        assert body["error"]["details"]["limit_class"] == "scan"


def test_a_read_is_not_blocked_by_scan_exhaustion(limited_app, alice_headers) -> None:  # type: ignore[no-untyped-def]
    """Classes are separate, so exhausting scans leaves reads working."""
    _install_tiny_rules(limited_app, capacity=1)
    with TestClient(limited_app) as client:
        client.post(
            "/api/v1/scans",
            headers=alice_headers,
            json={"aws_account_id": "00000000-0000-0000-0000-000000000000"},
        )
        client.post(
            "/api/v1/scans",
            headers=alice_headers,
            json={"aws_account_id": "00000000-0000-0000-0000-000000000000"},
        )
        # The read class has its own bucket.
        assert client.get("/api/v1/organizations", headers=alice_headers).status_code == 200


def test_limiting_is_keyed_per_principal(limited_app, alice_headers, bob_headers) -> None:  # type: ignore[no-untyped-def]
    """Alice exhausting her quota must not throttle Bob."""
    _install_tiny_rules(limited_app, capacity=1)
    with TestClient(limited_app) as client:
        for _ in range(2):
            client.post(
                "/api/v1/scans",
                headers=alice_headers,
                json={"aws_account_id": "00000000-0000-0000-0000-000000000000"},
            )
        blocked = client.post(
            "/api/v1/scans",
            headers=alice_headers,
            json={"aws_account_id": "00000000-0000-0000-0000-000000000000"},
        )
        assert blocked.status_code == 429

        # Bob has his own bucket and is not blocked.
        bob = client.post(
            "/api/v1/scans",
            headers=bob_headers,
            json={"aws_account_id": "00000000-0000-0000-0000-000000000000"},
        )
        assert bob.status_code != 429


def test_an_unauthenticated_flood_is_still_bounded(limited_app) -> None:  # type: ignore[no-untyped-def]
    """A caller without a valid token is keyed by IP, so it is still limited."""
    _install_tiny_rules(limited_app, capacity=1)
    with TestClient(limited_app) as client:
        codes = [
            client.get(
                "/api/v1/organizations", headers={"Authorization": "Bearer nope"}
            ).status_code
            for _ in range(4)
        ]
    assert 429 in codes


def test_an_invalid_token_is_keyed_by_ip_and_still_limited(limited_app) -> None:  # type: ignore[no-untyped-def]
    """A flood with no valid token must not escape the limiter."""
    _install_tiny_rules(limited_app, capacity=1)
    with TestClient(limited_app) as client:
        statuses = [client.get("/api/v1/organizations").status_code for _ in range(3)]
    assert 429 in statuses


def test_verifier_maps_the_test_token(verifier: StubTokenVerifier) -> None:
    """Guard for the tests above, which assume the stub's token mapping."""
    assert verifier.verify(ALICE_TOKEN).user_id == ALICE_ID
