"""Shared pytest fixtures.

The app is built with a test settings object and its container is reset per
test, so tests never share state. A stub token verifier is installed so no
test needs a real Supabase project or a real JWT.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.security import Principal, StubTokenVerifier
from app.main import create_app
from tests.fake_aws import FakeAwsAdapter

# Test tokens. These are opaque strings, not credentials of any kind.
ALICE_TOKEN = "test-token-alice"
BOB_TOKEN = "test-token-bob"

ALICE_ID = "user-alice"
BOB_ID = "user-bob"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        app_env="test",
        log_level="WARNING",
        supabase_url="http://localhost:54321",
        supabase_anon_key="test-anon-key",
        supabase_service_role_key="test-service-role-key",
        supabase_jwt_secret="test-jwt-secret",
        cors_allowed_origins=["http://localhost:3000"],
        # Workers run for real, so tests exercise the real queue and thread
        # hand-off. The reaper is disabled because its interval would make
        # tests slow and it is exercised directly in its own unit tests.
        scan_worker_count=2,
        scan_queue_max_size=10,
        scan_worker_poll_timeout_seconds=0.01,
        scan_reaper_enabled=False,
    )


@pytest.fixture
def verifier() -> StubTokenVerifier:
    return StubTokenVerifier(
        {
            ALICE_TOKEN: Principal(user_id=ALICE_ID, email="alice@example.com", claims={}),
            BOB_TOKEN: Principal(user_id=BOB_ID, email="bob@example.com", claims={}),
        }
    )


@pytest.fixture
def app(settings: Settings, verifier: StubTokenVerifier, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    application = create_app(settings)
    # The stub verifier replaces the real one for the duration of the test.
    import app.core.dependencies as deps

    application.dependency_overrides[deps.get_token_verifier] = lambda: verifier
    # The rate-limit middleware resolves the caller through app state, so the
    # same stub is reachable there. Without this the middleware would fall back
    # to the real verifier and key every test request by IP.
    application.state.token_verifier = verifier
    return application


@pytest.fixture
def client(app) -> Iterator[TestClient]:  # type: ignore[no-untyped-def]
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def alice_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ALICE_TOKEN}"}


@pytest.fixture
def bob_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {BOB_TOKEN}"}


@pytest.fixture
def org(client: TestClient, alice_headers: dict[str, str]) -> str:
    """An organization owned by alice, created through the real API."""
    response = client.post(
        "/api/v1/organizations",
        headers=alice_headers,
        json={"name": "Acme", "slug": "acme"},
    )
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


@pytest.fixture
def org_headers(alice_headers: dict[str, str], org: str) -> dict[str, str]:
    return {**alice_headers, "X-Organization-Id": org}


@pytest.fixture
def fake_adapter(app) -> FakeAwsAdapter:  # type: ignore[no-untyped-def]
    """Install the in-memory AWS fake on a running app.

    Both the request path (account validation) and the worker path (scan
    execution) resolve AWS through the connection service and the scan service,
    so swapping those two covers the whole pipeline. The billing service is a
    third holder of the adapter and is swapped too, or a scan would reach the
    real Cost Explorer client.
    """
    from app.services.billing import BillingService

    adapter = FakeAwsAdapter()
    app.state.aws_adapter = adapter
    app.state.aws_connection_service._adapter = adapter  # noqa: SLF001
    app.state.scan_service._adapter = adapter  # noqa: SLF001
    if app.state.scan_service._billing is not None:  # noqa: SLF001
        app.state.scan_service._billing = BillingService(adapter)
    return adapter
