"""Fixtures for the opt-in PostgreSQL integration suite.

The suite is inert unless ``TEST_DATABASE_URL`` is set. There is no default
DSN, no localhost fallback, and no attempt to find a server: without the
variable every test here skips with a clear reason. That is what keeps the
ordinary unit suite runnable on a machine with no PostgreSQL.

When the variable *is* set, the target is validated before anything connects,
and the tests run against a database the harness creates for the session. See
``_harness.py`` for the isolation argument.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest

from app.repositories.postgres import Database, build_postgres_container

from ._harness import (
    ALLOW_NONLOCAL_ENV,
    KEEP_DATABASE_ENV,
    EphemeralDatabase,
    UnsafeTestDatabaseError,
    create_ephemeral_database,
    test_database_url,
    validate_target,
)

# Collected at import time so a session-scoped fixture and the skip logic agree.
_DSN = test_database_url()


def pytest_collection_modifyitems(config: Any, items: list[Any]) -> None:
    """Skip the whole integration suite when no target is configured.

    Done at collection so the reason is visible per test rather than as a
    module-level error, and so ``-k``/``-m`` selections still behave.
    """
    if _DSN is not None:
        return
    skip = pytest.mark.skip(
        reason=(
            "TEST_DATABASE_URL is not set; PostgreSQL integration tests need a "
            "disposable server. Set TEST_DATABASE_URL=postgresql://... to run them."
        )
    )
    for item in items:
        if item.get_closest_marker("integration") is not None:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def ephemeral_database() -> Iterator[EphemeralDatabase]:
    """A freshly created, fully migrated database for this session.

    The target is validated first: an unsafe DSN fails the run rather than being
    skipped, because a misconfigured target is a mistake worth surfacing.
    """
    if _DSN is None:  # pragma: no cover - collection already skipped these
        pytest.skip("TEST_DATABASE_URL is not set")

    application_dsn = os.environ.get("DATABASE_URL") or None
    validate_target(_DSN, application_database_url=application_dsn)

    database = create_ephemeral_database(_DSN)
    try:
        yield database
    finally:
        if os.environ.get(KEEP_DATABASE_ENV) == "1":
            # Escape hatch for debugging a failing test. The database is named
            # in the report so it can be found and dropped by hand.
            print(f"\n[{KEEP_DATABASE_ENV}=1] kept database: {database.name}")
        else:
            database.drop()


@pytest.fixture(scope="session")
def container(ephemeral_database: EphemeralDatabase) -> Any:
    """The real PostgreSQL repository container, bound to the ephemeral database."""
    return build_postgres_container(Database(ephemeral_database.dsn))


@pytest.fixture
def conn(ephemeral_database: EphemeralDatabase) -> Iterator[psycopg.Connection[Any]]:
    """A superuser connection to the ephemeral database for setup and assertions.

    This is the same identity the API uses in production (the service role,
    which bypasses RLS), so it is the right tool for arranging rows and for
    checking what was actually persisted. RLS itself is exercised separately
    through ``rls_connection``.
    """
    connection = psycopg.connect(ephemeral_database.dsn, autocommit=True)
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def org_factory(conn: psycopg.Connection[Any]) -> Any:
    """Create an organization with a real owner and membership.

    Returns a callable rather than a value so a test can create a second tenant.
    Every value is unique per call: the tests share one session database, so a
    counter would collide across tests and make a failure look like a product
    bug rather than a fixture bug.
    """

    def make(name: str | None = None) -> dict[str, str]:
        token = uuid.uuid4().hex[:12]
        user_id = str(uuid.uuid4())
        conn.execute(
            "insert into auth.users (id, email) values (%s, %s)",
            (user_id, f"user-{token}@example.test"),
        )
        label = name or f"Org {token}"
        slug = f"org-{token}"
        org_id = conn.execute(
            "insert into public.organizations (name, slug) values (%s, %s) returning id",
            (label, slug),
        ).fetchone()[0]
        conn.execute(
            "insert into public.memberships (organization_id, user_id, role) "
            "values (%s, %s, 'owner')",
            (org_id, user_id),
        )
        return {
            "organization_id": str(org_id),
            "user_id": user_id,
            "slug": slug,
            "name": label,
        }

    return make


__all__ = [
    "ALLOW_NONLOCAL_ENV",
    "KEEP_DATABASE_ENV",
    "UnsafeTestDatabaseError",
]
