"""Tests for the runtime store selection and the in-memory scan guard.

These pin two properties that must hold no matter what else changes:

* the default runtime is the in-memory store — a configured ``DATABASE_URL``
  does not silently switch the application to PostgreSQL;
* ``create_if_no_active`` behaves identically in the in-memory repository, so
  removing the route's store lock did not weaken the duplicate-scan guard.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.config import Settings
from app.core.errors import ConflictError
from app.repositories import memory
from app.repositories.memory import (
    InMemoryScanRepository,
    InMemoryStore,
    build_container,
    build_container_for_settings,
)


def test_build_container_is_in_memory() -> None:
    """The default container is the in-memory one."""
    container = build_container()
    assert isinstance(container, memory.Container)
    assert isinstance(container.scans, InMemoryScanRepository)
    assert isinstance(container.store, InMemoryStore)


def test_container_without_a_database_url_is_in_memory() -> None:
    """An unset DSN selects the in-memory store."""
    settings = Settings(app_env="test")
    assert settings.database_url is None
    container = build_container_for_settings(settings)
    assert isinstance(container, memory.Container)


def test_container_with_a_database_url_still_defaults_to_in_memory() -> None:
    """A configured DSN does not switch the runtime in this phase.

    PostgreSQL is an explicit opt-in; selecting it merely because an environment
    variable is present would change production behaviour as a side effect of
    configuration.
    """
    settings = Settings(
        app_env="test",
        database_url="postgresql://user:placeholder@localhost:5432/cloudpatrol",
    )
    assert settings.database_url is not None
    container = build_container_for_settings(settings)
    assert isinstance(container, memory.Container)


def test_no_connection_is_attempted_when_the_database_url_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Building a container must never touch the network."""
    import psycopg

    def explode(*args: object, **kwargs: object) -> object:
        raise AssertionError("no connection may be opened without a DSN")

    monkeypatch.setattr(psycopg, "connect", explode)
    container = build_container_for_settings(Settings(app_env="test"))
    assert isinstance(container, memory.Container)


def test_container_selection_warns_when_a_dsn_is_unused(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A configured but unused DSN is reported, not silently ignored."""
    import logging

    settings = Settings(
        app_env="test",
        database_url="postgresql://user:placeholder@localhost:5432/cloudpatrol",
    )
    with caplog.at_level(logging.WARNING, logger=memory.__name__):
        build_container_for_settings(settings)
    assert any("DATABASE_URL is set" in record.message for record in caplog.records)
    # The warning must not include the DSN itself.
    assert all("placeholder" not in record.getMessage() for record in caplog.records)


# --- in-memory create_if_no_active -------------------------------------------


def _scan_fields(**overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "organization_id": "org-1",
        "aws_account_id": "acct-1",
        "status": "queued",
        "started_at": None,
        "finished_at": None,
        "resource_count": 0,
        "finding_count": 0,
        "partial_failures": [],
        "error_message": None,
        "created_by": "user-alice",
    }
    fields.update(overrides)
    return fields


def test_create_if_no_active_creates_when_the_account_is_free() -> None:
    store = InMemoryStore()
    scans = InMemoryScanRepository(store)
    record = scans.create_if_no_active(**_scan_fields())

    assert record.status == "queued"
    assert record.attempts == 0
    assert scans.get("org-1", record.id) is not None


def test_create_if_no_active_rejects_a_second_active_scan() -> None:
    """The duplicate-scan guard survives the removal of the route's lock."""
    store = InMemoryStore()
    scans = InMemoryScanRepository(store)
    scans.create_if_no_active(**_scan_fields())

    with pytest.raises(ConflictError) as excinfo:
        scans.create_if_no_active(**_scan_fields())
    assert "already in progress" in excinfo.value.message
    assert excinfo.value.details["status"] == "queued"


def test_create_if_no_active_allows_a_scan_after_the_first_finished() -> None:
    """A completed scan does not block a new one."""
    store = InMemoryStore()
    scans = InMemoryScanRepository(store)
    first = scans.create_if_no_active(**_scan_fields())
    scans.update(first.id, status="completed", finished_at=datetime.now(UTC))

    second = scans.create_if_no_active(**_scan_fields())
    assert second.id != first.id


def test_create_if_no_active_is_scoped_per_account() -> None:
    """Two different accounts may each have an active scan."""
    store = InMemoryStore()
    scans = InMemoryScanRepository(store)
    scans.create_if_no_active(**_scan_fields(aws_account_id="acct-1"))
    record = scans.create_if_no_active(**_scan_fields(aws_account_id="acct-2"))
    assert record.aws_account_id == "acct-2"


def test_create_if_no_active_is_scoped_per_organization() -> None:
    """Another tenant's active scan for the same account id does not block."""
    store = InMemoryStore()
    scans = InMemoryScanRepository(store)
    scans.create_if_no_active(**_scan_fields(organization_id="org-1"))
    record = scans.create_if_no_active(**_scan_fields(organization_id="org-2"))
    assert record.organization_id == "org-2"


def test_memory_repository_satisfies_the_scan_protocol() -> None:
    """The in-memory repository must expose every method the protocol declares."""
    for name in (
        "list_for_org",
        "get",
        "get_by_id",
        "find_active_for_account",
        "find_stale_active",
        "fail_if_stale",
        "mark_running",
        "create",
        "create_if_no_active",
        "update",
    ):
        assert callable(getattr(InMemoryScanRepository(InMemoryStore()), name)), name


# --- Phase D: the route no longer reaches into the store lock ----------------


def test_scans_route_does_not_use_the_store_lock() -> None:
    """The route must go through the repository, not the in-memory store.

    A PostgreSQL repository has no ``store`` attribute, so any remaining use of
    ``container.store`` here would break the moment the backing store is swapped.
    """
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "scans.py").read_text()
    assert "store.lock" not in source
    assert "container.store" not in source
    assert "create_if_no_active" in source


def test_postgres_repositories_do_not_reference_the_in_memory_store() -> None:
    """The PostgreSQL implementation must not depend on in-memory state."""
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[1] / "app" / "repositories" / "postgres.py"
    ).read_text()
    assert "InMemoryStore" not in source
    assert "threading" not in source


def test_postgres_container_exposes_the_same_repository_attributes() -> None:
    """A route must not be able to tell the two containers apart.

    Compared by attribute name, which is the only contract a route depends on.
    """
    from app.repositories.memory import Container
    from app.repositories.postgres import Database, build_postgres_container

    memory_fields = {name for name in Container.__dataclass_fields__ if name != "store"}
    database = Database("postgresql://user:placeholder@localhost:5432/db")
    pg_container = build_postgres_container(database)
    pg_fields = {
        name
        for name in (
            "organizations",
            "aws_accounts",
            "scans",
            "resources",
            "findings",
            "savings",
            "costs",
            "audit",
        )
        if hasattr(pg_container, name)
    }

    assert pg_fields == memory_fields, memory_fields ^ pg_fields
    # The in-memory-only attribute is deliberately absent from the PostgreSQL one.
    assert not hasattr(pg_container, "store")
