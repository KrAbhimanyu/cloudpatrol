"""Tests for the integration harness's safety guard.

These run with **no** database at all and are part of the ordinary unit suite.
That is deliberate: the guard is the thing that decides whether it is safe to
create and drop databases, so it must be tested even on a machine where the
integration suite skips. A guard that only runs when the risky path is taken is
a guard nobody has checked.

No connection is opened by anything here.
"""

from __future__ import annotations

import pytest

from tests.integration._harness import (
    ALLOW_NONLOCAL_ENV,
    EPHEMERAL_PREFIX,
    UnsafeTestDatabaseError,
    _replace_database,
    migration_files,
    validate_target,
)


def test_supabase_host_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A real Supabase project must be refused, with no opt-in available."""
    with pytest.raises(UnsafeTestDatabaseError, match="Supabase"):
        validate_target(
            "postgresql://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres"
        )


def test_supabase_pooler_host_is_refused() -> None:
    with pytest.raises(UnsafeTestDatabaseError, match="Supabase"):
        validate_target(
            "postgresql://postgres:pw@aws-0-eu-west-1.pooler.supabase.com:6543/postgres"
        )


def test_non_loopback_host_is_refused_by_default() -> None:
    with pytest.raises(UnsafeTestDatabaseError, match="non-loopback"):
        validate_target("postgresql://postgres:pw@db.internal.example:5432/postgres")


def test_non_loopback_is_allowed_only_with_the_explicit_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A CI service container is not loopback, so the opt-in must work.

    It must not, however, weaken the Supabase refusal: that is checked
    separately and stays unconditional.
    """
    monkeypatch.setenv(ALLOW_NONLOCAL_ENV, "1")
    validate_target("postgresql://postgres:pw@postgres:5432/postgres")

    with pytest.raises(UnsafeTestDatabaseError, match="Supabase"):
        validate_target(
            "postgresql://postgres:pw@db.abcdefghijklmnopqrst.supabase.co:5432/postgres"
        )


def test_non_postgresql_scheme_is_refused() -> None:
    with pytest.raises(UnsafeTestDatabaseError, match="scheme"):
        validate_target("mysql://root@localhost:3306/test")


def test_loopback_hosts_are_accepted() -> None:
    for dsn in (
        "postgresql://postgres:pw@localhost:5432/postgres",
        "postgresql://postgres:pw@127.0.0.1:5432/postgres",
        "postgresql://postgres:pw@[::1]:5432/postgres",
    ):
        validate_target(dsn)


def test_the_application_database_url_is_refused() -> None:
    """The app's own DSN must never be the test target."""
    dsn = "postgresql://postgres:pw@localhost:5432/cloudpatrol"
    with pytest.raises(UnsafeTestDatabaseError, match="DATABASE_URL"):
        validate_target(dsn, application_database_url=dsn)


def test_a_different_database_on_the_same_server_is_allowed() -> None:
    """Sharing a server is fine; sharing the database is not."""
    validate_target(
        "postgresql://postgres:pw@localhost:5432/cloudpatrol_it_abcd1234",
        application_database_url="postgresql://postgres:pw@localhost:5432/cloudpatrol",
    )


def test_migrations_are_discovered_in_order() -> None:
    """The harness must find 0001-0004 and apply them in numeric order."""
    names = [path.name for path in migration_files()]
    assert names[:4] == [
        "0001_init.sql",
        "0002_savings_basis_states.sql",
        "0003_cost_observations.sql",
        "0004_scan_attempts_and_savings_creator.sql",
    ]


def test_ephemeral_names_are_prefixed_and_random() -> None:
    """The drop guard keys on the name, so the shape matters."""
    import re

    pattern = re.compile(rf"^{EPHEMERAL_PREFIX}[0-9a-f]{{8}}$")
    assert pattern.match("cloudpatrol_it_00ff00ff")
    assert not pattern.match("cloudpatrol_it_")
    assert not pattern.match("postgres")
    assert not pattern.match("cloudpatrol_it_00ff00ff; drop database x")


def test_replace_database_keeps_credentials_and_host() -> None:
    out = _replace_database(
        "postgresql://user:secret@127.0.0.1:5432/postgres", "cloudpatrol_it_deadbeef"
    )
    assert out == "postgresql://user:secret@127.0.0.1:5432/cloudpatrol_it_deadbeef"


def test_guard_is_inert_without_the_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """No target configured means no target: the harness must not invent one."""
    from tests.integration._harness import test_database_url

    monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
    assert test_database_url() is None

    monkeypatch.setenv("TEST_DATABASE_URL", "   ")
    assert test_database_url() is None, "whitespace must not count as a configured target"
