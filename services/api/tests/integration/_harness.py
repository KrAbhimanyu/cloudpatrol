"""Harness for the opt-in PostgreSQL integration suite.

Nothing here runs unless ``TEST_DATABASE_URL`` is set. When it is set, the
harness does not connect to that database to run tests: it connects only to
*create a brand-new, uniquely named database*, applies the real migrations to
that new database, and drops it afterwards. The DSN therefore names a server the
harness is allowed to create databases on, never the database under test.

Isolation argument
------------------
The target is isolated because the harness creates it:

1. ``TEST_DATABASE_URL`` names a server and a maintenance database. No test ever
   reads or writes that database's own schema.
2. A fresh database ``cloudpatrol_it_<8 hex>`` is created. The name is random
   per session, so two runs — or two CI jobs on one server — cannot collide.
3. Migrations are applied to the new database inside a single transaction, so a
   failure leaves nothing half-applied.
4. Teardown drops *only* the database whose name the harness generated, after
   re-checking the name against the expected pattern.

The one destructive statement is that final drop, and it can only ever target a
name this process created. There is no ``DROP DATABASE`` for any other name, no
``DROP SCHEMA``, and no ``TRUNCATE``. Set ``CLOUDPATROL_KEEP_TEST_DATABASE=1`` to
keep the database for inspection.

Fail-closed validation
----------------------
The guard exists to make "I pointed the tests at the wrong database" impossible
rather than merely unlikely. It refuses, before any connection is opened:

* any Supabase host — this suite must never touch the user's real project;
* a non-loopback host, unless ``CLOUDPATROL_ALLOW_NONLOCAL_TEST_DB=1`` is set
  deliberately (for a CI service container, which is not loopback from the
  job's point of view);
* a URL equal to the application's own ``DATABASE_URL``;
* a non-PostgreSQL scheme.

A refusal raises; it does not skip. A misconfigured target is an error, not a
test that quietly did not run.
"""

from __future__ import annotations

import os
import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
from psycopg import sql

# tests/integration/_harness.py -> tests -> api -> services -> repository root
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
MIGRATIONS_DIR = REPOSITORY_ROOT / "supabase" / "migrations"

TEST_DATABASE_URL_ENV = "TEST_DATABASE_URL"
ALLOW_NONLOCAL_ENV = "CLOUDPATROL_ALLOW_NONLOCAL_TEST_DB"
KEEP_DATABASE_ENV = "CLOUDPATROL_KEEP_TEST_DATABASE"

# Every database this harness creates carries this prefix. The name is checked
# against the full pattern before it is ever passed to a DROP.
EPHEMERAL_PREFIX = "cloudpatrol_it_"
_EPHEMERAL_NAME = re.compile(rf"^{EPHEMERAL_PREFIX}[0-9a-f]{{8}}$")

_LOOPBACK_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "[::1]",
        # 0.0.0.0 is listed so a DSN naming it is treated as local and *accepted
        # by the loopback check*. It is not a bind address here — nothing in this
        # module binds a socket — so S104 does not apply.
        "0.0.0.0",  # noqa: S104
    }
)

# Refused unconditionally. A Supabase project is the user's real data; there is
# no opt-in that makes it an acceptable test target.
_FORBIDDEN_HOST_SUFFIXES = (
    ".supabase.co",
    ".supabase.com",
    ".supabase.net",
    ".supabase.in",
    ".pooler.supabase.com",
)


class UnsafeTestDatabaseError(RuntimeError):
    """Raised when ``TEST_DATABASE_URL`` is set but is not safe to use.

    Deliberately an error rather than a skip: a target that fails validation is
    a configuration mistake, and silently skipping would hide it.
    """


def bootstrap_sql() -> str:
    """The Supabase objects the migrations assume already exist.

    The migrations are written for Supabase, where ``auth.users``, ``auth.uid()``
    and the ``authenticated`` role are provided by the platform. Plain
    PostgreSQL has none of them, so they are stubbed here.

    This is test scaffolding, not a migration: it is never applied to a real
    database, and it lives outside ``supabase/migrations`` so it can never be
    mistaken for one or alter the migration ordering the static tests pin.

    ``auth.uid()`` reads ``request.jwt.claim.sub``, which is how Supabase exposes
    the caller's subject to RLS policies, so a test can switch identity the same
    way the platform does.
    """
    return """
create schema if not exists auth;

create table if not exists auth.users (
  id uuid primary key default gen_random_uuid(),
  email text
);

create or replace function auth.uid() returns uuid
language sql stable as $$
  select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin bypassrls;
  end if;
end
$$;
"""


def supabase_grants_sql() -> str:
    """The grants Supabase applies that the migrations rely on.

    The migrations ``grant execute`` to ``authenticated`` and write policies
    ``to authenticated``, but they never grant table privileges — on Supabase
    that is done by the platform. Without these grants an RLS test would pass
    for the wrong reason: the query would fail on a missing privilege rather
    than be filtered by a policy.
    """
    return """
grant usage on schema public to authenticated, anon;
grant usage on schema auth to authenticated;
grant select on auth.users to authenticated;
grant select, insert, update, delete on all tables in schema public to authenticated;
grant execute on all functions in schema public to authenticated;
alter default privileges in schema public
  grant select, insert, update, delete on tables to authenticated;
"""


def migration_files() -> list[Path]:
    """The migrations in their intended order.

    Sorted by numeric prefix, which is the order the filenames encode and the
    order the static test asserts is gapless.
    """
    return sorted(MIGRATIONS_DIR.glob("*.sql"), key=lambda path: path.name)


def test_database_url() -> str | None:
    value = os.environ.get(TEST_DATABASE_URL_ENV, "").strip()
    return value or None


def _is_loopback(host: str | None) -> bool:
    if host is None:
        # A Unix-socket DSN (libpq default) is local by definition.
        return True
    return host.lower() in _LOOPBACK_HOSTS


def validate_target(dsn: str, *, application_database_url: str | None = None) -> None:
    """Refuse a test target that is not demonstrably safe. Raises on refusal.

    Called before a connection is opened, so a bad target costs nothing and
    cannot have touched anything.
    """
    parsed = urlsplit(dsn)

    if parsed.scheme not in ("postgres", "postgresql"):
        raise UnsafeTestDatabaseError(
            f"{TEST_DATABASE_URL_ENV} must be a postgresql:// URL, got scheme {parsed.scheme!r}"
        )

    host = parsed.hostname
    if host:
        lowered = host.lower()
        for suffix in _FORBIDDEN_HOST_SUFFIXES:
            if lowered.endswith(suffix):
                raise UnsafeTestDatabaseError(
                    f"Refusing to run integration tests against a Supabase host ({host!r}). "
                    "These tests create and drop databases and must never touch a real project. "
                    "Point TEST_DATABASE_URL at a disposable local server instead."
                )

    if not _is_loopback(host) and os.environ.get(ALLOW_NONLOCAL_ENV) != "1":
        raise UnsafeTestDatabaseError(
            f"Refusing a non-loopback test host ({host!r}). "
            f"Set {ALLOW_NONLOCAL_ENV}=1 to allow it deliberately (for example a CI service "
            "container), but only if that server is disposable."
        )

    if application_database_url and _same_target(dsn, application_database_url):
        raise UnsafeTestDatabaseError(
            "TEST_DATABASE_URL must not be the application's own DATABASE_URL. "
            "The integration suite creates and drops databases."
        )


def _same_target(left: str, right: str) -> bool:
    """Compare two DSNs by host, port and database, ignoring credentials."""
    a, b = urlsplit(left), urlsplit(right)
    return (a.hostname, a.port, a.path) == (b.hostname, b.port, b.path)


def _normalize_scheme(dsn: str) -> str:
    """libpq accepts ``postgres://``; psycopg's stubs prefer ``postgresql://``."""
    return dsn.replace("postgres://", "postgresql://", 1)


@dataclass(frozen=True)
class EphemeralDatabase:
    """A database this harness created and is responsible for dropping."""

    name: str
    dsn: str
    server_dsn: str

    def drop(self) -> None:
        """Drop this database. Refuses any name the harness did not generate.

        The name check is the safety property: even if a bug passed the wrong
        string here, it could not drop a database whose name does not match the
        ephemeral pattern.
        """
        if not _EPHEMERAL_NAME.match(self.name):
            raise UnsafeTestDatabaseError(
                f"Refusing to drop {self.name!r}: not a harness-generated database name."
            )
        with psycopg.connect(self.server_dsn, autocommit=True) as conn:
            conn.execute(sql.SQL("drop database if exists {}").format(sql.Identifier(self.name)))


def create_ephemeral_database(server_dsn: str) -> EphemeralDatabase:
    """Create a fresh database and apply bootstrap, grants and migrations to it.

    Migrations run in one transaction: a failure anywhere leaves an empty
    database rather than a partially migrated one, which matters because a
    half-applied schema could make a later test pass or fail for the wrong
    reason.
    """
    server_dsn = _normalize_scheme(server_dsn)
    name = f"{EPHEMERAL_PREFIX}{secrets.token_hex(4)}"

    with psycopg.connect(server_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("create database {}").format(sql.Identifier(name)))

    dsn = _replace_database(server_dsn, name)
    with psycopg.connect(dsn) as conn:
        with conn:  # one transaction for the whole schema build
            conn.execute(bootstrap_sql())
            conn.execute(supabase_grants_sql())
            for path in migration_files():
                conn.execute(path.read_text(encoding="utf-8"))

    return EphemeralDatabase(name=name, dsn=dsn, server_dsn=server_dsn)


def _replace_database(dsn: str, database: str) -> str:
    parsed = urlsplit(dsn)
    netloc = parsed.netloc
    return f"{parsed.scheme}://{netloc}/{database}"


def applied_migration_names(server_dsn: str, database: str) -> list[str]:
    """Read back the tables the migrations should have created.

    Used by the tests to prove the migrations actually ran against this
    database, rather than trusting that the harness succeeded.
    """
    dsn = _replace_database(_normalize_scheme(server_dsn), database)
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "select tablename from pg_tables where schemaname = 'public' order by tablename"
        ).fetchall()
    return [row[0] for row in rows]


@contextmanager
def rls_connection(dsn: str, user_id: str | None) -> Iterator[psycopg.Connection[tuple]]:
    """A connection acting as the ``authenticated`` role, as Supabase does.

    Supabase serves end-user requests as ``authenticated`` with the JWT subject
    in ``request.jwt.claim.sub``. This reproduces that so a policy can be
    exercised rather than merely read.

    ``set role`` is deliberately not ``set session authorization``: it keeps the
    connection's own identity for logging while the policy sees ``authenticated``.
    """
    conn = psycopg.connect(dsn, autocommit=True)
    try:
        conn.execute("set role authenticated")
        if user_id is not None:
            conn.execute("select set_config('request.jwt.claim.sub', %s, false)", (user_id,))
        yield conn
    finally:
        conn.close()
