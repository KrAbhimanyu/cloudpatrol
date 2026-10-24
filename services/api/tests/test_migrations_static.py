"""Static checks on the SQL migrations.

These are text-level assertions, not a database test. No database is started,
no SQL is executed, and nothing here proves the migration *runs* — only that it
is additive, that it adds the columns the repository models require, and that
the migrations it builds on have not been edited in place.

A migration is append-only history: rewriting ``0001``-``0003`` after they may
have been applied to a database would make the applied state and the file
disagree, so their content is pinned by hash.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

# tests/ -> services/api/ -> services/ -> repository root
MIGRATIONS = Path(__file__).resolve().parents[3] / "supabase" / "migrations"

# Applied migrations must not change once they may have run against a database.
# These are the SHA-256 digests of the files as of migration 0004.
_PINNED_MIGRATIONS = {
    "0001_init.sql": "c09790a766b3c46057985fd28f3bc95bf16be0cc739d6daa1439ca1bc37c013a",
    "0002_savings_basis_states.sql": (
        "c6e1c8f3f7df0a6cf70ac5bdbcafecfeaf19a0b4748555e732c7c84a3d49e144"
    ),
    "0003_cost_observations.sql": (
        "29a2a8fa68376db345c39366655805ef58b9741ab63f5d99b69dd8291a5a5395"
    ),
}

_NEW_MIGRATION = "0004_scan_attempts_and_savings_creator.sql"


def _read(name: str) -> str:
    return (MIGRATIONS / name).read_text(encoding="utf-8")


def _strip_comments(sql: str) -> str:
    """Remove ``--`` line comments so assertions match executable SQL only.

    The migration explains itself in comments that name columns and keywords;
    without this, a check for "the file contains no DROP" could be satisfied or
    broken by prose rather than by a statement.
    """
    return "\n".join(line for line in sql.splitlines() if not line.strip().startswith("--"))


def _migration_names() -> list[str]:
    return sorted(p.name for p in MIGRATIONS.glob("*.sql"))


def test_migration_directory_is_where_we_think_it_is() -> None:
    assert MIGRATIONS.is_dir(), f"Expected {MIGRATIONS} to exist"


def test_migrations_are_numbered_sequentially_from_0001() -> None:
    """A gap or a duplicate number means migrations could apply out of order."""
    names = _migration_names()
    numbers = [name.split("_", 1)[0] for name in names]
    assert numbers == [f"{n:04d}" for n in range(1, len(names) + 1)], names


def test_earlier_migrations_are_unmodified() -> None:
    """``0001``-``0003`` must be byte-identical to the reviewed versions."""
    for name, expected in _PINNED_MIGRATIONS.items():
        digest = hashlib.sha256(_read(name).encode("utf-8")).hexdigest()
        assert digest == expected, (
            f"{name} has been edited. Migrations already applied to a database must not "
            f"change; add a new migration instead."
        )


def test_new_migration_adds_the_attempts_column() -> None:
    sql = _strip_comments(_read(_NEW_MIGRATION))
    assert re.search(
        r"alter table public\.scans\s+add column if not exists attempts integer "
        r"not null default 0",
        sql,
        re.IGNORECASE,
    ), "0004 must add scans.attempts as integer not null default 0"


def test_new_migration_adds_the_savings_created_by_column() -> None:
    sql = _strip_comments(_read(_NEW_MIGRATION))
    assert re.search(
        r"alter table public\.savings_records\s+add column if not exists created_by uuid",
        sql,
        re.IGNORECASE,
    ), "0004 must add savings_records.created_by as uuid"


def test_new_migration_is_additive_only() -> None:
    """No statement may drop, rename or retype anything.

    This is the property that makes the migration safe to apply to a database
    that already holds data.
    """
    sql = _strip_comments(_read(_NEW_MIGRATION))
    forbidden = (
        "drop ",
        "rename ",
        "alter column",
        "truncate",
        "delete from",
        "update ",
        "insert into",
        "type ",
    )
    lowered = sql.lower()
    offenders = [word for word in forbidden if word in lowered]
    assert not offenders, f"0004 must be additive only, but contains: {offenders}"


def test_new_migration_touches_only_the_two_intended_tables() -> None:
    sql = _strip_comments(_read(_NEW_MIGRATION))
    tables = set(re.findall(r"alter table public\.(\w+)", sql, re.IGNORECASE))
    assert tables == {"scans", "savings_records"}, tables


def test_new_migration_does_not_touch_security_objects() -> None:
    """RLS policies, grants, roles and the enum types must be left alone."""
    sql = _strip_comments(_read(_NEW_MIGRATION)).lower()
    for token in ("row level security", "create policy", "drop policy", "grant ", "revoke "):
        assert token not in sql, f"0004 must not alter security configuration ({token!r})"


def test_new_migration_does_not_change_the_currency_columns() -> None:
    """The ``text`` vs ``char(3)`` mismatch is documented, not fixed, in 0004."""
    sql = _strip_comments(_read(_NEW_MIGRATION))
    assert "cost_observations" not in sql
    assert "currency" not in sql


def test_new_migration_uses_if_not_exists_for_every_column() -> None:
    """Re-applying the migration must be a no-op, not an error."""
    sql = _strip_comments(_read(_NEW_MIGRATION))
    added = re.findall(r"add column\s+(if not exists\s+)?", sql, re.IGNORECASE)
    assert added, "expected at least one add column statement"
    assert all(match.strip() for match in added), "every add column needs if not exists"
