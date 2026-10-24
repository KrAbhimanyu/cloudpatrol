"""Tests for the PostgreSQL repositories.

These run against a fake connection, not a database. They pin the *shape* of
what the repositories send and how they translate what comes back:

* that every value is passed as a bound parameter, never interpolated;
* that row-to-dataclass mapping handles nullable columns and ``date`` values;
* that the expected integrity conflicts become domain errors;
* that tenant-scoped reads carry the organization predicate;
* that an upsert preserves finding state and creation time;
* that scan claim and stale-reaping are conditional single statements;
* that a failed multi-step write rolls back, and organization creation is atomic.

What these tests do **not** prove is that the SQL is valid PostgreSQL, that the
indexes are used, or that two real connections cannot both claim a scan. Those
require a live server; see ``docs/DEVELOPMENT.md`` for the proposed integration
step. A passing fake-connection test is not evidence of database behaviour.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from psycopg import sql
from psycopg.errors import CheckViolation, ForeignKeyViolation, UniqueViolation

from app.core.errors import ConflictError, NotFoundError
from app.repositories import postgres
from app.repositories.models import (
    AuditEventRecord,
    AwsAccountRecord,
    CostObservationRecord,
    FindingRecord,
    ResourceSnapshotRecord,
    SavingsRecord,
    ScanRecord,
)
from app.repositories.postgres import Database, build_postgres_container

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
ORG = "11111111-1111-1111-1111-111111111111"
ACCOUNT = "22222222-2222-2222-2222-222222222222"
SCAN = "33333333-3333-3333-3333-333333333333"
FINDING = "44444444-4444-4444-4444-444444444444"
USER = "55555555-5555-5555-5555-555555555555"


class FakeDiagnostic:
    def __init__(self, constraint_name: str | None = None) -> None:
        self.constraint_name = constraint_name


def unique_violation(constraint: str | None = None) -> UniqueViolation:
    """Build a UniqueViolation whose diagnostic names a constraint.

    psycopg's ``Diagnostic`` is populated by libpq and has no setter, so the
    constraint name is injected through a subclass. The instance still passes
    ``isinstance(exc, UniqueViolation)``, which is what the repository checks.
    """

    class _WithConstraint(UniqueViolation):
        diag = FakeDiagnostic(constraint)

    return _WithConstraint("duplicate key value violates unique constraint")


class FakeCursor:
    """Records executed statements and replays scripted results.

    ``script`` is a list of outcomes consumed in order. Each outcome is either a
    row (returned by ``fetchone``), a list of rows (returned by ``fetchall``), or
    an exception to raise.
    """

    def __init__(self, script: list[Any] | None = None) -> None:
        self.executed: list[tuple[str, Any]] = []
        self._script = list(script or [])
        self._last: Any = None
        self.rowcount = 0

    # -- recording ---------------------------------------------------------

    @staticmethod
    def _render(query: Any, params: Any) -> str:
        if isinstance(query, (sql.SQL, sql.Composed)):
            return query.as_string(None)
        return str(query)

    def _next(self) -> Any:
        if not self._script:
            return None
        outcome = self._script.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def execute(self, query: Any, params: Any = None, **_: Any) -> FakeCursor:
        self.executed.append((self._render(query, params), params))
        self._last = self._next()
        if isinstance(self._last, list):
            self.rowcount = len(self._last)
        else:
            self.rowcount = 1 if self._last is not None else 0
        return self

    def executemany(self, query: Any, params_seq: Any, **_: Any) -> FakeCursor:
        rows = list(params_seq)
        for params in rows:
            self.executed.append((self._render(query, params), params))
        self.rowcount = len(rows)
        return self

    def fetchone(self) -> Any:
        return self._last if not isinstance(self._last, list) else None

    def fetchall(self) -> Any:
        return self._last if isinstance(self._last, list) else []

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


class FakeConnection:
    """A connection whose transaction outcome is observable.

    Mirrors the part of psycopg's connection context manager the repositories
    rely on: commit on a clean exit, rollback when the block raises.
    """

    def __init__(self, script: list[Any] | None = None) -> None:
        self.cursor_obj = FakeCursor(script)
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self) -> FakeCursor:
        return self.cursor_obj

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> FakeConnection:
        return self

    def __exit__(self, exc_type: Any, *_: Any) -> None:
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()
        return None


class FakeSource:
    """A ConnectionSource that mirrors ``Database.connection()``.

    Commits on a clean exit, rolls back when the block raises, and closes the
    connection afterwards — the same lifecycle the real source provides, so a
    repository's transaction behaviour can be asserted without a server.
    """

    def __init__(self, script: list[Any] | None = None) -> None:
        self.connection_obj = FakeConnection(script)

    @contextmanager
    def connection(self) -> Any:
        conn = self.connection_obj
        try:
            with conn:
                yield conn
        finally:
            conn.close()


def container(script: list[Any] | None = None) -> tuple[Any, FakeSource]:
    """Build a container bound to a fake source, one transaction per operation."""
    source = FakeSource(script)
    database = Database("postgresql://user:placeholder@localhost:5432/cloudpatrol")
    return postgres.PostgresContainer(source, database=database), source


# --- row builders ------------------------------------------------------------


def scan_row(**overrides: Any) -> dict[str, Any]:
    row = {
        "id": uuid.UUID(SCAN),
        "organization_id": uuid.UUID(ORG),
        "aws_account_id": uuid.UUID(ACCOUNT),
        "status": "queued",
        "started_at": None,
        "finished_at": None,
        "resource_count": 0,
        "finding_count": 0,
        "partial_failures": [],
        "error_message": None,
        "created_by": uuid.UUID(USER),
        "created_at": NOW,
        "attempts": 0,
    }
    row.update(overrides)
    return row


def finding_row(**overrides: Any) -> dict[str, Any]:
    row = {
        "id": uuid.UUID(FINDING),
        "organization_id": uuid.UUID(ORG),
        "scan_id": uuid.UUID(SCAN),
        "aws_account_id": uuid.UUID(ACCOUNT),
        "detector": "unattached_ebs",
        "resource_type": "ebs_volume",
        "resource_id": "vol-1",
        "region": "us-east-1",
        "severity": "medium",
        "confidence": "high",
        "state": "estimated",
        "title": "Unattached volume",
        "summary": "A volume is not attached.",
        "evidence": {"size_gb": 100},
        "recommended_action": "Delete it.",
        "estimated_monthly_savings": Decimal("8.00"),
        "currency": "USD",
        "dedupe_key": "key-1",
        "created_at": NOW,
        "updated_at": NOW,
    }
    row.update(overrides)
    return row


def cost_row(**overrides: Any) -> dict[str, Any]:
    row = {
        "id": uuid.UUID(FINDING),
        "organization_id": uuid.UUID(ORG),
        "aws_account_id": uuid.UUID(ACCOUNT),
        "scan_id": uuid.UUID(SCAN),
        "service": "AmazonEC2",
        "amount": Decimal("12.3400"),
        "currency": "USD",
        "period_start": date(2026, 1, 1),
        "period_end": date(2026, 2, 1),
        "created_at": NOW,
    }
    row.update(overrides)
    return row


# --- parameterization --------------------------------------------------------


def test_values_are_passed_as_parameters_not_interpolated() -> None:
    """A value must never appear in the SQL text.

    This is the property that makes injection impossible: the statement is
    static and the value travels as a bound parameter.
    """
    c, source = container([scan_row(status="queued")])
    hostile = "'; drop table scans; --"
    c.scans.get(ORG, hostile)

    sql_text, params = source.connection_obj.cursor_obj.executed[-1]
    assert hostile not in sql_text
    assert params == (hostile, ORG)
    assert "%s" in sql_text


def test_column_names_are_identifiers_not_raw_text() -> None:
    """Identifiers are quoted, so a column name cannot smuggle syntax."""
    c, source = container([scan_row()])
    c.scans.update(SCAN, status="running")

    sql_text, _ = source.connection_obj.cursor_obj.executed[-1]
    assert '"status"' in sql_text
    assert "update" in sql_text.lower()


def test_unknown_column_is_rejected_before_any_sql_runs() -> None:
    """An allow-list, not a blacklist: an unlisted column never reaches the SQL."""
    c, source = container([scan_row()])
    with pytest.raises(ValueError, match="Unsupported column"):
        c.scans.update(SCAN, drop_me="x")
    assert source.connection_obj.cursor_obj.executed == []


def test_empty_update_is_rejected() -> None:
    c, _ = container([scan_row()])
    with pytest.raises(ValueError, match="at least one field"):
        c.scans.update(SCAN)


# --- row mapping -------------------------------------------------------------


def test_scan_row_maps_uuids_and_timestamps_to_the_model() -> None:
    c, _ = container([scan_row(status="partial", attempts=3)])
    record = c.scans.get_by_id(SCAN)

    assert isinstance(record, ScanRecord)
    assert record.id == SCAN
    assert record.organization_id == ORG
    assert record.aws_account_id == ACCOUNT
    assert record.attempts == 3
    assert record.created_by == USER
    assert record.created_at == NOW


def test_scan_maps_nullable_columns_to_none() -> None:
    c, _ = container(
        [scan_row(created_by=None, started_at=None, finished_at=None, error_message=None)]
    )
    record = c.scans.get_by_id(SCAN)

    assert record is not None
    assert record.created_by is None
    assert record.started_at is None
    assert record.finished_at is None
    assert record.error_message is None


def test_missing_row_returns_none() -> None:
    c, _ = container([None])
    assert c.scans.get(ORG, SCAN) is None


def test_cost_period_dates_are_converted_to_strings() -> None:
    """``period_start`` is a ``date`` in PostgreSQL and a ``str`` in the model."""
    c, _ = container([[cost_row()]])
    records = c.costs.list_for_org(ORG)

    assert len(records) == 1
    assert isinstance(records[0], CostObservationRecord)
    assert records[0].period_start == "2026-01-01"
    assert records[0].period_end == "2026-02-01"
    assert records[0].amount == Decimal("12.3400")


def test_finding_evidence_json_is_mapped() -> None:
    c, _ = container([[finding_row()]])
    records = c.findings.list_for_org(ORG)

    assert records[0].evidence == {"size_gb": 100}
    assert records[0].estimated_monthly_savings == Decimal("8.00")


def test_nullable_savings_amount_maps_to_none() -> None:
    """NULL means "we could not price this", which is not the same as 0.00."""
    c, _ = container([[finding_row(estimated_monthly_savings=None)]])
    records = c.findings.list_for_org(ORG)

    assert records[0].estimated_monthly_savings is None


def test_resource_attributes_json_is_mapped() -> None:
    row = {
        "id": uuid.UUID(FINDING),
        "organization_id": uuid.UUID(ORG),
        "scan_id": uuid.UUID(SCAN),
        "aws_account_id": uuid.UUID(ACCOUNT),
        "resource_type": "ebs_volume",
        "resource_id": "vol-1",
        "region": "us-east-1",
        "name": None,
        "state": "available",
        "attributes": {"size_gb": 100},
        "created_at": NOW,
    }
    c, _ = container([[row]])
    records = c.resources.list_for_scan(ORG, SCAN)

    assert isinstance(records[0], ResourceSnapshotRecord)
    assert records[0].attributes == {"size_gb": 100}
    assert records[0].name is None


def test_audit_event_metadata_is_mapped() -> None:
    row = {
        "id": uuid.UUID(FINDING),
        "organization_id": uuid.UUID(ORG),
        "actor_user_id": None,
        "action": "scan.failed",
        "target_type": "scan",
        "target_id": SCAN,
        "metadata": {"code": "not_found"},
        "created_at": NOW,
    }
    c, _ = container([[row]])
    events = c.audit.list_for_org(ORG)

    assert isinstance(events[0], AuditEventRecord)
    assert events[0].metadata == {"code": "not_found"}
    assert events[0].actor_user_id is None


def test_savings_record_maps_decimals_and_nulls() -> None:
    row = {
        "id": uuid.UUID(FINDING),
        "organization_id": uuid.UUID(ORG),
        "aws_account_id": uuid.UUID(ACCOUNT),
        "finding_id": uuid.UUID(FINDING),
        "basis": "potential",
        "monthly_amount": Decimal("8.00"),
        "currency": "USD",
        "evidence": None,
        "measured_from": None,
        "measured_to": None,
        "created_by": uuid.UUID(USER),
        "created_at": NOW,
    }
    c, _ = container([row])
    record = c.savings.find_for_finding(ORG, FINDING, basis="potential")

    assert isinstance(record, SavingsRecord)
    assert record.monthly_amount == Decimal("8.00")
    assert record.evidence is None
    assert record.created_by == USER


def test_aws_account_regions_array_is_mapped_to_a_list() -> None:
    row = {
        "id": uuid.UUID(ACCOUNT),
        "organization_id": uuid.UUID(ORG),
        "label": "prod",
        "account_id": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/CloudPatrolReadOnly",
        "regions": ["us-east-1", "eu-west-1"],
        "status": "validated",
        "status_message": None,
        "external_id_ref": "aws-account/ref/external-id",
        "last_validated_at": None,
        "created_by": uuid.UUID(USER),
        "created_at": NOW,
    }
    c, _ = container([row])
    record = c.aws_accounts.get(ORG, ACCOUNT)

    assert isinstance(record, AwsAccountRecord)
    assert record.regions == ["us-east-1", "eu-west-1"]
    assert record.external_id_ref == "aws-account/ref/external-id"


# --- tenant scoping ----------------------------------------------------------


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.scans.list_for_org(ORG),
        lambda c: c.scans.get(ORG, SCAN),
        lambda c: c.scans.find_active_for_account(ORG, ACCOUNT),
        lambda c: c.aws_accounts.list_for_org(ORG),
        lambda c: c.aws_accounts.get(ORG, ACCOUNT),
        lambda c: c.aws_accounts.find_by_account_id(ORG, "123456789012"),
        lambda c: c.resources.list_for_scan(ORG, SCAN),
        lambda c: c.findings.list_for_org(ORG),
        lambda c: c.findings.get(ORG, FINDING),
        lambda c: c.savings.list_for_org(ORG),
        lambda c: c.savings.get(ORG, FINDING),
        lambda c: c.savings.find_for_finding(ORG, FINDING, basis="potential"),
        lambda c: c.costs.list_for_org(ORG),
        lambda c: c.audit.list_for_org(ORG),
        lambda c: c.organizations.get_membership(USER, ORG),
    ],
)
def test_tenant_scoped_reads_filter_by_organization(call: Any) -> None:
    """Every tenant-scoped read must carry the organization predicate."""
    c, source = container([[], None])
    call(c)

    sql_text, params = source.connection_obj.cursor_obj.executed[-1]
    assert "organization_id = %s" in sql_text, sql_text
    assert ORG in params, params


def test_unscoped_reads_are_only_the_worker_ones() -> None:
    """``get_by_id`` and ``find_stale_active`` are the two unscoped reads.

    They exist for the background worker and the reaper, which act on scans that
    already exist and carry their own organization. No route may call them.
    """

    def where_clause(statement: str) -> str:
        # The RETURNING list names every column, so only the WHERE clause shows
        # whether the read is scoped.
        return statement.split(" where ", 1)[1].split(" returning ", 1)[0]

    c, source = container([scan_row()])
    c.scans.get_by_id(SCAN)
    sql_text, _ = source.connection_obj.cursor_obj.executed[-1]
    assert "organization_id" not in where_clause(sql_text)

    c2, source2 = container([[]])
    c2.scans.find_stale_active(active_before=NOW)
    sql_text2, _ = source2.connection_obj.cursor_obj.executed[-1]
    assert "organization_id" not in where_clause(sql_text2)


def test_find_active_for_account_filters_active_statuses() -> None:
    c, source = container([None])
    c.scans.find_active_for_account(ORG, ACCOUNT)

    sql_text, params = source.connection_obj.cursor_obj.executed[-1]
    assert "status = any(%s)" in sql_text
    assert list(postgres._ACTIVE_SCAN_STATUSES) in params


def test_findings_list_applies_optional_filters() -> None:
    c, source = container([[]])
    c.findings.list_for_org(ORG, state="dismissed", aws_account_id=ACCOUNT)

    sql_text, params = source.connection_obj.cursor_obj.executed[-1]
    assert "state = %s" in sql_text
    assert "aws_account_id = %s" in sql_text
    assert params == [ORG, "dismissed", ACCOUNT]


# --- conflict translation ----------------------------------------------------


def test_duplicate_slug_becomes_a_conflict() -> None:
    """A globally unique slug conflict must not surface as a raw database error."""
    c, _ = container([unique_violation("organizations_slug_key")])
    with pytest.raises(ConflictError) as excinfo:
        c.organizations.create_organization(name="Acme", slug="acme", owner_user_id=USER)
    assert "slug" in excinfo.value.message


def test_other_unique_violation_on_organization_becomes_a_conflict() -> None:
    c, _ = container([unique_violation("organizations_pkey")])
    with pytest.raises(ConflictError):
        c.organizations.create_organization(name="Acme", slug="acme", owner_user_id=USER)


def test_foreign_key_violation_on_organization_becomes_not_found() -> None:
    """An owner that is not a real auth user is a 404, not a 500."""
    c, _ = container([ForeignKeyViolation("insert or update violates foreign key")])
    with pytest.raises(NotFoundError):
        c.organizations.create_organization(name="Acme", slug="acme", owner_user_id=USER)


def test_duplicate_scan_becomes_a_conflict() -> None:
    c, _ = container([unique_violation("scans_one_active_per_account_idx")])
    with pytest.raises(ConflictError, match="already in progress"):
        c.scans.create(
            organization_id=ORG,
            aws_account_id=ACCOUNT,
            status="queued",
            started_at=None,
            finished_at=None,
            resource_count=0,
            finding_count=0,
            partial_failures=[],
            error_message=None,
            created_by=USER,
        )


def test_duplicate_ledger_entry_becomes_a_conflict() -> None:
    c, _ = container([unique_violation("savings_records_finding_basis_idx")])
    with pytest.raises(ConflictError, match="already exists"):
        c.savings.create(
            organization_id=ORG,
            aws_account_id=ACCOUNT,
            finding_id=FINDING,
            basis="potential",
            monthly_amount=Decimal("8.00"),
            currency="USD",
            evidence=None,
            measured_from=None,
            measured_to=None,
            created_by=USER,
        )


def test_check_violation_becomes_a_conflict_not_a_500() -> None:
    """An invalid row is a caller error; it must not look like a server fault."""
    c, _ = container([CheckViolation("new row violates check constraint")])
    with pytest.raises(ConflictError):
        c.aws_accounts.create(
            organization_id=ORG,
            label="prod",
            account_id="123456789012",
            role_arn="not-an-arn",
            regions=["us-east-1"],
            status="pending",
            status_message=None,
            last_validated_at=None,
            external_id_ref=None,
            created_by=USER,
        )


def test_unexpected_error_is_not_swallowed() -> None:
    """Only known conflicts are translated; anything else propagates untouched."""
    c, _ = container([RuntimeError("connection reset")])
    with pytest.raises(RuntimeError, match="connection reset"):
        c.scans.list_for_org(ORG)


# --- upsert semantics --------------------------------------------------------


def test_upsert_preserves_state_and_created_at_in_the_statement() -> None:
    """The DO UPDATE set-list must not touch ``state`` or ``created_at``.

    This is the SQL-level guarantee that a re-scan cannot revert an
    acknowledgement or a dismissal, nor move the original discovery time.
    """
    c, source = container([{**finding_row(), "inserted": False}])
    record = FindingRecord(
        id=FINDING,
        organization_id=ORG,
        scan_id=SCAN,
        aws_account_id=ACCOUNT,
        detector="unattached_ebs",
        resource_type="ebs_volume",
        resource_id="vol-1",
        region="us-east-1",
        severity="medium",
        confidence="high",
        state="estimated",
        title="Unattached volume",
        summary="A volume is not attached.",
        evidence={"size_gb": 100},
        recommended_action="Delete it.",
        estimated_monthly_savings=Decimal("8.00"),
        currency="USD",
        dedupe_key="key-1",
        created_at=NOW,
        updated_at=NOW,
    )
    c.findings.upsert_many([record])

    sql_text, _ = source.connection_obj.cursor_obj.executed[-1]
    update_clause = sql_text.split("do update set", 1)[1]
    assert "state = " not in update_clause
    assert "created_at = " not in update_clause
    # The observation fields are refreshed.
    assert "scan_id = excluded.scan_id" in update_clause
    assert "evidence = excluded.evidence" in update_clause
    assert "updated_at = now()" in update_clause


def test_upsert_conflict_target_matches_the_unique_index() -> None:
    c, source = container([{**finding_row(), "inserted": True}])
    c.findings.upsert_many(
        [
            FindingRecord(
                id=FINDING,
                organization_id=ORG,
                scan_id=SCAN,
                aws_account_id=ACCOUNT,
                detector="d",
                resource_type="t",
                resource_id="r",
                region="us-east-1",
                severity="low",
                confidence="low",
                state="estimated",
                title="t",
                summary="s",
                evidence={},
                recommended_action="a",
                estimated_monthly_savings=None,
                currency="USD",
                dedupe_key="k",
                created_at=NOW,
                updated_at=NOW,
            )
        ]
    )
    sql_text, _ = source.connection_obj.cursor_obj.executed[-1]
    assert "on conflict (aws_account_id, dedupe_key)" in sql_text


def test_upsert_counts_inserted_and_refreshed_separately() -> None:
    """A re-scan that re-confirms known findings is not the same as finding none."""
    c, _ = container([{**finding_row(), "inserted": True}, {**finding_row(), "inserted": False}])
    result = c.findings.upsert_many([_finding_model(), _finding_model()])

    assert result.inserted == 1
    assert result.refreshed == 1
    assert result.total == 2


def test_upsert_with_no_records_does_not_touch_the_database() -> None:
    c, source = container([])
    result = c.findings.upsert_many([])

    assert result.total == 0
    assert source.connection_obj.cursor_obj.executed == []


def _finding_model() -> FindingRecord:
    return FindingRecord(
        id=FINDING,
        organization_id=ORG,
        scan_id=SCAN,
        aws_account_id=ACCOUNT,
        detector="d",
        resource_type="t",
        resource_id="r",
        region="us-east-1",
        severity="low",
        confidence="low",
        state="estimated",
        title="t",
        summary="s",
        evidence={},
        recommended_action="a",
        estimated_monthly_savings=None,
        currency="USD",
        dedupe_key="k",
        created_at=NOW,
        updated_at=NOW,
    )


# --- scan claim and stale transitions ----------------------------------------


def test_mark_running_is_a_conditional_single_statement() -> None:
    """The claim must be one statement gated on the queued status."""
    c, source = container([scan_row(status="running", attempts=1)])
    record = c.scans.mark_running(SCAN, started_at=NOW)

    assert record.attempts == 1
    sql_text, params = source.connection_obj.cursor_obj.executed[-1]
    assert sql_text.lower().startswith("update")
    assert "status = 'running'" in sql_text
    assert "attempts = attempts + 1" in sql_text
    assert "status = 'queued'" in sql_text
    assert params == (NOW, SCAN)


def test_mark_running_conflicts_when_already_claimed() -> None:
    """No row returned means the scan was not queued: a second worker lost."""
    c, _ = container([None])
    with pytest.raises(ConflictError, match="already been claimed"):
        c.scans.mark_running(SCAN, started_at=NOW)


def test_fail_if_stale_is_a_conditional_single_statement() -> None:
    """The staleness test must be in the WHERE clause, not a prior read."""
    cutoff = NOW - timedelta(seconds=60)
    c, source = container([{"id": uuid.UUID(SCAN)}])
    assert c.scans.fail_if_stale(SCAN, active_before=cutoff, message="interrupted") is True

    sql_text, params = source.connection_obj.cursor_obj.executed[-1]
    assert sql_text.lower().startswith("update")
    assert "status = 'failed'" in sql_text
    assert "coalesce(started_at, created_at) < %s" in sql_text
    assert "status = any(%s)" in sql_text
    assert params == ("interrupted", SCAN, list(postgres._ACTIVE_SCAN_STATUSES), cutoff)


def test_fail_if_stale_returns_false_when_no_longer_stale() -> None:
    """A worker claimed the scan in the meantime, so the reaper's write is a no-op."""
    c, _ = container([None])
    assert c.scans.fail_if_stale(SCAN, active_before=NOW, message="x") is False


def test_find_stale_active_uses_coalesce_for_the_measurement_point() -> None:
    c, source = container([[]])
    c.scans.find_stale_active(active_before=NOW)

    sql_text, params = source.connection_obj.cursor_obj.executed[-1]
    assert "coalesce(started_at, created_at) < %s" in sql_text
    assert params == (list(postgres._ACTIVE_SCAN_STATUSES), NOW)


def test_create_if_no_active_is_a_guarded_insert() -> None:
    c, source = container([scan_row()])
    c.scans.create_if_no_active(
        organization_id=ORG,
        aws_account_id=ACCOUNT,
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by=USER,
    )

    sql_text, params = source.connection_obj.cursor_obj.executed[-1]
    assert "where not exists" in sql_text
    assert "aws_account_id = %s and status = any(%s)" in sql_text
    assert ACCOUNT in params


def test_create_if_no_active_conflicts_when_guard_matches() -> None:
    """No row returned means the guard clause found an active scan."""
    c, _ = container([None])
    with pytest.raises(ConflictError, match="already in progress"):
        c.scans.create_if_no_active(
            organization_id=ORG,
            aws_account_id=ACCOUNT,
            status="queued",
            started_at=None,
            finished_at=None,
            resource_count=0,
            finding_count=0,
            partial_failures=[],
            error_message=None,
            created_by=USER,
        )


def test_create_if_no_active_conflicts_on_the_unique_index_race() -> None:
    """The partial unique index is the backstop for two concurrent callers."""
    c, _ = container([unique_violation("scans_one_active_per_account_idx")])
    with pytest.raises(ConflictError, match="already in progress"):
        c.scans.create_if_no_active(
            organization_id=ORG,
            aws_account_id=ACCOUNT,
            status="queued",
            started_at=None,
            finished_at=None,
            resource_count=0,
            finding_count=0,
            partial_failures=[],
            error_message=None,
            created_by=USER,
        )


# --- cost deduplication ------------------------------------------------------


def test_cost_insert_uses_the_natural_key_conflict_target() -> None:
    c, source = container([])
    c.costs.add_many(
        [
            CostObservationRecord(
                id=FINDING,
                organization_id=ORG,
                aws_account_id=ACCOUNT,
                scan_id=SCAN,
                service="AmazonEC2",
                amount=Decimal("12.3400"),
                currency="USD",
                period_start="2026-01-01",
                period_end="2026-02-01",
                created_at=NOW,
            )
        ]
    )

    sql_text, _ = source.connection_obj.cursor_obj.executed[-1]
    assert "on conflict (aws_account_id, scan_id, service, period_start) do nothing" in sql_text


def test_cost_insert_returns_the_number_of_rows_inserted() -> None:
    """A repeat import inserts nothing, so the count distinguishes it from the first."""
    source = FakeSource([])
    conn = source.connection_obj

    # First call: the row inserts, rowcount 1.
    class OneInsertCursor(FakeCursor):
        def execute(self, query: Any, params: Any = None, **_: Any) -> Any:
            super().execute(query, params)
            self.rowcount = 1
            return self

    conn.cursor_obj = OneInsertCursor([])
    database = Database("postgresql://user:placeholder@localhost:5432/db")
    c = build_postgres_container(database, connection=conn)
    assert c.costs.add_many([_cost_model()]) == 1

    # Second call: the conflict skips it, rowcount 0.
    class NoInsertCursor(FakeCursor):
        def execute(self, query: Any, params: Any = None, **_: Any) -> Any:
            super().execute(query, params)
            self.rowcount = 0
            return self

    conn.cursor_obj = NoInsertCursor([])
    assert c.costs.add_many([_cost_model()]) == 0


def test_cost_add_many_with_no_records_does_not_touch_the_database() -> None:
    c, source = container([])
    assert c.costs.add_many([]) == 0
    assert source.connection_obj.cursor_obj.executed == []


def _cost_model() -> CostObservationRecord:
    return CostObservationRecord(
        id=FINDING,
        organization_id=ORG,
        aws_account_id=ACCOUNT,
        scan_id=SCAN,
        service="AmazonEC2",
        amount=Decimal("12.3400"),
        currency="USD",
        period_start="2026-01-01",
        period_end="2026-02-01",
        created_at=NOW,
    )


# --- transaction boundaries --------------------------------------------------


def test_organization_creation_commits_once_with_both_rows() -> None:
    """Organization and owner membership are written in one transaction."""
    c, source = container(
        [{"id": uuid.UUID(ORG), "name": "Acme", "slug": "acme", "created_at": NOW}]
    )
    organization = c.organizations.create_organization(name="Acme", slug="acme", owner_user_id=USER)

    assert organization.id == ORG
    executed = source.connection_obj.cursor_obj.executed
    assert len(executed) == 2
    assert "insert into" in executed[0][0] and "organizations" in executed[0][0]
    assert "insert into" in executed[1][0] and "memberships" in executed[1][0]
    assert source.connection_obj.committed is True
    assert source.connection_obj.rolled_back is False
    assert source.connection_obj.closed is True


def test_organization_creation_rolls_back_when_membership_insert_fails() -> None:
    """A failure in the second insert must not leave an ownerless organization."""
    c, source = container(
        [{"id": uuid.UUID(ORG), "name": "Acme", "slug": "acme", "created_at": NOW}]
    )
    source.connection_obj.cursor_obj._script.append(
        ForeignKeyViolation("insert or update violates foreign key constraint")
    )

    with pytest.raises(NotFoundError):
        c.organizations.create_organization(name="Acme", slug="acme", owner_user_id=USER)

    assert source.connection_obj.rolled_back is True
    assert source.connection_obj.committed is False


def test_rollback_on_failure_inside_a_transaction_block() -> None:
    """A raised error inside ``with conn`` rolls back; a clean exit commits."""
    conn = FakeConnection()
    try:
        with conn:
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert conn.rolled_back is True
    assert conn.committed is False

    clean = FakeConnection()
    with clean:
        pass
    assert clean.committed is True


def test_database_transaction_yields_a_container_sharing_one_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The unit of work binds every repository to one connection and transaction.

    ``psycopg.connect`` is replaced so no server is needed; what is asserted is
    that the container handed to the caller is bound to that one connection, so
    its writes share a transaction.
    """
    conn = FakeConnection(
        [{"id": uuid.UUID(ORG), "name": "Acme", "slug": "acme", "created_at": NOW}]
    )
    opened: list[Any] = []

    def fake_connect(*args: Any, **kwargs: Any) -> FakeConnection:
        opened.append((args, kwargs))
        return conn

    monkeypatch.setattr(postgres.psycopg, "connect", fake_connect)

    database = Database("postgresql://user:placeholder@localhost:5432/db")
    with database.transaction() as scoped:
        organization = scoped.organizations.create_organization(
            name="Acme", slug="acme", owner_user_id=USER
        )

    assert organization.id == ORG
    # One connection was opened for the whole block, and it was committed once.
    assert len(opened) == 1
    assert conn.committed is True
    assert conn.closed is True
    # Both inserts went to that connection, in order.
    executed = conn.cursor_obj.executed
    assert len(executed) == 2
    assert "organizations" in executed[0][0]
    assert "memberships" in executed[1][0]


def test_database_transaction_rolls_back_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure inside the unit of work leaves nothing committed."""
    conn = FakeConnection(
        [{"id": uuid.UUID(ORG), "name": "Acme", "slug": "acme", "created_at": NOW}]
    )
    conn.cursor_obj._script.append(ForeignKeyViolation("fk"))

    monkeypatch.setattr(postgres.psycopg, "connect", lambda *a, **k: conn)

    database = Database("postgresql://user:placeholder@localhost:5432/db")
    with pytest.raises(NotFoundError), database.transaction() as scoped:
        scoped.organizations.create_organization(name="Acme", slug="acme", owner_user_id=USER)

    assert conn.rolled_back is True
    assert conn.committed is False


def test_build_postgres_container_opens_no_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Constructing the container must not touch the network.

    ``psycopg.connect`` is replaced with one that fails, so any eager connection
    during construction would raise.
    """

    def explode(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("no connection may be opened while building a container")

    monkeypatch.setattr(postgres.psycopg, "connect", explode)
    database = Database("postgresql://user:placeholder@localhost:5432/db")
    c = build_postgres_container(database)
    # The repositories exist but nothing has connected.
    assert c.scans is not None
    assert c.database is database


def test_database_repr_never_leaks_the_dsn() -> None:
    """The DSN embeds a password and must not appear in a repr or str."""
    database = Database("postgresql://user:secret-password@localhost:5432/db")
    assert "secret-password" not in repr(database)
    assert "secret-password" not in str(database)
    assert repr(database) == "Database(dsn=***)"


def test_resource_add_many_is_idempotent_per_scan() -> None:
    c, source = container([])
    c.resources.add_many(
        [
            ResourceSnapshotRecord(
                id=FINDING,
                organization_id=ORG,
                scan_id=SCAN,
                aws_account_id=ACCOUNT,
                resource_type="ebs_volume",
                resource_id="vol-1",
                region="us-east-1",
                name=None,
                state="available",
                attributes={},
                created_at=NOW,
            )
        ]
    )

    sql_text, _ = source.connection_obj.cursor_obj.executed[-1]
    assert "on conflict (scan_id, resource_type, resource_id, region) do nothing" in sql_text


def test_audit_record_drops_a_non_uuid_actor() -> None:
    """The reaper's "system" actor would fail the FK, so it is recorded as null."""
    c, source = container(
        [
            {
                "id": uuid.UUID(FINDING),
                "organization_id": uuid.UUID(ORG),
                "actor_user_id": None,
                "action": "scan.reaped",
                "target_type": "scan",
                "target_id": SCAN,
                "metadata": {},
                "created_at": NOW,
            }
        ]
    )
    c.audit.record(
        organization_id=ORG,
        actor_user_id="system",
        action="scan.reaped",
        target_type="scan",
        target_id=SCAN,
        metadata={},
    )

    _, params = source.connection_obj.cursor_obj.executed[-1]
    assert None in params
    assert "system" not in params


def test_audit_record_keeps_a_uuid_actor() -> None:
    c, source = container(
        [
            {
                "id": uuid.UUID(FINDING),
                "organization_id": uuid.UUID(ORG),
                "actor_user_id": uuid.UUID(USER),
                "action": "scan.failed",
                "target_type": "scan",
                "target_id": SCAN,
                "metadata": {},
                "created_at": NOW,
            }
        ]
    )
    c.audit.record(
        organization_id=ORG,
        actor_user_id=USER,
        action="scan.failed",
        target_type="scan",
        target_id=SCAN,
        metadata={},
    )

    _, params = source.connection_obj.cursor_obj.executed[-1]
    assert USER in params


# --- connection hygiene ------------------------------------------------------


def test_connections_are_closed_after_each_operation() -> None:
    c, source = container([scan_row()])
    c.scans.get_by_id(SCAN)
    assert source.connection_obj.closed is True


def test_json_columns_are_wrapped_for_psycopg() -> None:
    """A plain dict would be rejected by psycopg; Jsonb serialises it."""
    c, source = container([scan_row()])
    c.scans.update(SCAN, partial_failures=[{"service": "ec2"}])

    _, params = source.connection_obj.cursor_obj.executed[-1]
    from psycopg.types.json import Jsonb

    assert any(isinstance(p, Jsonb) for p in params)


def test_regions_placeholder_is_cast_to_text_array() -> None:
    row = {
        "id": uuid.UUID(ACCOUNT),
        "organization_id": uuid.UUID(ORG),
        "label": "prod",
        "account_id": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/R",
        "regions": ["us-east-1"],
        "status": "pending",
        "status_message": None,
        "external_id_ref": None,
        "last_validated_at": None,
        "created_by": uuid.UUID(USER),
        "created_at": NOW,
    }
    c, source = container([row])
    c.aws_accounts.create(
        organization_id=ORG,
        label="prod",
        account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/R",
        regions=["us-east-1"],
        status="pending",
        status_message=None,
        last_validated_at=None,
        external_id_ref=None,
        created_by=USER,
    )

    sql_text, _ = source.connection_obj.cursor_obj.executed[-1]
    assert "%s::text[]" in sql_text


def test_cost_period_placeholders_are_cast_to_date() -> None:
    c, source = container([])
    c.costs.add_many([_cost_model()])

    sql_text, _ = source.connection_obj.cursor_obj.executed[-1]
    assert "%s::date" in sql_text
