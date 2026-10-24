"""Real-PostgreSQL integration tests for the repository layer.

Every test here runs against a live PostgreSQL server and the real migrations.
Nothing is mocked: the statements are composed by ``app.repositories.postgres``
and executed by psycopg, so a malformed statement, a wrong column name, a type
mismatch or a constraint that does not exist fails here and only here. The
fake-connection unit tests in ``tests/test_postgres_repositories.py`` check the
*shape* of the SQL; these check that it actually works.

The suite is skipped entirely unless ``TEST_DATABASE_URL`` is set. See
``conftest.py`` and ``_harness.py`` for the isolation and fail-closed argument.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import psycopg
import pytest

from app.core.errors import ConflictError, NotFoundError
from app.repositories.models import (
    CostObservationRecord,
    FindingRecord,
    ResourceSnapshotRecord,
)

from ._harness import rls_connection

pytestmark = pytest.mark.integration


def _now() -> datetime:
    return datetime.now(UTC)


def _finding(
    *,
    organization_id: str,
    account_id: str,
    scan_id: str,
    dedupe_key: str = "dedupe-1",
    state: str = "estimated",
    title: str = "Unattached EBS volume",
    savings: Decimal | None = Decimal("8.00"),
) -> FindingRecord:
    return FindingRecord(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        scan_id=scan_id,
        aws_account_id=account_id,
        detector="unattached_ebs",
        resource_type="ebs_volume",
        resource_id="vol-0123456789abcdef0",
        region="us-east-1",
        severity="medium",
        confidence="high",
        state=state,
        title=title,
        summary="Volume has been unattached for 30 days.",
        evidence={"size_gb": 100, "age_days": 30},
        recommended_action="Snapshot and delete the volume.",
        estimated_monthly_savings=savings,
        currency="USD",
        dedupe_key=dedupe_key,
        created_at=_now(),
        updated_at=_now(),
    )


# ---------------------------------------------------------------------------
# Migrations actually ran against this database
# ---------------------------------------------------------------------------


def test_migrations_created_the_expected_tables(ephemeral_database, conn) -> None:
    """The schema the tests depend on exists in *this* database.

    Without this, a harness that silently applied nothing would let every other
    test fail with a confusing "relation does not exist" instead of one clear
    message.
    """
    rows = conn.execute("select tablename from pg_tables where schemaname = 'public'").fetchall()
    present = {row[0] for row in rows}
    expected = {
        "organizations",
        "memberships",
        "aws_accounts",
        "scans",
        "resource_snapshots",
        "findings",
        "finding_reviews",
        "savings_records",
        "cost_observations",
        "audit_events",
    }
    assert expected <= present, f"missing tables: {sorted(expected - present)}"


def test_migration_0004_columns_are_present(conn) -> None:
    """``attempts`` and ``created_by`` come from 0004 and must have applied."""
    columns = {
        row[0]
        for row in conn.execute(
            "select column_name from information_schema.columns "
            "where table_name = 'scans' and table_schema = 'public'"
        ).fetchall()
    }
    assert "attempts" in columns

    savings_columns = {
        row[0]
        for row in conn.execute(
            "select column_name from information_schema.columns "
            "where table_name = 'savings_records' and table_schema = 'public'"
        ).fetchall()
    }
    assert "created_by" in savings_columns


def test_the_partial_unique_index_for_active_scans_exists(conn) -> None:
    """The active-scan guarantee is an index, so its existence is the guarantee."""
    definition = conn.execute(
        "select indexdef from pg_indexes "
        "where schemaname = 'public' and indexname = 'scans_one_active_per_account_idx'"
    ).fetchone()
    assert definition is not None, "the active-scan index is missing"
    assert "WHERE" in definition[0], "the index must be partial, not over all statuses"


# ---------------------------------------------------------------------------
# CRUD and row-to-model mapping
# ---------------------------------------------------------------------------


def test_organization_round_trips_through_the_repository(container, org_factory) -> None:
    """A created organization reads back with every field mapped correctly."""
    seed = org_factory()
    fetched = container.organizations.get_organization(seed["organization_id"])
    assert fetched is not None
    assert fetched.name == seed["name"]
    assert fetched.slug == seed["slug"]
    assert isinstance(fetched.created_at, datetime)


def test_create_organization_writes_owner_membership(container, conn) -> None:
    """Creating an org and its owner membership is one unit of work.

    The membership is what makes the organization reachable at all, so it must
    exist immediately after the call returns.
    """
    user_id = str(uuid.uuid4())
    conn.execute(
        "insert into auth.users (id, email) values (%s, %s)", (user_id, "owner@example.test")
    )
    slug = f"slug-{uuid.uuid4().hex[:12]}"
    org = container.organizations.create_organization(
        name="Created Org", slug=slug, owner_user_id=user_id
    )

    membership = container.organizations.get_membership(user_id, org.id)
    assert membership is not None
    assert membership.role == "owner"
    assert membership.organization_id == org.id

    listed = container.organizations.list_memberships(user_id)
    assert [m.organization_id for m in listed] == [org.id]


def test_duplicate_slug_raises_conflict(container, conn) -> None:
    """``organizations.slug`` is globally unique; a repeat must be a conflict.

    This exercises the real ``UniqueViolation`` and the constraint-name check
    that distinguishes it, which a fake cursor cannot do faithfully.
    """
    user_id = str(uuid.uuid4())
    conn.execute(
        "insert into auth.users (id, email) values (%s, %s)", (user_id, "dup@example.test")
    )
    slug = f"dupe-{uuid.uuid4().hex[:12]}"
    container.organizations.create_organization(name="First", slug=slug, owner_user_id=user_id)

    with pytest.raises(ConflictError):
        container.organizations.create_organization(name="Second", slug=slug, owner_user_id=user_id)


def test_organization_slug_check_constraint_is_enforced(container, conn) -> None:
    """A malformed slug is rejected by the database, not just the schema layer."""
    user_id = str(uuid.uuid4())
    conn.execute(
        "insert into auth.users (id, email) values (%s, %s)", (user_id, "bad@example.test")
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "insert into public.organizations (name, slug) values (%s, %s)",
            ("Bad Slug", "Not A Slug"),
        )


def test_membership_requires_a_real_user(conn, org_factory) -> None:
    """``memberships.user_id`` references ``auth.users``; a ghost user is refused."""
    seed = org_factory()
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        conn.execute(
            "insert into public.memberships (organization_id, user_id, role) "
            "values (%s, %s, 'member')",
            (seed["organization_id"], str(uuid.uuid4())),
        )


def test_aws_account_regions_array_round_trips(container, org_factory) -> None:
    """A ``text[]`` column must come back as a Python list, not a string.

    This is exactly the class of bug a fake cursor hides: it returns whatever
    the test told it to, so an array-adaptation mistake would pass there.
    """
    seed = org_factory()
    account = container.aws_accounts.create(
        organization_id=seed["organization_id"],
        label="prod",
        account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/CloudPatrolReadOnly",
        regions=["us-east-1", "eu-west-1", "ap-southeast-2"],
        status="validated",
        status_message=None,
        external_id_ref="vault/ref/abc",
        last_validated_at=None,
        created_by=seed["user_id"],
    )
    assert account.regions == ["us-east-1", "eu-west-1", "ap-southeast-2"]

    fetched = container.aws_accounts.get(seed["organization_id"], account.id)
    assert fetched is not None
    assert fetched.regions == ["us-east-1", "eu-west-1", "ap-southeast-2"]


def test_aws_account_role_arn_must_match_account_id(conn, org_factory) -> None:
    """The cross-column check constraint rejects a mismatched ARN.

    A row claiming one account while pointing at another's role would be a
    confused-deputy risk, so the database refuses it.
    """
    seed = org_factory()
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "insert into public.aws_accounts "
            "(organization_id, label, account_id, role_arn, regions) "
            "values (%s, %s, %s, %s, %s)",
            (
                seed["organization_id"],
                "mismatch",
                "123456789012",
                "arn:aws:iam::999999999999:role/Other",
                ["us-east-1"],
            ),
        )


def test_same_aws_account_cannot_be_registered_twice(container, org_factory) -> None:
    """``unique (organization_id, account_id)`` prevents doubled findings."""
    seed = org_factory()
    fields = {
        "organization_id": seed["organization_id"],
        "label": "prod",
        "account_id": "210987654321",
        "role_arn": "arn:aws:iam::210987654321:role/CloudPatrolReadOnly",
        "regions": ["us-east-1"],
        "status": "validated",
        "status_message": None,
        "external_id_ref": None,
        "last_validated_at": None,
        "created_by": None,
    }
    container.aws_accounts.create(**fields)
    with pytest.raises(ConflictError):
        container.aws_accounts.create(**fields)


# ---------------------------------------------------------------------------
# Tenant-scoped reads and writes
# ---------------------------------------------------------------------------


def test_scans_list_is_scoped_to_the_organization(container, org_factory, conn) -> None:
    """A second tenant's scan must be invisible to the first.

    The in-memory store enforced this in Python; here it is enforced by the
    ``WHERE`` clause the repository composes, so this proves the clause is real.
    """
    tenant_a = org_factory("Tenant A")
    tenant_b = org_factory("Tenant B")
    account_a = _account_row(conn, tenant_a["organization_id"], "111111111111")
    account_b = _account_row(conn, tenant_b["organization_id"], "222222222222")

    scan_a = container.scans.create(
        organization_id=tenant_a["organization_id"],
        aws_account_id=account_a,
        status="completed",
        started_at=_now(),
        finished_at=_now(),
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by=None,
    )
    container.scans.create(
        organization_id=tenant_b["organization_id"],
        aws_account_id=account_b,
        status="completed",
        started_at=_now(),
        finished_at=_now(),
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by=None,
    )

    visible = container.scans.list_for_org(tenant_a["organization_id"])
    assert [s.id for s in visible] == [scan_a.id]

    # A direct cross-tenant read by id is also refused.
    assert container.scans.get(tenant_b["organization_id"], scan_a.id) is None


def test_findings_list_is_scoped_to_the_organization(container, conn, org_factory) -> None:
    tenant_a = org_factory("Tenant A")
    tenant_b = org_factory("Tenant B")
    account_a = _account_row(conn, tenant_a["organization_id"], "333333333333")
    account_b = _account_row(conn, tenant_b["organization_id"], "444444444444")
    scan_a = _scan_row(conn, tenant_a["organization_id"], account_a)
    scan_b = _scan_row(conn, tenant_b["organization_id"], account_b)

    container.findings.upsert_many(
        [
            _finding(
                organization_id=tenant_a["organization_id"],
                account_id=account_a,
                scan_id=scan_a,
                dedupe_key="a-1",
            )
        ]
    )
    container.findings.upsert_many(
        [
            _finding(
                organization_id=tenant_b["organization_id"],
                account_id=account_b,
                scan_id=scan_b,
                dedupe_key="b-1",
            )
        ]
    )

    a_findings = container.findings.list_for_org(tenant_a["organization_id"])
    assert len(a_findings) == 1
    assert a_findings[0].organization_id == tenant_a["organization_id"]


def test_cost_reads_are_scoped_to_the_organization(container, conn, org_factory) -> None:
    tenant_a = org_factory("Tenant A")
    tenant_b = org_factory("Tenant B")
    account_a = _account_row(conn, tenant_a["organization_id"], "555555555555")
    account_b = _account_row(conn, tenant_b["organization_id"], "666666666666")
    scan_a = _scan_row(conn, tenant_a["organization_id"], account_a)
    scan_b = _scan_row(conn, tenant_b["organization_id"], account_b)

    container.costs.add_many(
        [
            _cost(
                org=tenant_a["organization_id"],
                account=account_a,
                scan=scan_a,
                service="AmazonEC2",
                amount=Decimal("10.00"),
            )
        ]
    )
    container.costs.add_many(
        [
            _cost(
                org=tenant_b["organization_id"],
                account=account_b,
                scan=scan_b,
                service="AmazonS3",
                amount=Decimal("20.00"),
            )
        ]
    )

    a_costs = container.costs.list_for_org(tenant_a["organization_id"])
    assert [c.service for c in a_costs] == ["AmazonEC2"]


# ---------------------------------------------------------------------------
# Finding upsert preservation semantics
# ---------------------------------------------------------------------------


def test_reupsert_refreshes_evidence_and_preserves_state(container, conn, org_factory) -> None:
    """The core dedupe contract, against a real ``ON CONFLICT DO UPDATE``.

    A re-scan must refresh the observation but never revert a human decision or
    move the original discovery time.
    """
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "777777777777")
    scan = _scan_row(conn, seed["organization_id"], account)

    first = container.findings.upsert_many(
        [
            _finding(
                organization_id=seed["organization_id"],
                account_id=account,
                scan_id=scan,
                dedupe_key="key-preserve",
                title="Original title",
                savings=Decimal("8.00"),
            )
        ]
    )
    assert first.inserted == 1
    assert first.refreshed == 0
    original = first.records[0]

    # A human acknowledges the finding.
    container.findings.update(original.id, state="acknowledged")

    second = container.findings.upsert_many(
        [
            _finding(
                organization_id=seed["organization_id"],
                account_id=account,
                scan_id=scan,
                dedupe_key="key-preserve",
                title="Refreshed title",
                savings=Decimal("12.50"),
            )
        ]
    )
    assert second.inserted == 0
    assert second.refreshed == 1
    refreshed = second.records[0]

    assert refreshed.id == original.id, "the same row must be updated, not a new one inserted"
    assert refreshed.state == "acknowledged", "state must survive a re-scan"
    assert refreshed.title == "Refreshed title", "evidence must be refreshed"
    assert refreshed.estimated_monthly_savings == Decimal("12.50")
    assert refreshed.created_at == original.created_at, "discovery time must not move"

    # And the database agrees: exactly one row for that dedupe key.
    count = conn.execute(
        "select count(*) from public.findings where aws_account_id = %s and dedupe_key = %s",
        (account, "key-preserve"),
    ).fetchone()[0]
    assert count == 1


def test_dismissed_finding_stays_dismissed_across_a_rescan(container, conn, org_factory) -> None:
    """A dismissal is a decision; a later scan must not resurrect the finding."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "888888888888")
    scan = _scan_row(conn, seed["organization_id"], account)

    result = container.findings.upsert_many(
        [
            _finding(
                organization_id=seed["organization_id"],
                account_id=account,
                scan_id=scan,
                dedupe_key="key-dismiss",
            )
        ]
    )
    container.findings.update(result.records[0].id, state="dismissed")

    container.findings.upsert_many(
        [
            _finding(
                organization_id=seed["organization_id"],
                account_id=account,
                scan_id=scan,
                dedupe_key="key-dismiss",
            )
        ]
    )
    after = container.findings.get(seed["organization_id"], result.records[0].id)
    assert after is not None
    assert after.state == "dismissed"


def test_distinct_dedupe_keys_create_distinct_findings(container, conn, org_factory) -> None:
    """The unique index is per (account, dedupe_key), so different keys coexist."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "999999999999")
    scan = _scan_row(conn, seed["organization_id"], account)

    result = container.findings.upsert_many(
        [
            _finding(
                organization_id=seed["organization_id"],
                account_id=account,
                scan_id=scan,
                dedupe_key="key-a",
            ),
            _finding(
                organization_id=seed["organization_id"],
                account_id=account,
                scan_id=scan,
                dedupe_key="key-b",
            ),
        ]
    )
    assert result.inserted == 2
    assert len(container.findings.list_for_org(seed["organization_id"])) == 2


def test_null_savings_is_not_zero(container, conn, org_factory) -> None:
    """NULL means "not defensibly priced"; 0.00 means "saves nothing".

    The two must survive a database round trip as different values, because the
    UI renders them differently.
    """
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "101010101010")
    scan = _scan_row(conn, seed["organization_id"], account)

    unpriced = container.findings.upsert_many(
        [
            _finding(
                organization_id=seed["organization_id"],
                account_id=account,
                scan_id=scan,
                dedupe_key="key-null",
                savings=None,
            )
        ]
    )
    zero = container.findings.upsert_many(
        [
            _finding(
                organization_id=seed["organization_id"],
                account_id=account,
                scan_id=scan,
                dedupe_key="key-zero",
                savings=Decimal("0.00"),
            )
        ]
    )

    assert unpriced.records[0].estimated_monthly_savings is None
    assert zero.records[0].estimated_monthly_savings == Decimal("0.00")


# ---------------------------------------------------------------------------
# Resource snapshots
# ---------------------------------------------------------------------------


def test_resource_snapshot_deduplicates_within_a_scan(container, conn, org_factory) -> None:
    """``unique (scan_id, resource_type, resource_id, region)`` makes re-add a no-op."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "121212121212")
    scan = _scan_row(conn, seed["organization_id"], account)

    record = ResourceSnapshotRecord(
        id=str(uuid.uuid4()),
        organization_id=seed["organization_id"],
        scan_id=scan,
        aws_account_id=account,
        resource_type="ebs_volume",
        resource_id="vol-snapshot-test",
        region="us-east-1",
        name="data-vol",
        state="available",
        attributes={"size_gb": 50, "encrypted": True},
        created_at=_now(),
    )
    container.resources.add_many([record])
    # A second insert of the same natural key must not raise and must not duplicate.
    container.resources.add_many([record])

    stored = container.resources.list_for_scan(seed["organization_id"], scan)
    assert len(stored) == 1
    assert stored[0].attributes == {"size_gb": 50, "encrypted": True}


# ---------------------------------------------------------------------------
# Cost observations: deduplication and date conversion
# ---------------------------------------------------------------------------


def test_cost_observation_deduplicates_on_the_natural_key(container, conn, org_factory) -> None:
    """A re-scan must not double the reported bill."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "131313131313")
    scan = _scan_row(conn, seed["organization_id"], account)

    observation = _cost(
        org=seed["organization_id"],
        account=account,
        scan=scan,
        service="AmazonEC2",
        amount=Decimal("123.4500"),
    )
    first = container.costs.add_many([observation])
    assert first == 1, "the first import inserts"

    duplicate = _cost(
        org=seed["organization_id"],
        account=account,
        scan=scan,
        service="AmazonEC2",
        amount=Decimal("123.4500"),
    )
    second = container.costs.add_many([duplicate])
    assert second == 0, "the repeat is skipped, not inserted"

    stored = container.costs.list_for_org(seed["organization_id"])
    assert len(stored) == 1


def test_cost_period_dates_come_back_as_iso_strings(container, conn, org_factory) -> None:
    """A ``date`` column maps to the model's ``str``, not a ``date`` object.

    The model declares ``period_start: str``, so a mapping that returned a
    ``date`` would be a latent type error the fake-cursor tests cannot catch.
    """
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "141414141414")
    scan = _scan_row(conn, seed["organization_id"], account)

    container.costs.add_many(
        [
            _cost(
                org=seed["organization_id"],
                account=account,
                scan=scan,
                service="AmazonS3",
                amount=Decimal("5.00"),
                period_start="2026-01-01",
                period_end="2026-02-01",
            )
        ]
    )
    stored = container.costs.list_for_org(seed["organization_id"])[0]
    assert stored.period_start == "2026-01-01"
    assert isinstance(stored.period_start, str)
    assert stored.period_end == "2026-02-01"


def test_cost_amount_keeps_four_decimal_precision(container, conn, org_factory) -> None:
    """``numeric(14,4)`` must not be silently rounded to cents."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "151515151515")
    scan = _scan_row(conn, seed["organization_id"], account)

    container.costs.add_many(
        [
            _cost(
                org=seed["organization_id"],
                account=account,
                scan=scan,
                service="AWS Lambda",
                amount=Decimal("0.1234"),
            )
        ]
    )
    stored = container.costs.list_for_org(seed["organization_id"])[0]
    assert stored.amount == Decimal("0.1234")


def test_cost_period_order_constraint_is_enforced(conn, org_factory) -> None:
    """``period_end >= period_start`` is a database check, not a convention."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "161616161616")
    scan = _scan_row(conn, seed["organization_id"], account)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "insert into public.cost_observations "
            "(organization_id, aws_account_id, scan_id, service, amount, period_start, period_end) "
            "values (%s, %s, %s, %s, %s, %s, %s)",
            (
                seed["organization_id"],
                account,
                scan,
                "AmazonEC2",
                Decimal("1.00"),
                "2026-02-01",
                "2026-01-01",
            ),
        )


# ---------------------------------------------------------------------------
# Transaction rollback
# ---------------------------------------------------------------------------


def test_organization_and_membership_roll_back_together(container, conn) -> None:
    """If the membership insert fails, the organization must not survive.

    Otherwise a failed create would leave an ownerless organization behind — a
    tenant nobody can reach. The unit of work is ``connection()``, and this
    proves it is genuinely one transaction.
    """
    before = conn.execute("select count(*) from public.organizations").fetchone()[0]
    # A non-existent owner: the membership insert violates the foreign key and
    # must take the organization insert with it.
    ghost_user = str(uuid.uuid4())
    with pytest.raises(NotFoundError):
        container.organizations.create_organization(
            name="Rollback Org",
            slug=f"rollback-{uuid.uuid4().hex[:12]}",
            owner_user_id=ghost_user,
        )
    after = conn.execute("select count(*) from public.organizations").fetchone()[0]
    assert after == before, "the organization row must have been rolled back"


def test_transaction_context_commits_every_write_together(container, conn, org_factory) -> None:
    """``Database.transaction()`` shares one connection across repositories."""
    seed = org_factory()
    database = container.database

    with database.transaction() as unit:
        account = unit.aws_accounts.create(
            organization_id=seed["organization_id"],
            label="txn",
            account_id="171717171717",
            role_arn="arn:aws:iam::171717171717:role/CloudPatrolReadOnly",
            regions=["us-east-1"],
            status="pending",
            status_message=None,
            external_id_ref=None,
            last_validated_at=None,
            created_by=None,
        )
        unit.audit.record(
            organization_id=seed["organization_id"],
            actor_user_id=None,
            action="account.connected",
            target_type="aws_account",
            target_id=account.id,
            metadata={"via": "integration-test"},
        )

    assert container.aws_accounts.get(seed["organization_id"], account.id) is not None
    events = container.audit.list_for_org(seed["organization_id"])
    assert any(event.action == "account.connected" for event in events)


def test_transaction_rolls_back_all_writes_on_failure(container, conn, org_factory) -> None:
    """A raise inside the block must discard every write it made."""
    seed = org_factory()
    database = container.database
    account_id = "181818181818"
    with pytest.raises(RuntimeError):
        with database.transaction() as unit:
            unit.aws_accounts.create(
                organization_id=seed["organization_id"],
                label="doomed",
                account_id=account_id,
                role_arn=f"arn:aws:iam::{account_id}:role/CloudPatrolReadOnly",
                regions=["us-east-1"],
                status="pending",
                status_message=None,
                external_id_ref=None,
                last_validated_at=None,
                created_by=None,
            )
            raise RuntimeError("simulated failure after a write")

    row = conn.execute(
        "select count(*) from public.aws_accounts where account_id = %s", (account_id,)
    ).fetchone()[0]
    assert row == 0, "the account written before the failure must have rolled back"


# ---------------------------------------------------------------------------
# Concurrency and scan lifecycle
# ---------------------------------------------------------------------------


def test_concurrent_scan_creation_yields_exactly_one_winner(container, conn, org_factory) -> None:
    """The partial unique index, not application code, prevents two active scans.

    Eight threads race to start a scan for one account. Exactly one may succeed.
    This is the property the in-memory lock provided and that only the database
    can provide for the PostgreSQL store.
    """
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "191919191919")

    winners: list[str] = []
    losers: list[str] = []
    barrier = threading.Barrier(8)

    def attempt() -> None:
        barrier.wait()
        try:
            scan = container.scans.create_if_no_active(
                organization_id=seed["organization_id"],
                aws_account_id=account,
                status="queued",
                started_at=None,
                finished_at=None,
                resource_count=0,
                finding_count=0,
                partial_failures=[],
                error_message=None,
                created_by=None,
            )
            winners.append(scan.id)
        except ConflictError:
            losers.append("conflict")
        except Exception as exc:  # pragma: no cover - surfaced in the assertion
            losers.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(winners) == 1, f"exactly one thread may win, got {winners}; losers={losers}"
    assert len(set(winners)) == 1

    active = conn.execute(
        "select count(*) from public.scans "
        "where aws_account_id = %s and status in ('queued', 'running')",
        (account,),
    ).fetchone()[0]
    assert active == 1, "the database must hold exactly one active scan"


def test_create_if_no_active_refuses_a_second_active_scan(container, conn, org_factory) -> None:
    """Sequential duplicate: the guard clause itself must refuse."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "202020202020")

    container.scans.create_if_no_active(
        organization_id=seed["organization_id"],
        aws_account_id=account,
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by=None,
    )
    with pytest.raises(ConflictError):
        container.scans.create_if_no_active(
            organization_id=seed["organization_id"],
            aws_account_id=account,
            status="queued",
            started_at=None,
            finished_at=None,
            resource_count=0,
            finding_count=0,
            partial_failures=[],
            error_message=None,
            created_by=None,
        )


def test_a_terminal_scan_does_not_block_a_new_one(container, conn, org_factory) -> None:
    """The index is partial: a completed scan leaves the account free to rescan."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "212121212121")
    first = container.scans.create_if_no_active(
        organization_id=seed["organization_id"],
        aws_account_id=account,
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by=None,
    )
    container.scans.update(first.id, status="completed", finished_at=_now())

    second = container.scans.create_if_no_active(
        organization_id=seed["organization_id"],
        aws_account_id=account,
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by=None,
    )
    assert second.id != first.id


def test_mark_running_claims_exactly_one_worker(container, conn, org_factory) -> None:
    """``status = 'queued'`` in the predicate makes the claim exclusive."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "222222222222")
    scan = container.scans.create_if_no_active(
        organization_id=seed["organization_id"],
        aws_account_id=account,
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by=None,
    )

    claimed = container.scans.mark_running(scan.id, started_at=_now())
    assert claimed.status == "running"
    assert claimed.attempts == 1

    # A second claim on the same scan must be refused, and must not bump attempts.
    with pytest.raises(ConflictError):
        container.scans.mark_running(scan.id, started_at=_now())

    reread = container.scans.get_by_id(scan.id)
    assert reread is not None
    assert reread.attempts == 1, "a failed claim must not increment attempts"


def test_fail_if_stale_only_fires_while_the_scan_is_stale(container, conn, org_factory) -> None:
    """The staleness predicate is evaluated by the database, atomically.

    A scan whose ``started_at`` is recent must not be failed by a reaper using
    an older cutoff — there is no read-then-write window to lose.
    """
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "232323232323")
    scan = container.scans.create_if_no_active(
        organization_id=seed["organization_id"],
        aws_account_id=account,
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by=None,
    )

    # The scan is fresh: a cutoff in the past must not fail it.
    not_stale = container.scans.fail_if_stale(
        scan.id, active_before=_now() - timedelta(hours=1), message="reaped"
    )
    assert not_stale is False

    # With a future cutoff the same call must succeed and fail the scan.
    stale = container.scans.fail_if_stale(
        scan.id, active_before=_now() + timedelta(hours=1), message="reaped"
    )
    assert stale is True

    after = container.scans.get_by_id(scan.id)
    assert after is not None
    assert after.status == "failed"
    assert after.error_message == "reaped"

    # A second reap must be a no-op: the scan is no longer active.
    again = container.scans.fail_if_stale(
        scan.id, active_before=_now() + timedelta(hours=1), message="reaped again"
    )
    assert again is False


def test_find_stale_active_measures_from_started_at_once_running(
    container, conn, org_factory
) -> None:
    """The reaper's query uses ``coalesce(started_at, created_at)``.

    A running scan is judged from when it started, a queued one from when it was
    created, so a long queue wait is not mistaken for a hung scan.
    """
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "242424242424")
    scan = container.scans.create_if_no_active(
        organization_id=seed["organization_id"],
        aws_account_id=account,
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by=None,
    )
    # Backdate created_at so the queued scan looks stale.
    conn.execute(
        "update public.scans set created_at = now() - interval '2 hours' where id = %s",
        (scan.id,),
    )

    stale = container.scans.find_stale_active(active_before=_now() - timedelta(hours=1))
    assert scan.id in {s.id for s in stale}

    # Claim it now: started_at is recent, so it is no longer stale.
    container.scans.mark_running(scan.id, started_at=_now())
    stale_after = container.scans.find_stale_active(active_before=_now() - timedelta(hours=1))
    assert scan.id not in {s.id for s in stale_after}


# ---------------------------------------------------------------------------
# Savings ledger: PostgreSQL-specific constraints
# ---------------------------------------------------------------------------


def test_verified_savings_requires_evidence_and_a_window(conn, org_factory) -> None:
    """A ``verified`` row with no evidence is refused by the database.

    This is what stops an estimate being relabelled as realised money. It is a
    check constraint, so it can only be proven against a real server.
    """
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "252525252525")
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "insert into public.savings_records "
            "(organization_id, aws_account_id, basis, monthly_amount, currency) "
            "values (%s, %s, 'verified', %s, 'USD')",
            (seed["organization_id"], account, Decimal("50.00")),
        )


def test_one_live_ledger_entry_per_finding_and_basis(container, conn, org_factory) -> None:
    """``savings_records_finding_basis_idx`` prevents double attribution."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "262626262626")
    scan = _scan_row(conn, seed["organization_id"], account)
    finding = container.findings.upsert_many(
        [
            _finding(
                organization_id=seed["organization_id"],
                account_id=account,
                scan_id=scan,
                dedupe_key="key-savings",
            )
        ]
    ).records[0]

    container.savings.create(
        organization_id=seed["organization_id"],
        aws_account_id=account,
        finding_id=finding.id,
        basis="estimated",
        monthly_amount=Decimal("8.00"),
        currency="USD",
        evidence=None,
        measured_from=None,
        measured_to=None,
        created_by=None,
    )
    with pytest.raises(ConflictError):
        container.savings.create(
            organization_id=seed["organization_id"],
            aws_account_id=account,
            finding_id=finding.id,
            basis="estimated",
            monthly_amount=Decimal("9.00"),
            currency="USD",
            evidence=None,
            measured_from=None,
            measured_to=None,
            created_by=None,
        )


def test_savings_basis_domain_includes_the_intermediate_states(
    container, conn, org_factory
) -> None:
    """Migration 0002 widened ``basis``; the wider domain must be live.

    A rejected value here would mean 0002 did not apply.
    """
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "272727272727")
    for basis in ("potential", "approved", "implemented", "inconclusive"):
        record = container.savings.create(
            organization_id=seed["organization_id"],
            aws_account_id=account,
            finding_id=None,
            basis=basis,
            monthly_amount=Decimal("1.00"),
            currency="USD",
            evidence=None,
            measured_from=None,
            measured_to=None,
            created_by=None,
        )
        assert record.basis == basis


def test_savings_amounts_keep_two_decimal_places(container, conn, org_factory) -> None:
    """``numeric(14,2)`` round trips exactly; money is never a float here."""
    seed = org_factory()
    account = _account_row(conn, seed["organization_id"], "282828282828")
    record = container.savings.create(
        organization_id=seed["organization_id"],
        aws_account_id=account,
        finding_id=None,
        basis="estimated",
        monthly_amount=Decimal("1234.56"),
        currency="USD",
        evidence=None,
        measured_from=None,
        measured_to=None,
        created_by=None,
    )
    assert record.monthly_amount == Decimal("1234.56")
    fetched = container.savings.get(seed["organization_id"], record.id)
    assert fetched is not None
    assert fetched.monthly_amount == Decimal("1234.56")


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def test_audit_event_with_a_system_actor_has_no_user(container, conn, org_factory) -> None:
    """The reaper records a system event with no actor; the FK must allow NULL."""
    seed = org_factory()
    event = container.audit.record(
        organization_id=seed["organization_id"],
        actor_user_id=None,
        action="scan.failed",
        target_type="scan",
        target_id=str(uuid.uuid4()),
        metadata={"reason": "stale"},
    )
    assert event.actor_user_id is None
    events = container.audit.list_for_org(seed["organization_id"])
    assert [e.id for e in events] == [event.id]


# ---------------------------------------------------------------------------
# RLS: tenant isolation at the database layer
# ---------------------------------------------------------------------------


def test_rls_hides_another_tenants_organizations(ephemeral_database, conn) -> None:
    """With the ``authenticated`` role and a JWT subject, RLS filters rows.

    ``docs/SECURITY.md`` records deployed RLS behaviour as unverified. This
    exercises the policies on a real server with the grants Supabase applies, so
    the claim is tested rather than assumed. It is still not a live Supabase
    project, and the report says so.
    """

    user_a, user_b = str(uuid.uuid4()), str(uuid.uuid4())
    conn.execute(
        "insert into auth.users (id, email) values (%s, 'a@test'), (%s, 'b@test')",
        (user_a, user_b),
    )
    suffix = uuid.uuid4().hex[:10]
    org_a = conn.execute(
        "insert into public.organizations (name, slug) values ('Tenant A', %s) returning id",
        (f"rls-a-{suffix}",),
    ).fetchone()[0]
    org_b = conn.execute(
        "insert into public.organizations (name, slug) values ('Tenant B', %s) returning id",
        (f"rls-b-{suffix}",),
    ).fetchone()[0]
    conn.execute(
        "insert into public.memberships (organization_id, user_id, role) "
        "values (%s, %s, 'owner'), (%s, %s, 'owner')",
        (org_a, user_a, org_b, user_b),
    )

    with rls_connection(ephemeral_database.dsn, user_a) as as_a:
        visible = as_a.execute("select id from public.organizations").fetchall()
        assert [str(row[0]) for row in visible] == [str(org_a)]
        # An explicit cross-tenant read returns nothing rather than the row.
        hidden = as_a.execute(
            "select id from public.organizations where id = %s", (org_b,)
        ).fetchall()
        assert hidden == []

    with rls_connection(ephemeral_database.dsn, user_b) as as_b:
        visible_b = as_b.execute("select id from public.organizations").fetchall()
        assert [str(row[0]) for row in visible_b] == [str(org_b)]


def test_rls_denies_a_non_member(ephemeral_database, conn) -> None:
    """A signed-in user with no membership sees nothing, not everything."""

    stranger = str(uuid.uuid4())
    conn.execute("insert into auth.users (id, email) values (%s, 'stranger@test')", (stranger,))
    with rls_connection(ephemeral_database.dsn, stranger) as as_stranger:
        assert as_stranger.execute("select id from public.organizations").fetchall() == []


def test_rls_denies_a_member_writing_a_connection(ephemeral_database, conn) -> None:
    """Only owners and admins may insert an AWS account; a plain member may not."""

    owner, member = str(uuid.uuid4()), str(uuid.uuid4())
    conn.execute(
        "insert into auth.users (id, email) values (%s, 'o@test'), (%s, 'm@test')",
        (owner, member),
    )
    suffix = uuid.uuid4().hex[:10]
    org_id = conn.execute(
        "insert into public.organizations (name, slug) values ('Roles', %s) returning id",
        (f"roles-{suffix}",),
    ).fetchone()[0]
    conn.execute(
        "insert into public.memberships (organization_id, user_id, role) "
        "values (%s, %s, 'owner'), (%s, %s, 'member')",
        (org_id, owner, org_id, member),
    )

    with rls_connection(ephemeral_database.dsn, member) as as_member:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            as_member.execute(
                "insert into public.aws_accounts "
                "(organization_id, label, account_id, role_arn, regions) "
                "values (%s, 'x', '303030303030', "
                "'arn:aws:iam::303030303030:role/R', %s)",
                (org_id, ["us-east-1"]),
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _account_row(conn: psycopg.Connection, organization_id: str, account_id: str) -> str:
    """Insert an AWS account directly and return its primary key."""
    return str(
        conn.execute(
            "insert into public.aws_accounts "
            "(organization_id, label, account_id, role_arn, regions, status) "
            "values (%s, %s, %s, %s, %s, 'validated') returning id",
            (
                organization_id,
                f"acct-{account_id}",
                account_id,
                f"arn:aws:iam::{account_id}:role/CloudPatrolReadOnly",
                ["us-east-1"],
            ),
        ).fetchone()[0]
    )


def _scan_row(conn: psycopg.Connection, organization_id: str, aws_account_id: str) -> str:
    return str(
        conn.execute(
            "insert into public.scans (organization_id, aws_account_id, status) "
            "values (%s, %s, 'completed') returning id",
            (organization_id, aws_account_id),
        ).fetchone()[0]
    )


def _cost(
    *,
    org: str,
    account: str,
    scan: str,
    service: str,
    amount: Decimal,
    period_start: str = "2026-01-01",
    period_end: str = "2026-02-01",
) -> CostObservationRecord:
    return CostObservationRecord(
        id=str(uuid.uuid4()),
        organization_id=org,
        aws_account_id=account,
        scan_id=scan,
        service=service,
        amount=amount,
        currency="USD",
        period_start=period_start,
        period_end=period_end,
        created_at=_now(),
    )
