"""PostgreSQL repository implementations (psycopg 3, synchronous).

These satisfy the same protocols as :mod:`app.repositories.memory`, so no route
or service changes when the backing store is swapped. psycopg 3 is used directly
rather than an ORM: the dataclasses in :mod:`app.repositories.models` already are
the row shapes, and one hand-written statement per operation keeps the SQL
auditable — which matters when the tenant filter is the isolation boundary.

Tenancy
-------
Every tenant-scoped read carries ``organization_id = %s`` in its ``WHERE``
clause. The API is expected to run with a database role that *bypasses* RLS
(the Supabase service role), so RLS is not the enforcement point for API
traffic — this SQL is. ``ScanRepository.get_by_id`` and
``ScanRepository.find_stale_active`` are the two deliberately unscoped reads, and
they exist only for the background worker and the reaper. Neither is reachable
from a tenant-facing route.

Transactions
------------
:class:`Database` opens one connection per operation and commits on success, or
rolls back if the block raises — psycopg's connection context manager does both,
then the connection is closed in ``finally``, so no path leaks one.
:meth:`Database.transaction` yields a container whose repositories share a single
connection and transaction, so a multi-step workflow is all-or-nothing. That is
the unit of work: the same repository code runs either way, bound to a different
connection source.

Several workflows are already atomic without it, because each is a single
statement or a single connection block:

* organization + owner membership — two inserts in one ``connection()`` block;
* scan creation under the one-active-per-account rule — one guarded ``INSERT``
  backed by a partial unique index;
* scan claim — one conditional ``UPDATE ... WHERE status = 'queued'``;
* stale-scan reaping — one conditional ``UPDATE ... WHERE <still stale>``.

Scan *completion* is the exception, and it is documented in the phase report:
the scan service writes resources, findings, savings, costs, status and audit
through separate repository handles, so those are separate transactions until the
service is given a transaction scope. The unit-of-work primitive here is what
that refactor will use.

Failure translation
-------------------
Expected integrity conflicts (a duplicate slug, a second active scan, a repeated
ledger entry) become :class:`~app.core.errors.ConflictError`, so callers get the
same 409 the in-memory store's checks produce. A check-constraint violation — an
invalid row, not a server fault — is also mapped to a conflict. Anything
unexpected is re-raised untouched: a swallowed database error would turn a real
fault into a silent success.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal
from typing import Any

import psycopg
from psycopg import Connection, sql
from psycopg.errors import CheckViolation, ForeignKeyViolation, UniqueViolation
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from app.core.errors import ConflictError, NotFoundError
from app.repositories.models import (
    AuditEventRecord,
    AwsAccountRecord,
    CostObservationRecord,
    FindingRecord,
    FindingUpsertResult,
    MembershipRecord,
    OrganizationRecord,
    ResourceSnapshotRecord,
    SavingsRecord,
    ScanRecord,
    new_id,
)

# libpq connection timeout. A hung connect must not hold a request thread open.
_CONNECT_TIMEOUT_SECONDS = 10

_ACTIVE_SCAN_STATUSES = ("queued", "running")

# Placeholders whose column needs an explicit target type. Without the cast,
# psycopg sends an untyped parameter and PostgreSQL infers the type from
# context — unambiguous for a column, but not for an array or a jsonb literal.
_PLACEHOLDERS: dict[str, sql.SQL] = {
    "regions": sql.SQL("%s::text[]"),
    "partial_failures": sql.SQL("%s::jsonb"),
    "attributes": sql.SQL("%s::jsonb"),
    "evidence": sql.SQL("%s::jsonb"),
    "metadata": sql.SQL("%s::jsonb"),
    "period_start": sql.SQL("%s::date"),
    "period_end": sql.SQL("%s::date"),
}

# JSON columns receive a Jsonb-wrapped value so psycopg serialises the mapping
# rather than rejecting it.
_JSON_COLUMNS = frozenset({"partial_failures", "attributes", "evidence", "metadata"})

# Columns a caller may set through the generic create/update helpers, per table.
# An allow-list, not a blacklist: an unlisted name is refused before it can reach
# an identifier, so a caller cannot widen the writable surface.
_SCAN_COLUMNS = frozenset(
    {
        "organization_id",
        "aws_account_id",
        "status",
        "started_at",
        "finished_at",
        "resource_count",
        "finding_count",
        "partial_failures",
        "error_message",
        "created_by",
        "attempts",
    }
)
_AWS_ACCOUNT_COLUMNS = frozenset(
    {
        "organization_id",
        "label",
        "account_id",
        "role_arn",
        "regions",
        "status",
        "status_message",
        "external_id_ref",
        "last_validated_at",
        "created_by",
    }
)
_FINDING_UPDATE_COLUMNS = frozenset(
    {
        "scan_id",
        "severity",
        "confidence",
        "state",
        "title",
        "summary",
        "evidence",
        "recommended_action",
        "estimated_monthly_savings",
        "currency",
    }
)
_SAVINGS_INSERT_COLUMNS = frozenset(
    {
        "organization_id",
        "aws_account_id",
        "finding_id",
        "basis",
        "monthly_amount",
        "currency",
        "evidence",
        "measured_from",
        "measured_to",
        "created_by",
    }
)
_SAVINGS_UPDATE_COLUMNS = frozenset(
    {"basis", "monthly_amount", "evidence", "measured_from", "measured_to", "created_by"}
)
_COST_INSERT_COLUMNS = frozenset(
    {
        "organization_id",
        "aws_account_id",
        "scan_id",
        "service",
        "amount",
        "currency",
        "period_start",
        "period_end",
    }
)
_AUDIT_COLUMNS = frozenset(
    {"organization_id", "actor_user_id", "action", "target_type", "target_id", "metadata"}
)

_ORG_RETURNING = ("id", "name", "slug", "created_at")
_MEMBERSHIP_RETURNING = ("id", "organization_id", "user_id", "role", "created_at")
_AWS_ACCOUNT_RETURNING = (
    "id",
    "organization_id",
    "label",
    "account_id",
    "role_arn",
    "regions",
    "status",
    "status_message",
    "external_id_ref",
    "last_validated_at",
    "created_by",
    "created_at",
)
_SCAN_RETURNING = (
    "id",
    "organization_id",
    "aws_account_id",
    "status",
    "started_at",
    "finished_at",
    "resource_count",
    "finding_count",
    "partial_failures",
    "error_message",
    "created_by",
    "created_at",
    "attempts",
)
_RESOURCE_RETURNING = (
    "id",
    "organization_id",
    "scan_id",
    "aws_account_id",
    "resource_type",
    "resource_id",
    "region",
    "name",
    "state",
    "attributes",
    "created_at",
)
_FINDING_RETURNING = (
    "id",
    "organization_id",
    "scan_id",
    "aws_account_id",
    "detector",
    "resource_type",
    "resource_id",
    "region",
    "severity",
    "confidence",
    "state",
    "title",
    "summary",
    "evidence",
    "recommended_action",
    "estimated_monthly_savings",
    "currency",
    "dedupe_key",
    "created_at",
    "updated_at",
)
_SAVINGS_RETURNING = (
    "id",
    "organization_id",
    "aws_account_id",
    "finding_id",
    "basis",
    "monthly_amount",
    "currency",
    "evidence",
    "measured_from",
    "measured_to",
    "created_by",
    "created_at",
)
_COST_RETURNING = (
    "id",
    "organization_id",
    "aws_account_id",
    "scan_id",
    "service",
    "amount",
    "currency",
    "period_start",
    "period_end",
    "created_at",
)
_AUDIT_RETURNING = (
    "id",
    "organization_id",
    "actor_user_id",
    "action",
    "target_type",
    "target_id",
    "metadata",
    "created_at",
)


# --- small SQL builders ------------------------------------------------------


def _columns(names: tuple[str, ...] | list[str]) -> sql.Composed:
    return sql.SQL(", ").join(sql.Identifier(name) for name in names)


def _placeholder(column: str) -> sql.SQL | sql.Composed:
    return _PLACEHOLDERS.get(column, sql.SQL("%s"))


def _insert(table: str, columns: list[str], returning: tuple[str, ...]) -> sql.SQL | sql.Composed:
    return sql.SQL("insert into {} ({}) values ({}) returning {}").format(
        sql.Identifier("public", table),
        _columns(columns),
        sql.SQL(", ").join(_placeholder(name) for name in columns),
        _columns(returning),
    )


def _update(
    table: str, columns: list[str], returning: tuple[str, ...], where: sql.SQL | sql.Composed
) -> sql.SQL | sql.Composed:
    return sql.SQL("update {} set {} where {} returning {}").format(
        sql.Identifier("public", table),
        sql.SQL(", ").join(
            sql.SQL("{} = {}").format(sql.Identifier(name), _placeholder(name)) for name in columns
        ),
        where,
        _columns(returning),
    )


def _select(
    table: str,
    returning: tuple[str, ...],
    where: sql.SQL | sql.Composed,
    *,
    order: sql.SQL | sql.Composed | None = None,
    limit: int | None = None,
) -> sql.SQL | sql.Composed:
    statement = sql.SQL("select {} from {} where {}").format(
        _columns(returning), sql.Identifier("public", table), where
    )
    if order is not None:
        statement = sql.SQL("{} order by {}").format(statement, order)
    if limit is not None:
        statement = sql.SQL("{} limit {}").format(statement, sql.Literal(limit))
    return statement


def _validated_columns(fields: dict[str, Any], allowed: frozenset[str]) -> list[str]:
    unknown = sorted(set(fields) - allowed)
    if unknown:
        raise ValueError(f"Unsupported column(s): {', '.join(unknown)}")
    if not fields:
        raise ValueError("at least one field is required")
    return list(fields)


def _adapt(column: str, value: Any) -> Any:
    if value is not None and column in _JSON_COLUMNS:
        return Jsonb(value)
    return value


def _params(fields: dict[str, Any], columns: list[str]) -> list[Any]:
    return [_adapt(name, fields[name]) for name in columns]


def _classify(exc: Exception, *, check_message: str) -> Exception:
    """Map a check-constraint violation to a conflict; pass anything else through.

    A check violation means the row itself is invalid — a malformed role ARN, an
    empty region list, a verified saving with no evidence. That is a caller
    error, not a server fault, so it must not surface as a 500. Any other
    exception is returned unchanged and re-raised by the caller.
    """
    if isinstance(exc, CheckViolation):
        return ConflictError(check_message)
    return exc


# --- row -> dataclass mappers ------------------------------------------------


def _as_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _as_iso(value: Any) -> str | None:
    """Render a ``date`` the database returned as the ``str`` the model holds."""
    if value is None:
        return None
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)


def _organization(row: dict[str, Any]) -> OrganizationRecord:
    return OrganizationRecord(
        id=str(row["id"]),
        name=row["name"],
        slug=row["slug"],
        created_at=row["created_at"],
    )


def _membership(row: dict[str, Any]) -> MembershipRecord:
    return MembershipRecord(
        id=str(row["id"]),
        organization_id=str(row["organization_id"]),
        user_id=str(row["user_id"]),
        role=row["role"],
        created_at=row["created_at"],
    )


def _aws_account(row: dict[str, Any]) -> AwsAccountRecord:
    return AwsAccountRecord(
        id=str(row["id"]),
        organization_id=str(row["organization_id"]),
        label=row["label"],
        account_id=row["account_id"],
        role_arn=row["role_arn"],
        regions=list(row["regions"]),
        status=row["status"],
        status_message=row["status_message"],
        last_validated_at=row["last_validated_at"],
        created_at=row["created_at"],
        created_by=_as_optional_str(row["created_by"]),
        external_id_ref=row["external_id_ref"],
    )


def _scan(row: dict[str, Any]) -> ScanRecord:
    return ScanRecord(
        id=str(row["id"]),
        organization_id=str(row["organization_id"]),
        aws_account_id=str(row["aws_account_id"]),
        status=row["status"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        resource_count=row["resource_count"],
        finding_count=row["finding_count"],
        partial_failures=list(row["partial_failures"] or []),
        error_message=row["error_message"],
        created_at=row["created_at"],
        created_by=_as_optional_str(row["created_by"]),
        attempts=row["attempts"],
    )


def _resource(row: dict[str, Any]) -> ResourceSnapshotRecord:
    return ResourceSnapshotRecord(
        id=str(row["id"]),
        organization_id=str(row["organization_id"]),
        scan_id=str(row["scan_id"]),
        aws_account_id=str(row["aws_account_id"]),
        resource_type=row["resource_type"],
        resource_id=row["resource_id"],
        region=row["region"],
        name=row["name"],
        state=row["state"],
        attributes=row["attributes"],
        created_at=row["created_at"],
    )


def _finding(row: dict[str, Any]) -> FindingRecord:
    amount = row["estimated_monthly_savings"]
    return FindingRecord(
        id=str(row["id"]),
        organization_id=str(row["organization_id"]),
        scan_id=str(row["scan_id"]),
        aws_account_id=str(row["aws_account_id"]),
        detector=row["detector"],
        resource_type=row["resource_type"],
        resource_id=row["resource_id"],
        region=row["region"],
        severity=row["severity"],
        confidence=row["confidence"],
        state=row["state"],
        title=row["title"],
        summary=row["summary"],
        evidence=row["evidence"],
        recommended_action=row["recommended_action"],
        estimated_monthly_savings=Decimal(amount) if amount is not None else None,
        currency=row["currency"],
        dedupe_key=row["dedupe_key"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _savings(row: dict[str, Any]) -> SavingsRecord:
    return SavingsRecord(
        id=str(row["id"]),
        organization_id=str(row["organization_id"]),
        aws_account_id=str(row["aws_account_id"]),
        finding_id=_as_optional_str(row["finding_id"]),
        basis=row["basis"],
        monthly_amount=Decimal(row["monthly_amount"]),
        currency=row["currency"],
        evidence=row["evidence"],
        measured_from=row["measured_from"],
        measured_to=row["measured_to"],
        created_by=_as_optional_str(row["created_by"]),
        created_at=row["created_at"],
    )


def _cost(row: dict[str, Any]) -> CostObservationRecord:
    return CostObservationRecord(
        id=str(row["id"]),
        organization_id=str(row["organization_id"]),
        aws_account_id=str(row["aws_account_id"]),
        scan_id=_as_optional_str(row["scan_id"]),
        service=row["service"],
        amount=Decimal(row["amount"]),
        currency=row["currency"],
        period_start=_as_iso(row["period_start"]) or "",
        period_end=_as_iso(row["period_end"]) or "",
        created_at=row["created_at"],
    )


def _audit(row: dict[str, Any]) -> AuditEventRecord:
    return AuditEventRecord(
        id=str(row["id"]),
        organization_id=str(row["organization_id"]),
        actor_user_id=_as_optional_str(row["actor_user_id"]),
        action=row["action"],
        target_type=row["target_type"],
        target_id=row["target_id"],
        metadata=row["metadata"] or {},
        created_at=row["created_at"],
    )


def _is_uuid(value: Any) -> bool:
    try:
        uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return False
    return True


# --- connection sources ------------------------------------------------------


class ConnectionSource:
    """Something a repository borrows a connection from.

    Only ``connection()`` is required: a context manager that yields an open
    connection and guarantees it is closed (or handed back) afterwards.
    """

    @contextmanager
    def connection(self) -> Iterator[Connection[dict[str, Any]]]:  # pragma: no cover
        raise NotImplementedError


class Database(ConnectionSource):
    """Owns the DSN and hands out connections.

    Constructing a ``Database`` does **not** connect; a connection is opened only
    when ``connection()`` is called. That is what lets the application hold the
    object while the DSN is unset and never touch the network.

    The DSN embeds a password, so it is held privately and never rendered — not
    by ``repr``, not in an exception, not in a log line.
    """

    def __init__(self, dsn: str, *, connect_timeout: int = _CONNECT_TIMEOUT_SECONDS) -> None:
        self._dsn = dsn
        self._connect_timeout = connect_timeout

    def __repr__(self) -> str:
        return "Database(dsn=***)"

    __str__ = __repr__

    @contextmanager
    def connection(self) -> Iterator[Connection[dict[str, Any]]]:
        """One connection, one transaction.

        psycopg's connection context manager commits on a clean exit and rolls
        back if the block raises, then the connection is closed in ``finally``.
        There is no path that leaves a connection open or a transaction
        half-applied.
        """
        conn = psycopg.connect(
            self._dsn,
            row_factory=dict_row,
            connect_timeout=self._connect_timeout,
        )
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[PostgresContainer]:
        """A container whose repositories share one connection and transaction.

        Every write performed through the yielded container lands together, or
        none of it does. Use this for a workflow that must not be observed
        half-finished.
        """
        conn = psycopg.connect(
            self._dsn,
            row_factory=dict_row,
            connect_timeout=self._connect_timeout,
        )
        try:
            with conn:
                yield PostgresContainer(_BoundConnection(conn), database=self)
        finally:
            conn.close()


class _BoundConnection(ConnectionSource):
    """Yields an already-open connection without committing or closing it.

    The enclosing :meth:`Database.transaction` owns the transaction boundary; a
    repository bound to this must not commit on its own, or the atomicity the
    unit of work promises would be lost.
    """

    def __init__(self, conn: Connection[dict[str, Any]]) -> None:
        self._conn = conn

    @contextmanager
    def connection(self) -> Iterator[Connection[dict[str, Any]]]:
        yield self._conn


# --- repositories ------------------------------------------------------------


class PostgresOrganizationRepository:
    def __init__(self, source: ConnectionSource) -> None:
        self._source = source

    def get_membership(self, user_id: str, organization_id: str) -> MembershipRecord | None:
        statement = _select(
            "memberships",
            _MEMBERSHIP_RETURNING,
            sql.SQL("user_id = %s and organization_id = %s"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (user_id, organization_id))
            row = cur.fetchone()
        return _membership(row) if row else None

    def list_memberships(self, user_id: str) -> list[MembershipRecord]:
        statement = _select(
            "memberships",
            _MEMBERSHIP_RETURNING,
            sql.SQL("user_id = %s"),
            order=sql.SQL("created_at"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (user_id,))
            rows = cur.fetchall()
        return [_membership(row) for row in rows]

    def get_organization(self, organization_id: str) -> OrganizationRecord | None:
        statement = _select("organizations", _ORG_RETURNING, sql.SQL("id = %s"))
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (organization_id,))
            row = cur.fetchone()
        return _organization(row) if row else None

    def create_organization(
        self, *, name: str, slug: str, owner_user_id: str
    ) -> OrganizationRecord:
        """Insert the organization and its owner membership in one transaction.

        Both rows are written inside a single ``connection()`` block, so they
        commit together or not at all. An organization with no owner would be
        unreachable by anyone, including the person who just created it.
        """
        insert_org = _insert("organizations", ["id", "name", "slug"], _ORG_RETURNING)
        insert_membership = _insert(
            "memberships",
            ["id", "organization_id", "user_id", "role"],
            _MEMBERSHIP_RETURNING,
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            try:
                cur.execute(insert_org, (new_id(), name, slug))
                row = cur.fetchone()
                assert row is not None  # a returning insert always yields a row
                organization = _organization(row)
                cur.execute(
                    insert_membership,
                    (new_id(), organization.id, owner_user_id, "owner"),
                )
            except UniqueViolation as exc:
                raise self._conflict(exc) from exc
            except ForeignKeyViolation as exc:
                # The owner must be a real auth user; otherwise the membership
                # insert fails and takes the whole transaction with it.
                raise NotFoundError("The owning user does not exist.") from exc
        return organization

    @staticmethod
    def _conflict(exc: UniqueViolation) -> ConflictError:
        # The slug is unique globally, not per user, so a second tenant cannot
        # take a slug another tenant already holds.
        if exc.diag.constraint_name == "organizations_slug_key":
            return ConflictError("That workspace slug is already taken.")
        return ConflictError("The workspace already exists.")


class PostgresAwsAccountRepository:
    def __init__(self, source: ConnectionSource) -> None:
        self._source = source

    def list_for_org(self, organization_id: str) -> list[AwsAccountRecord]:
        statement = _select(
            "aws_accounts",
            _AWS_ACCOUNT_RETURNING,
            sql.SQL("organization_id = %s"),
            order=sql.SQL("created_at"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (organization_id,))
            rows = cur.fetchall()
        return [_aws_account(row) for row in rows]

    def get(self, organization_id: str, account_pk: str) -> AwsAccountRecord | None:
        # The organization predicate is the tenant boundary: a row belonging to
        # another tenant is reported as absent, so this cannot be used to
        # enumerate other tenants' records.
        statement = _select(
            "aws_accounts",
            _AWS_ACCOUNT_RETURNING,
            sql.SQL("id = %s and organization_id = %s"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (account_pk, organization_id))
            row = cur.fetchone()
        return _aws_account(row) if row else None

    def find_by_account_id(self, organization_id: str, account_id: str) -> AwsAccountRecord | None:
        statement = _select(
            "aws_accounts",
            _AWS_ACCOUNT_RETURNING,
            sql.SQL("organization_id = %s and account_id = %s"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (organization_id, account_id))
            row = cur.fetchone()
        return _aws_account(row) if row else None

    def create(self, **fields: Any) -> AwsAccountRecord:
        columns = ["id", *_validated_columns(fields, _AWS_ACCOUNT_COLUMNS)]
        values = {"id": new_id(), **fields}
        statement = _insert("aws_accounts", columns, _AWS_ACCOUNT_RETURNING)
        with self._source.connection() as conn, conn.cursor() as cur:
            try:
                cur.execute(statement, _params(values, columns))
                row = cur.fetchone()
            except UniqueViolation as exc:
                raise ConflictError(
                    "This AWS account is already connected to this organization."
                ) from exc
            except ForeignKeyViolation as exc:
                raise NotFoundError("The organization does not exist.") from exc
            except Exception as exc:  # noqa: BLE001 - re-raised, only classified
                raise _classify(
                    exc, check_message="The AWS account details are not valid."
                ) from exc
        assert row is not None
        return _aws_account(row)

    def update(self, account_pk: str, **fields: Any) -> AwsAccountRecord:
        columns = _validated_columns(fields, _AWS_ACCOUNT_COLUMNS)
        statement = _update("aws_accounts", columns, _AWS_ACCOUNT_RETURNING, sql.SQL("id = %s"))
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, [*_params(fields, columns), account_pk])
            row = cur.fetchone()
        if row is None:
            raise NotFoundError("AWS account not found.")
        return _aws_account(row)


class PostgresScanRepository:
    def __init__(self, source: ConnectionSource) -> None:
        self._source = source

    def list_for_org(self, organization_id: str) -> list[ScanRecord]:
        statement = _select(
            "scans",
            _SCAN_RETURNING,
            sql.SQL("organization_id = %s"),
            order=sql.SQL("created_at desc"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (organization_id,))
            rows = cur.fetchall()
        return [_scan(row) for row in rows]

    def get(self, organization_id: str, scan_id: str) -> ScanRecord | None:
        statement = _select("scans", _SCAN_RETURNING, sql.SQL("id = %s and organization_id = %s"))
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (scan_id, organization_id))
            row = cur.fetchone()
        return _scan(row) if row else None

    def get_by_id(self, scan_id: str) -> ScanRecord | None:
        """Unscoped read for the worker and reaper only. Never call from a route."""
        statement = _select("scans", _SCAN_RETURNING, sql.SQL("id = %s"))
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (scan_id,))
            row = cur.fetchone()
        return _scan(row) if row else None

    def find_active_for_account(
        self, organization_id: str, aws_account_id: str
    ) -> ScanRecord | None:
        statement = _select(
            "scans",
            _SCAN_RETURNING,
            sql.SQL("organization_id = %s and aws_account_id = %s and status = any(%s)"),
            order=sql.SQL("created_at desc"),
            limit=1,
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (organization_id, aws_account_id, list(_ACTIVE_SCAN_STATUSES)))
            row = cur.fetchone()
        return _scan(row) if row else None

    def find_stale_active(self, *, active_before: datetime) -> list[ScanRecord]:
        # ``coalesce`` mirrors the in-memory rule: measure from started_at once
        # running, otherwise from created_at while still queued.
        statement = _select(
            "scans",
            _SCAN_RETURNING,
            sql.SQL("status = any(%s) and coalesce(started_at, created_at) < %s"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (list(_ACTIVE_SCAN_STATUSES), active_before))
            rows = cur.fetchall()
        return [_scan(row) for row in rows]

    def fail_if_stale(self, scan_id: str, *, active_before: datetime, message: str) -> bool:
        """Fail a scan only if it is *still* stale, as one conditional update.

        The staleness test lives in the ``WHERE`` clause, so the database decides
        atomically. A worker that claimed the scan a moment ago moved
        ``started_at`` past the cutoff, the predicate no longer matches, and the
        reaper's write does not land — there is no read-then-write window to lose.
        """
        statement = sql.SQL(
            "update {} set status = 'failed', finished_at = now(), error_message = %s "
            "where id = %s and status = any(%s) "
            "and coalesce(started_at, created_at) < %s returning {}"
        ).format(sql.Identifier("public", "scans"), _columns(("id",)))
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (message, scan_id, list(_ACTIVE_SCAN_STATUSES), active_before))
            return cur.fetchone() is not None

    def mark_running(self, scan_id: str, *, started_at: datetime) -> ScanRecord:
        """Claim a queued scan, incrementing ``attempts``, in one statement.

        ``status = 'queued'`` in the predicate is what makes the claim exclusive:
        two workers racing on the same scan cannot both match, so exactly one
        increments ``attempts`` and the other is told the scan is already taken.
        The in-memory store gets the same guarantee from its lock instead.
        """
        statement = sql.SQL(
            "update {} set status = 'running', started_at = %s, attempts = attempts + 1 "
            "where id = %s and status = 'queued' returning {}"
        ).format(sql.Identifier("public", "scans"), _columns(_SCAN_RETURNING))
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (started_at, scan_id))
            row = cur.fetchone()
        if row is None:
            raise ConflictError("This scan has already been claimed.")
        return _scan(row)

    def create_if_no_active(self, **fields: Any) -> ScanRecord:
        """Insert a scan unless the account already has an active one.

        ``scans_one_active_per_account_idx`` is the real guarantee: a partial
        unique index over ``aws_account_id`` for active statuses. If two callers
        race past the ``WHERE NOT EXISTS`` check, the second insert violates the
        index and is translated into the same conflict the check would have
        produced — so the caller never has to hold a lock across check-and-insert.
        """
        columns = ["id", *_validated_columns(fields, _SCAN_COLUMNS)]
        values = {"id": new_id(), **fields}
        statement = sql.SQL(
            "insert into {} ({}) select {} where not exists ("
            "select 1 from {} where aws_account_id = %s and status = any(%s)"
            ") returning {}"
        ).format(
            sql.Identifier("public", "scans"),
            _columns(columns),
            sql.SQL(", ").join(_placeholder(name) for name in columns),
            sql.Identifier("public", "scans"),
            _columns(_SCAN_RETURNING),
        )
        params = [*_params(values, columns), fields["aws_account_id"], list(_ACTIVE_SCAN_STATUSES)]
        with self._source.connection() as conn, conn.cursor() as cur:
            try:
                cur.execute(statement, params)
                row = cur.fetchone()
            except UniqueViolation as exc:
                # The index caught a race the guard clause could not.
                raise ConflictError("A scan for this account is already in progress.") from exc
            except ForeignKeyViolation as exc:
                raise NotFoundError("The AWS account does not exist.") from exc
        if row is None:
            # The guard clause matched: an active scan already exists.
            raise ConflictError("A scan for this account is already in progress.")
        return _scan(row)

    def create(self, **fields: Any) -> ScanRecord:
        columns = ["id", *_validated_columns(fields, _SCAN_COLUMNS)]
        values = {"id": new_id(), **fields}
        statement = _insert("scans", columns, _SCAN_RETURNING)
        with self._source.connection() as conn, conn.cursor() as cur:
            try:
                cur.execute(statement, _params(values, columns))
                row = cur.fetchone()
            except UniqueViolation as exc:
                raise ConflictError("A scan for this account is already in progress.") from exc
            except ForeignKeyViolation as exc:
                raise NotFoundError("The AWS account does not exist.") from exc
        assert row is not None
        return _scan(row)

    def update(self, scan_id: str, **fields: Any) -> ScanRecord:
        columns = _validated_columns(fields, _SCAN_COLUMNS)
        statement = _update("scans", columns, _SCAN_RETURNING, sql.SQL("id = %s"))
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, [*_params(fields, columns), scan_id])
            row = cur.fetchone()
        if row is None:
            raise NotFoundError("Scan not found.")
        return _scan(row)


class PostgresResourceRepository:
    def __init__(self, source: ConnectionSource) -> None:
        self._source = source

    def add_many(self, records: list[ResourceSnapshotRecord]) -> None:
        if not records:
            return
        columns = [
            "id",
            "organization_id",
            "scan_id",
            "aws_account_id",
            "resource_type",
            "resource_id",
            "region",
            "name",
            "state",
            "attributes",
        ]
        statement = sql.SQL(
            "insert into {} ({}) values ({}) "
            "on conflict (scan_id, resource_type, resource_id, region) do nothing"
        ).format(
            sql.Identifier("public", "resource_snapshots"),
            _columns(columns),
            sql.SQL(", ").join(_placeholder(name) for name in columns),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.executemany(
                statement,
                [
                    (
                        record.id,
                        record.organization_id,
                        record.scan_id,
                        record.aws_account_id,
                        record.resource_type,
                        record.resource_id,
                        record.region,
                        record.name,
                        record.state,
                        Jsonb(record.attributes),
                    )
                    for record in records
                ],
            )

    def list_for_scan(self, organization_id: str, scan_id: str) -> list[ResourceSnapshotRecord]:
        statement = _select(
            "resource_snapshots",
            _RESOURCE_RETURNING,
            sql.SQL("scan_id = %s and organization_id = %s"),
            order=sql.SQL("created_at"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (scan_id, organization_id))
            rows = cur.fetchall()
        return [_resource(row) for row in rows]


class PostgresFindingRepository:
    def __init__(self, source: ConnectionSource) -> None:
        self._source = source

    def upsert_many(self, records: list[FindingRecord]) -> FindingUpsertResult:
        """Insert new findings, refresh re-observed ones, preserve the decision.

        ``on conflict (aws_account_id, dedupe_key)`` matches the unique index on
        the table. The ``DO UPDATE`` set-list deliberately omits ``state`` and
        ``created_at``: a re-scan refreshes the evidence and the scan reference
        but must never revert an acknowledgement or a dismissal, nor move the
        original discovery time.

        ``(xmax = 0)`` distinguishes the two outcomes inside ``RETURNING``: a
        freshly inserted row has no updating transaction id, an updated one does.
        That makes the inserted/refreshed split accurate without a second query.
        """
        if not records:
            return FindingUpsertResult()

        columns = [
            "id",
            "organization_id",
            "scan_id",
            "aws_account_id",
            "detector",
            "resource_type",
            "resource_id",
            "region",
            "severity",
            "confidence",
            "state",
            "title",
            "summary",
            "evidence",
            "recommended_action",
            "estimated_monthly_savings",
            "currency",
            "dedupe_key",
        ]
        statement = sql.SQL(
            "insert into {} ({}) values ({}) "
            "on conflict (aws_account_id, dedupe_key) do update set "
            "scan_id = excluded.scan_id, severity = excluded.severity, "
            "confidence = excluded.confidence, title = excluded.title, "
            "summary = excluded.summary, evidence = excluded.evidence, "
            "recommended_action = excluded.recommended_action, "
            "estimated_monthly_savings = excluded.estimated_monthly_savings, "
            "currency = excluded.currency, updated_at = now() "
            "returning {}, (xmax = 0) as inserted"
        ).format(
            sql.Identifier("public", "findings"),
            _columns(columns),
            sql.SQL(", ").join(_placeholder(name) for name in columns),
            _columns(_FINDING_RETURNING),
        )

        inserted = 0
        refreshed = 0
        persisted: list[FindingRecord] = []
        with self._source.connection() as conn, conn.cursor() as cur:
            for record in records:
                cur.execute(
                    statement,
                    (
                        record.id,
                        record.organization_id,
                        record.scan_id,
                        record.aws_account_id,
                        record.detector,
                        record.resource_type,
                        record.resource_id,
                        record.region,
                        record.severity,
                        record.confidence,
                        record.state,
                        record.title,
                        record.summary,
                        Jsonb(record.evidence),
                        record.recommended_action,
                        record.estimated_monthly_savings,
                        record.currency,
                        record.dedupe_key,
                    ),
                )
                row = cur.fetchone()
                assert row is not None
                if row.pop("inserted"):
                    inserted += 1
                else:
                    refreshed += 1
                persisted.append(_finding(row))
        return FindingUpsertResult(
            inserted=inserted, refreshed=refreshed, skipped=0, records=tuple(persisted)
        )

    def list_for_org(
        self,
        organization_id: str,
        *,
        state: str | None = None,
        aws_account_id: str | None = None,
    ) -> list[FindingRecord]:
        clauses = [sql.SQL("organization_id = %s")]
        params: list[Any] = [organization_id]
        if state:
            clauses.append(sql.SQL("state = %s"))
            params.append(state)
        if aws_account_id:
            clauses.append(sql.SQL("aws_account_id = %s"))
            params.append(aws_account_id)
        statement = _select(
            "findings",
            _FINDING_RETURNING,
            sql.SQL(" and ").join(clauses),
            order=sql.SQL("created_at desc"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, params)
            rows = cur.fetchall()
        return [_finding(row) for row in rows]

    def get(self, organization_id: str, finding_id: str) -> FindingRecord | None:
        statement = _select(
            "findings", _FINDING_RETURNING, sql.SQL("id = %s and organization_id = %s")
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (finding_id, organization_id))
            row = cur.fetchone()
        return _finding(row) if row else None

    def update(self, finding_id: str, **fields: Any) -> FindingRecord:
        columns = _validated_columns(fields, _FINDING_UPDATE_COLUMNS)
        statement = _update("findings", columns, _FINDING_RETURNING, sql.SQL("id = %s"))
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, [*_params(fields, columns), finding_id])
            row = cur.fetchone()
        if row is None:
            raise NotFoundError("Finding not found.")
        return _finding(row)


class PostgresSavingsRepository:
    def __init__(self, source: ConnectionSource) -> None:
        self._source = source

    def create(self, **fields: Any) -> SavingsRecord:
        columns = ["id", *_validated_columns(fields, _SAVINGS_INSERT_COLUMNS)]
        values = {"id": new_id(), **fields}
        statement = _insert("savings_records", columns, _SAVINGS_RETURNING)
        with self._source.connection() as conn, conn.cursor() as cur:
            try:
                cur.execute(statement, _params(values, columns))
                row = cur.fetchone()
            except UniqueViolation as exc:
                # savings_records_finding_basis_idx: one live entry per finding
                # per basis. The in-memory store raises ValueError here; a
                # conflict is the honest HTTP equivalent and cannot be mistaken
                # for a server fault.
                raise ConflictError(
                    "A ledger entry already exists for this finding and basis."
                ) from exc
            except ForeignKeyViolation as exc:
                raise NotFoundError("The referenced finding or account does not exist.") from exc
            except Exception as exc:  # noqa: BLE001 - re-raised, only classified
                raise _classify(
                    exc, check_message="The savings entry violates the ledger rules."
                ) from exc
        assert row is not None
        return _savings(row)

    def get(self, organization_id: str, record_id: str) -> SavingsRecord | None:
        statement = _select(
            "savings_records",
            _SAVINGS_RETURNING,
            sql.SQL("id = %s and organization_id = %s"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (record_id, organization_id))
            row = cur.fetchone()
        return _savings(row) if row else None

    def find_for_finding(
        self, organization_id: str, finding_id: str, *, basis: str
    ) -> SavingsRecord | None:
        statement = _select(
            "savings_records",
            _SAVINGS_RETURNING,
            sql.SQL("organization_id = %s and finding_id = %s and basis = %s"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (organization_id, finding_id, basis))
            row = cur.fetchone()
        return _savings(row) if row else None

    def list_for_org(
        self, organization_id: str, *, basis: str | None = None
    ) -> list[SavingsRecord]:
        clauses = [sql.SQL("organization_id = %s")]
        params: list[Any] = [organization_id]
        if basis:
            clauses.append(sql.SQL("basis = %s"))
            params.append(basis)
        statement = _select(
            "savings_records",
            _SAVINGS_RETURNING,
            sql.SQL(" and ").join(clauses),
            order=sql.SQL("created_at desc"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, params)
            rows = cur.fetchall()
        return [_savings(row) for row in rows]

    def update(self, record_id: str, **fields: Any) -> SavingsRecord:
        columns = _validated_columns(fields, _SAVINGS_UPDATE_COLUMNS)
        statement = _update("savings_records", columns, _SAVINGS_RETURNING, sql.SQL("id = %s"))
        with self._source.connection() as conn, conn.cursor() as cur:
            try:
                cur.execute(statement, [*_params(fields, columns), record_id])
                row = cur.fetchone()
            except Exception as exc:  # noqa: BLE001 - re-raised, only classified
                raise _classify(
                    exc, check_message="The savings entry violates the ledger rules."
                ) from exc
        if row is None:
            raise NotFoundError("Savings record not found.")
        return _savings(row)

    def delete_for_finding(self, organization_id: str, finding_id: str, *, basis: str) -> bool:
        statement = sql.SQL("delete from {} where {}").format(
            sql.Identifier("public", "savings_records"),
            sql.SQL("organization_id = %s and finding_id = %s and basis = %s"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (organization_id, finding_id, basis))
            return cur.rowcount > 0


class PostgresCostRepository:
    def __init__(self, source: ConnectionSource) -> None:
        self._source = source

    def add_many(self, records: list[CostObservationRecord]) -> int:
        """Insert cost rows, ignoring ones already recorded for the period.

        ``on conflict`` targets ``cost_observations_unique_idx``, the natural key
        (account, scan, service, period). Without it a re-scan would duplicate
        the reported bill. The return value counts rows actually inserted, so a
        caller can tell a first import from a repeat.

        Note: a unique index treats a NULL ``scan_id`` as distinct from every
        other NULL, so two rows with no scan and the same period would both
        insert. In practice a cost row is always written by a scan and carries
        an id.
        """
        if not records:
            return 0
        columns = [
            "id",
            "organization_id",
            "aws_account_id",
            "scan_id",
            "service",
            "amount",
            "currency",
            "period_start",
            "period_end",
        ]
        statement = sql.SQL(
            "insert into {} ({}) values ({}) "
            "on conflict (aws_account_id, scan_id, service, period_start) do nothing"
        ).format(
            sql.Identifier("public", "cost_observations"),
            _columns(columns),
            sql.SQL(", ").join(_placeholder(name) for name in columns),
        )
        inserted = 0
        with self._source.connection() as conn, conn.cursor() as cur:
            for record in records:
                cur.execute(
                    statement,
                    (
                        record.id,
                        record.organization_id,
                        record.aws_account_id,
                        record.scan_id,
                        record.service,
                        record.amount,
                        record.currency,
                        record.period_start,
                        record.period_end,
                    ),
                )
                # rowcount is 0 when the row conflicted and was skipped.
                inserted += cur.rowcount
        return inserted

    def list_for_org(
        self, organization_id: str, *, aws_account_id: str | None = None
    ) -> list[CostObservationRecord]:
        clauses = [sql.SQL("organization_id = %s")]
        params: list[Any] = [organization_id]
        if aws_account_id:
            clauses.append(sql.SQL("aws_account_id = %s"))
            params.append(aws_account_id)
        statement = _select(
            "cost_observations",
            _COST_RETURNING,
            sql.SQL(" and ").join(clauses),
            order=sql.SQL("period_start desc, service"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, params)
            rows = cur.fetchall()
        return [_cost(row) for row in rows]


class PostgresAuditRepository:
    def __init__(self, source: ConnectionSource) -> None:
        self._source = source

    def record(self, **fields: Any) -> AuditEventRecord:
        columns = _validated_columns(fields, _AUDIT_COLUMNS)
        values = {"id": new_id(), **fields}
        # ``actor_user_id`` is nullable, so a system event (the reaper failing a
        # scan) can be recorded without inventing a user. A non-uuid actor — the
        # literal "system" the reaper uses — would fail the foreign key to
        # auth.users, so it is recorded as a system event rather than lost.
        actor = values.get("actor_user_id")
        if actor is not None and not _is_uuid(actor):
            values["actor_user_id"] = None
        statement = _insert("audit_events", ["id", *columns], _AUDIT_RETURNING)
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, _params(values, ["id", *columns]))
            row = cur.fetchone()
        assert row is not None
        return _audit(row)

    def list_for_org(self, organization_id: str) -> list[AuditEventRecord]:
        statement = _select(
            "audit_events",
            _AUDIT_RETURNING,
            sql.SQL("organization_id = %s"),
            order=sql.SQL("created_at desc"),
        )
        with self._source.connection() as conn, conn.cursor() as cur:
            cur.execute(statement, (organization_id,))
            rows = cur.fetchall()
        return [_audit(row) for row in rows]


# --- container ---------------------------------------------------------------


class PostgresContainer:
    """The composition root for a PostgreSQL-backed runtime.

    Attribute names match :class:`app.repositories.memory.Container`, so a route
    or service cannot tell the two apart. ``database`` is the only extra, and it
    is how the container opens a multi-step transaction. There is deliberately
    no ``store`` attribute: that belongs to the in-memory implementation, and
    nothing above this boundary may depend on it.

    This container is never selected by default. It is constructed explicitly —
    see :func:`build_postgres_container`.
    """

    def __init__(self, source: ConnectionSource, *, database: Database) -> None:
        self.database = database
        self.organizations = PostgresOrganizationRepository(source)
        self.aws_accounts = PostgresAwsAccountRepository(source)
        self.scans = PostgresScanRepository(source)
        self.resources = PostgresResourceRepository(source)
        self.findings = PostgresFindingRepository(source)
        self.savings = PostgresSavingsRepository(source)
        self.costs = PostgresCostRepository(source)
        self.audit = PostgresAuditRepository(source)


def build_postgres_container(
    database: Database, *, connection: Connection[dict[str, Any]] | None = None
) -> PostgresContainer:
    """Build a PostgreSQL container.

    This is the explicit opt-in. It is **not** called by
    :func:`app.main.create_app` or :func:`app.repositories.memory.build_container`,
    which both keep the in-memory store, so a deployment cannot select PostgreSQL
    by accident. Nothing here connects either: a connection is opened lazily, on
    the first operation, and only if one is ever performed.

    Passing ``connection`` binds every repository to it, which is how
    :meth:`Database.transaction` composes a unit of work. With no connection the
    repositories open their own, one transaction per operation.
    """
    source: ConnectionSource = database if connection is None else _BoundConnection(connection)
    return PostgresContainer(source, database=database)


__all__ = [
    "ConnectionSource",
    "Database",
    "PostgresContainer",
    "build_postgres_container",
]
