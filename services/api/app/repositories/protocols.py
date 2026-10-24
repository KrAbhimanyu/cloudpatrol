"""Repository protocols — the data-access contract.

Routes and services depend on these protocols, never on a concrete store.
Swapping the in-memory implementation for PostgreSQL/Supabase requires no
change above this boundary.

Tenancy rule: every read that returns tenant data takes an
``organization_id`` and filters by it. No method returns records across
organizations, so a caller cannot accidentally read another tenant's data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

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
)


class OrganizationRepository(Protocol):
    def get_membership(self, user_id: str, organization_id: str) -> MembershipRecord | None: ...
    def list_memberships(self, user_id: str) -> list[MembershipRecord]: ...
    def get_organization(self, organization_id: str) -> OrganizationRecord | None: ...
    def create_organization(
        self, *, name: str, slug: str, owner_user_id: str
    ) -> OrganizationRecord: ...


class AwsAccountRepository(Protocol):
    def list_for_org(self, organization_id: str) -> list[AwsAccountRecord]: ...
    def get(self, organization_id: str, account_pk: str) -> AwsAccountRecord | None: ...
    def find_by_account_id(
        self, organization_id: str, account_id: str
    ) -> AwsAccountRecord | None: ...
    def create(self, **fields: Any) -> AwsAccountRecord: ...
    def update(self, account_pk: str, **fields: Any) -> AwsAccountRecord: ...


class ScanRepository(Protocol):
    def list_for_org(self, organization_id: str) -> list[ScanRecord]: ...
    def get(self, organization_id: str, scan_id: str) -> ScanRecord | None: ...
    def get_by_id(self, scan_id: str) -> ScanRecord | None:
        """Look up a scan without an organization filter.

        INTERNAL USE ONLY — for the background worker and the stale-scan
        reaper, which act on scans that already exist and carry their own
        organization. No route may use this, because it bypasses the tenant
        boundary that every other read enforces.
        """
        ...

    def find_active_for_account(
        self, organization_id: str, aws_account_id: str
    ) -> ScanRecord | None: ...
    def find_stale_active(self, *, active_before: datetime) -> list[ScanRecord]:
        """Active scans whose last activity predates ``active_before``.

        Used by the reaper to release scans whose worker died. Without this a
        crashed scan would keep its account locked out of future scans.
        """
        ...

    def fail_if_stale(self, scan_id: str, *, active_before: datetime, message: str) -> bool:
        """Fail a scan only if it is *still* stale, atomically.

        The reaper must not fail a scan that a worker claimed in the meantime.
        Checking staleness and writing the outcome as one locked operation is
        what makes that safe; a separate read-then-write would let a scan be
        failed a moment after it legitimately started.

        Returns True if this call failed the scan, False if it was no longer
        eligible.
        """
        ...

    def mark_running(self, scan_id: str, *, started_at: datetime) -> ScanRecord:
        """Atomically transition to ``running`` and increment ``attempts``.

        Read-modify-write under the store lock, so two workers racing on the
        same scan cannot both believe they started it.
        """
        ...

    def create_if_no_active(self, **fields: Any) -> ScanRecord:
        """Create a scan unless one is already active for the account.

        This exists so the caller does not have to hold a store lock across a
        check-then-insert. The existence check and the insert are a single
        statement, and ``scans_one_active_per_account_idx`` is the backstop for
        the race between two concurrent callers: one of them loses and is told
        so, rather than both creating an active scan.

        Raises :class:`ConflictError` when an active scan already exists.
        """
        ...

    def create(self, **fields: Any) -> ScanRecord: ...
    def update(self, scan_id: str, **fields: Any) -> ScanRecord: ...


class ResourceRepository(Protocol):
    def add_many(self, records: list[ResourceSnapshotRecord]) -> None: ...
    def list_for_scan(self, organization_id: str, scan_id: str) -> list[ResourceSnapshotRecord]: ...


class FindingRepository(Protocol):
    def upsert_many(self, records: list[FindingRecord]) -> FindingUpsertResult:
        """Insert new findings and refresh re-observed ones.

        A finding already present (matched on ``dedupe_key``) has its evidence
        and scan reference updated while its ``state`` and ``created_at`` are
        preserved. Returning split counts lets a caller distinguish "found
        nothing" from "re-confirmed what we already knew".
        """
        ...

    def list_for_org(
        self,
        organization_id: str,
        *,
        state: str | None = None,
        aws_account_id: str | None = None,
    ) -> list[FindingRecord]: ...
    def get(self, organization_id: str, finding_id: str) -> FindingRecord | None: ...
    def update(self, finding_id: str, **fields: Any) -> FindingRecord: ...


class AuditRepository(Protocol):
    def record(self, **fields: Any) -> AuditEventRecord: ...
    def list_for_org(self, organization_id: str) -> list[AuditEventRecord]: ...


class SavingsRepository(Protocol):
    """The savings ledger.

    Every method is organization-scoped. ``find_for_finding`` exists so a
    caller can ask "does this finding already have a ledger entry for this
    basis?" before writing one, which is what prevents a second scan from
    attributing the same saving twice.
    """

    def create(self, **fields: Any) -> SavingsRecord: ...
    def get(self, organization_id: str, record_id: str) -> SavingsRecord | None: ...
    def find_for_finding(
        self, organization_id: str, finding_id: str, *, basis: str
    ) -> SavingsRecord | None: ...
    def list_for_org(
        self, organization_id: str, *, basis: str | None = None
    ) -> list[SavingsRecord]: ...
    def update(self, record_id: str, **fields: Any) -> SavingsRecord: ...
    def delete_for_finding(self, organization_id: str, finding_id: str, *, basis: str) -> bool:
        """Remove a ledger entry. Used when a finding is dismissed.

        Dismissing a finding must withdraw its potential saving, or the
        dashboard keeps advertising money the user has explicitly rejected.
        """
        ...


class CostRepository(Protocol):
    """Billing observations, kept separate from inventory.

    Organization-scoped like every other read. ``add_many`` is idempotent per
    (scan, service, period) so re-running a scan does not duplicate a reported
    cost, which would inflate the apparent bill.
    """

    def add_many(self, records: list[CostObservationRecord]) -> int: ...
    def list_for_org(
        self,
        organization_id: str,
        *,
        aws_account_id: str | None = None,
    ) -> list[CostObservationRecord]: ...
