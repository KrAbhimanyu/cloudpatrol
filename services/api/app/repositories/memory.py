"""In-memory repository implementations.

This phase ships an in-memory store so the API, its validation and its
authorization rules are fully exercisable and testable without a database or
live credentials. A PostgreSQL/Supabase implementation will satisfy the same
protocols in a later phase, so no route or service code changes when the
backing store is swapped.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

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
    utc_now,
)

_ACTIVE_SCAN_STATUSES = frozenset({"queued", "running"})


class InMemoryStore:
    """Thread-safe in-memory backing store.

    A lock guards mutations because FastAPI serves requests concurrently and
    the duplicate-scan check is a read-then-write that must be atomic.
    """

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.organizations: dict[str, OrganizationRecord] = {}
        self.memberships: dict[str, MembershipRecord] = {}
        self.aws_accounts: dict[str, AwsAccountRecord] = {}
        self.scans: dict[str, ScanRecord] = {}
        self.resources: list[ResourceSnapshotRecord] = []
        self.findings: dict[str, FindingRecord] = {}
        self.savings_records: list[SavingsRecord] = []
        self.cost_observations: list[CostObservationRecord] = []
        self.audit_events: list[AuditEventRecord] = []


class InMemoryOrganizationRepository:
    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def get_membership(self, user_id: str, organization_id: str) -> MembershipRecord | None:
        for membership in self._store.memberships.values():
            if membership.user_id == user_id and membership.organization_id == organization_id:
                return membership
        return None

    def list_memberships(self, user_id: str) -> list[MembershipRecord]:
        return [m for m in self._store.memberships.values() if m.user_id == user_id]

    def get_organization(self, organization_id: str) -> OrganizationRecord | None:
        return self._store.organizations.get(organization_id)

    def create_organization(
        self, *, name: str, slug: str, owner_user_id: str
    ) -> OrganizationRecord:
        with self._store.lock:
            org = OrganizationRecord(id=new_id(), name=name, slug=slug, created_at=utc_now())
            self._store.organizations[org.id] = org
            membership = MembershipRecord(
                id=new_id(),
                organization_id=org.id,
                user_id=owner_user_id,
                role="owner",
                created_at=utc_now(),
            )
            self._store.memberships[membership.id] = membership
            return org


class InMemoryAwsAccountRepository:
    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def list_for_org(self, organization_id: str) -> list[AwsAccountRecord]:
        return sorted(
            (a for a in self._store.aws_accounts.values() if a.organization_id == organization_id),
            key=lambda a: a.created_at,
        )

    def get(self, organization_id: str, account_pk: str) -> AwsAccountRecord | None:
        record = self._store.aws_accounts.get(account_pk)
        # The organization check is the tenant boundary. A record belonging to
        # another organization is reported as absent rather than forbidden, so
        # this cannot be used to enumerate other tenants' records.
        if record is None or record.organization_id != organization_id:
            return None
        return record

    def find_by_account_id(self, organization_id: str, account_id: str) -> AwsAccountRecord | None:
        for record in self._store.aws_accounts.values():
            if record.organization_id == organization_id and record.account_id == account_id:
                return record
        return None

    def create(self, **fields: Any) -> AwsAccountRecord:
        with self._store.lock:
            record = AwsAccountRecord(id=new_id(), created_at=utc_now(), **fields)
            self._store.aws_accounts[record.id] = record
            return record

    def update(self, account_pk: str, **fields: Any) -> AwsAccountRecord:
        with self._store.lock:
            updated = replace(self._store.aws_accounts[account_pk], **fields)
            self._store.aws_accounts[account_pk] = updated
            return updated


class InMemoryScanRepository:
    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def list_for_org(self, organization_id: str) -> list[ScanRecord]:
        return sorted(
            (s for s in self._store.scans.values() if s.organization_id == organization_id),
            key=lambda s: s.created_at,
            reverse=True,
        )

    def get(self, organization_id: str, scan_id: str) -> ScanRecord | None:
        record = self._store.scans.get(scan_id)
        if record is None or record.organization_id != organization_id:
            return None
        return record

    def get_by_id(self, scan_id: str) -> ScanRecord | None:
        """Unscoped lookup for the worker and reaper. Not for route handlers."""
        return self._store.scans.get(scan_id)

    def find_active_for_account(
        self, organization_id: str, aws_account_id: str
    ) -> ScanRecord | None:
        for record in self._store.scans.values():
            if (
                record.organization_id == organization_id
                and record.aws_account_id == aws_account_id
                and record.status in _ACTIVE_SCAN_STATUSES
            ):
                return record
        return None

    def find_stale_active(self, *, active_before: datetime) -> list[ScanRecord]:
        """Active scans with no recent progress.

        A scan is stale if it has been active since before ``active_before``,
        measured from ``started_at`` when running and from ``created_at`` when
        still queued. Both cases mean the worker that owned it is gone.
        """
        stale: list[ScanRecord] = []
        for record in self._store.scans.values():
            if record.status not in _ACTIVE_SCAN_STATUSES:
                continue
            since = record.started_at or record.created_at
            if since < active_before:
                stale.append(record)
        return stale

    def fail_if_stale(self, scan_id: str, *, active_before: datetime, message: str) -> bool:
        """Fail a scan only if it is still stale, under the store lock.

        Guards the race between the reaper deciding a scan is abandoned and a
        worker claiming it. Without the lock the reaper could fail a scan that
        had just legitimately started.
        """
        with self._store.lock:
            current = self._store.scans.get(scan_id)
            if current is None or current.status not in _ACTIVE_SCAN_STATUSES:
                return False
            since = current.started_at or current.created_at
            if since >= active_before:
                # A worker claimed it after the reaper's scan; leave it alone.
                return False
            self._store.scans[scan_id] = replace(
                current,
                status="failed",
                finished_at=utc_now(),
                error_message=message,
            )
            return True

    def mark_running(self, scan_id: str, *, started_at: datetime) -> ScanRecord:
        """Claim a scan for execution, incrementing its attempt count."""
        with self._store.lock:
            current = self._store.scans[scan_id]
            updated = replace(
                current,
                status="running",
                started_at=started_at,
                attempts=current.attempts + 1,
            )
            self._store.scans[scan_id] = updated
            return updated

    def create(self, **fields: Any) -> ScanRecord:
        with self._store.lock:
            record = ScanRecord(id=new_id(), created_at=utc_now(), **fields)
            self._store.scans[record.id] = record
            return record

    def update(self, scan_id: str, **fields: Any) -> ScanRecord:
        with self._store.lock:
            updated = replace(self._store.scans[scan_id], **fields)
            self._store.scans[scan_id] = updated
            return updated


class InMemoryResourceRepository:
    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def add_many(self, records: list[ResourceSnapshotRecord]) -> None:
        with self._store.lock:
            self._store.resources.extend(records)

    def list_for_scan(self, organization_id: str, scan_id: str) -> list[ResourceSnapshotRecord]:
        return [
            r
            for r in self._store.resources
            if r.scan_id == scan_id and r.organization_id == organization_id
        ]


class InMemoryFindingRepository:
    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def upsert_many(self, records: list[FindingRecord]) -> FindingUpsertResult:
        """Insert new findings and refresh the evidence of existing ones.

        ``dedupe_key`` uniqueness is enforced here exactly as a database unique
        index would, so re-running a scan cannot inflate finding counts or
        double-count potential savings.

        A re-observed finding is *refreshed*, not skipped. The alternative —
        dropping it — would leave the row pointing at the old scan with old
        evidence, so a finding the latest scan confirmed would look stale, and a
        scan that re-confirmed fifty problems would report finding_count 0.

        The human decision is preserved. ``state`` and ``created_at`` are
        carried over from the existing row, so a re-scan cannot silently revert
        an acknowledgement or a dismissal.
        """
        result = FindingUpsertResult()
        persisted: list[FindingRecord] = []
        with self._store.lock:
            by_key = {f.dedupe_key: f for f in self._store.findings.values()}

            for record in records:
                existing = by_key.get(record.dedupe_key)
                if existing is None:
                    self._store.findings[record.id] = record
                    by_key[record.dedupe_key] = record
                    persisted.append(record)
                    result = replace(result, inserted=result.inserted + 1)
                    continue

                refreshed = replace(
                    existing,
                    # Observation data is replaced with the newest evidence.
                    scan_id=record.scan_id,
                    severity=record.severity,
                    confidence=record.confidence,
                    title=record.title,
                    summary=record.summary,
                    evidence=record.evidence,
                    recommended_action=record.recommended_action,
                    estimated_monthly_savings=record.estimated_monthly_savings,
                    currency=record.currency,
                    updated_at=utc_now(),
                    # ``state`` and ``created_at`` deliberately unchanged.
                )
                self._store.findings[existing.id] = refreshed
                by_key[record.dedupe_key] = refreshed
                persisted.append(refreshed)
                result = replace(result, refreshed=result.refreshed + 1)

        return replace(result, records=tuple(persisted))

    def list_for_org(
        self,
        organization_id: str,
        *,
        state: str | None = None,
        aws_account_id: str | None = None,
    ) -> list[FindingRecord]:
        results = [f for f in self._store.findings.values() if f.organization_id == organization_id]
        if state:
            results = [f for f in results if f.state == state]
        if aws_account_id:
            results = [f for f in results if f.aws_account_id == aws_account_id]
        return sorted(results, key=lambda f: f.created_at, reverse=True)

    def get(self, organization_id: str, finding_id: str) -> FindingRecord | None:
        record = self._store.findings.get(finding_id)
        if record is None or record.organization_id != organization_id:
            return None
        return record

    def update(self, finding_id: str, **fields: Any) -> FindingRecord:
        with self._store.lock:
            updated = replace(self._store.findings[finding_id], **fields)
            self._store.findings[finding_id] = updated
            return updated


class InMemoryCostRepository:
    """In-memory billing store.

    Deduplication is per (aws_account_id, scan_id, service, period_start), which
    mirrors the uniqueness a database index would enforce. Without it, a
    re-scanned account would report twice its real cost.
    """

    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def add_many(self, records: list[CostObservationRecord]) -> int:
        inserted = 0
        with self._store.lock:
            seen = {
                (c.aws_account_id, c.scan_id, c.service, c.period_start)
                for c in self._store.cost_observations
            }
            for record in records:
                key = (record.aws_account_id, record.scan_id, record.service, record.period_start)
                if key in seen:
                    continue
                self._store.cost_observations.append(record)
                seen.add(key)
                inserted += 1
        return inserted

    def list_for_org(
        self, organization_id: str, *, aws_account_id: str | None = None
    ) -> list[CostObservationRecord]:
        results = [c for c in self._store.cost_observations if c.organization_id == organization_id]
        if aws_account_id:
            results = [c for c in results if c.aws_account_id == aws_account_id]
        return sorted(results, key=lambda c: (c.period_start, c.service), reverse=True)


class InMemorySavingsRepository:
    """In-memory savings ledger.

    The uniqueness rule the database enforces with a partial unique index is
    enforced here under the store lock, so the in-memory store cannot accept a
    duplicate that PostgreSQL would reject.
    """

    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def create(self, **fields: Any) -> SavingsRecord:
        with self._store.lock:
            record = SavingsRecord(id=new_id(), created_at=utc_now(), **fields)
            for existing in self._store.savings_records:
                if (
                    existing.organization_id == record.organization_id
                    and record.finding_id is not None
                    and existing.finding_id == record.finding_id
                    and existing.basis == record.basis
                ):
                    raise ValueError("A ledger entry already exists for this finding and basis.")
            self._store.savings_records.append(record)
            return record

    def get(self, organization_id: str, record_id: str) -> SavingsRecord | None:
        for record in self._store.savings_records:
            if record.id == record_id and record.organization_id == organization_id:
                return record
        return None

    def find_for_finding(
        self, organization_id: str, finding_id: str, *, basis: str
    ) -> SavingsRecord | None:
        for record in self._store.savings_records:
            if (
                record.organization_id == organization_id
                and record.finding_id == finding_id
                and record.basis == basis
            ):
                return record
        return None

    def list_for_org(
        self, organization_id: str, *, basis: str | None = None
    ) -> list[SavingsRecord]:
        results = [r for r in self._store.savings_records if r.organization_id == organization_id]
        if basis:
            results = [r for r in results if r.basis == basis]
        return sorted(results, key=lambda r: r.created_at, reverse=True)

    def update(self, record_id: str, **fields: Any) -> SavingsRecord:
        with self._store.lock:
            for index, record in enumerate(self._store.savings_records):
                if record.id == record_id:
                    updated = replace(record, **fields)
                    self._store.savings_records[index] = updated
                    return updated
            raise KeyError(record_id)

    def delete_for_finding(self, organization_id: str, finding_id: str, *, basis: str) -> bool:
        with self._store.lock:
            for index, record in enumerate(self._store.savings_records):
                if (
                    record.organization_id == organization_id
                    and record.finding_id == finding_id
                    and record.basis == basis
                ):
                    del self._store.savings_records[index]
                    return True
            return False


class InMemoryAuditRepository:
    def __init__(self, store: InMemoryStore) -> None:
        self._store = store

    def record(self, **fields: Any) -> AuditEventRecord:
        with self._store.lock:
            event = AuditEventRecord(id=new_id(), created_at=utc_now(), **fields)
            self._store.audit_events.append(event)
            return event

    def list_for_org(self, organization_id: str) -> list[AuditEventRecord]:
        return [e for e in self._store.audit_events if e.organization_id == organization_id]


@dataclass(slots=True)
class Container:
    """Composition root holding the repository implementations."""

    store: InMemoryStore
    organizations: InMemoryOrganizationRepository
    aws_accounts: InMemoryAwsAccountRepository
    scans: InMemoryScanRepository
    resources: InMemoryResourceRepository
    findings: InMemoryFindingRepository
    savings: InMemorySavingsRepository
    costs: InMemoryCostRepository
    audit: InMemoryAuditRepository


def build_container() -> Container:
    store = InMemoryStore()
    return Container(
        store=store,
        organizations=InMemoryOrganizationRepository(store),
        aws_accounts=InMemoryAwsAccountRepository(store),
        scans=InMemoryScanRepository(store),
        resources=InMemoryResourceRepository(store),
        findings=InMemoryFindingRepository(store),
        savings=InMemorySavingsRepository(store),
        costs=InMemoryCostRepository(store),
        audit=InMemoryAuditRepository(store),
    )
