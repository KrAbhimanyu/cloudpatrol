"""Repository data models.

Plain dataclasses that mirror the database rows. Keeping them separate from
both the protocols and the implementations means the same shapes are reused
whether the backing store is in-memory (this phase) or PostgreSQL/Supabase.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any


def new_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class OrganizationRecord:
    id: str
    name: str
    slug: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class MembershipRecord:
    id: str
    organization_id: str
    user_id: str
    role: str
    created_at: datetime

    @property
    def can_manage_accounts(self) -> bool:
        """Whether this role may connect or remove AWS accounts."""
        return self.role in {"owner", "admin"}


@dataclass(frozen=True, slots=True)
class AwsAccountRecord:
    """Non-secret AWS connection metadata.

    There is no credential field by design. CloudPatrol stores the role ARN
    and a reference to the external ID; it never stores access keys.
    """

    id: str
    organization_id: str
    label: str
    account_id: str
    role_arn: str
    regions: list[str]
    status: str
    status_message: str | None
    last_validated_at: datetime | None
    created_at: datetime
    created_by: str | None = None
    # Opaque reference into the secret vault. The external ID itself is never
    # stored here.
    external_id_ref: str | None = None


@dataclass(frozen=True, slots=True)
class ScanRecord:
    """A scan run and its outcome.

    ``attempts`` counts how many times a worker has picked this scan up. It is
    what lets a reaper tell "queued and never started" from "started, then the
    worker died" without guessing from timestamps.
    """

    id: str
    organization_id: str
    aws_account_id: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    resource_count: int
    finding_count: int
    partial_failures: list[dict[str, Any]] = field(default_factory=list)
    error_message: str | None = None
    created_at: datetime = field(default_factory=utc_now)
    created_by: str | None = None
    attempts: int = 0


@dataclass(frozen=True, slots=True)
class ResourceSnapshotRecord:
    id: str
    organization_id: str
    scan_id: str
    aws_account_id: str
    resource_type: str
    resource_id: str
    region: str
    name: str | None
    state: str | None
    attributes: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True, slots=True)
class FindingRecord:
    """A cost optimization opportunity.

    ``state`` is the human decision (or verification) and is never overwritten
    by a later scan; the observation fields are. ``updated_at`` moves when a
    re-scan refreshes the evidence, so the UI can show how current a finding is
    separately from when it was first seen.
    """

    id: str
    organization_id: str
    scan_id: str
    aws_account_id: str
    detector: str
    resource_type: str
    resource_id: str
    region: str
    severity: str
    confidence: str
    state: str
    title: str
    summary: str
    evidence: dict[str, Any]
    recommended_action: str
    estimated_monthly_savings: Decimal | None
    currency: str
    dedupe_key: str
    created_at: datetime
    updated_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class FindingUpsertResult:
    """Outcome of persisting a batch of findings.

    Splitting the counts matters: a scan that re-observes fifty known problems
    and finds nothing new is a very different result from one that finds
    nothing at all, and reporting both as "0 findings" would hide that.

    ``records`` holds the persisted rows — the new ones and the refreshed ones —
    so a caller that needs their ids (the savings ledger does) does not have to
    re-query and guess which candidate mapped to which row.
    """

    inserted: int = 0
    refreshed: int = 0
    skipped: int = 0
    records: tuple[FindingRecord, ...] = ()

    @property
    def total(self) -> int:
        return self.inserted + self.refreshed + self.skipped


@dataclass(frozen=True, slots=True)
class AuditEventRecord:
    id: str
    organization_id: str
    actor_user_id: str | None
    action: str
    target_type: str
    target_id: str | None
    metadata: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True, slots=True)
class SavingsRecord:
    """One entry in the savings ledger.

    ``basis`` is the column that keeps the ledgers apart, and it mirrors the
    ``savings_records`` table exactly:

    * ``potential``   — an estimate from a finding. Never money that was saved.
    * ``approved``    — a human decided to act. Still not saved.
    * ``implemented`` — the change was made. Still not *proven* saved.
    * ``verified``    — measured after the change, with evidence and a window.
    * ``inconclusive``— a measurement was attempted and did not demonstrate a
                        saving. Kept so a failed verification is not silently
                        dropped and re-attempted forever.

    Only ``verified`` is realised money. The database enforces that a
    ``verified`` row carries both evidence and a measurement window, so a
    verification cannot be recorded without something backing it.
    """

    id: str
    organization_id: str
    aws_account_id: str
    finding_id: str | None
    basis: str
    monthly_amount: Decimal
    currency: str
    evidence: dict[str, Any] | None
    measured_from: datetime | None
    measured_to: datetime | None
    created_by: str | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class CostObservationRecord:
    """A monthly cost figure for one AWS service, as reported by Cost Explorer.

    This is *billing* data, kept deliberately separate from resource inventory:

    * It comes from a different API (Cost Explorer, a global service reached
      through us-east-1) with a different IAM permission
      (``ce:GetCostAndUsage``) from the inventory calls.
    * Its permission is granted separately, so a connection may be able to list
      resources but not read costs. That has to be representable, not an error
      that fails the whole scan.
    * It is a *reported* figure. It is not a saving, and it is not attributable
      to a finding. Summing it with a savings estimate would be meaningless.

    ``amount`` is the unblended cost for ``period_start``..``period_end`` as AWS
    billed it, in ``currency``.
    """

    id: str
    organization_id: str
    aws_account_id: str
    scan_id: str | None
    service: str
    amount: Decimal
    currency: str
    period_start: str
    period_end: str
    created_at: datetime
