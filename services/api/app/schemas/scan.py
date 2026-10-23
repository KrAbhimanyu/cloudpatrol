"""Pydantic schemas for scans, resources and findings."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ScanStatus = Literal["queued", "running", "completed", "partial", "failed"]
ServiceStatus = Literal["ok", "skipped", "failed"]
FindingState = Literal["estimated", "acknowledged", "implemented", "verified", "dismissed"]
Severity = Literal["low", "medium", "high"]
Confidence = Literal["low", "medium", "high"]


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    aws_account_id: str = Field(min_length=1, max_length=64)


class PartialFailure(BaseModel):
    """A per-service, per-region failure recorded during a scan.

    Its presence is what forces a scan to ``partial`` instead of
    ``completed``, so a partially failed scan can never be reported as a
    clean success.
    """

    service: str
    region: str | None = None
    code: str
    message: str


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    aws_account_id: str
    status: ScanStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    resource_count: int = 0
    finding_count: int = 0
    partial_failures: list[PartialFailure] = Field(default_factory=list)
    error_message: str | None = None
    created_at: datetime


class ScanList(BaseModel):
    items: list[ScanRead]
    total: int


class ResourceSnapshotRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    resource_type: str
    resource_id: str
    region: str
    name: str | None = None
    state: str | None = None
    attributes: dict[str, object] = Field(default_factory=dict)


class FindingRead(BaseModel):
    """A cost optimization opportunity.

    ``state`` starts at ``estimated``. A figure is only ever labelled
    ``verified`` once post-change evidence exists, which this phase does not
    produce.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    scan_id: str
    aws_account_id: str
    detector: str
    resource_type: str
    resource_id: str
    region: str
    severity: Severity
    confidence: Confidence
    state: FindingState
    title: str
    summary: str
    evidence: dict[str, object] = Field(default_factory=dict)
    recommended_action: str
    estimated_monthly_savings: Decimal | None = None
    currency: str = "USD"
    created_at: datetime
    updated_at: datetime | None = None


class FindingList(BaseModel):
    items: list[FindingRead]
    total: int


class FindingReviewUpdate(BaseModel):
    """Allowed review transitions for a finding."""

    model_config = ConfigDict(extra="forbid")

    state: Literal["acknowledged", "dismissed"]
    note: str | None = Field(default=None, max_length=2000)


# --- Savings ledger -------------------------------------------------------

SavingsBasis = Literal["potential", "approved", "implemented", "verified", "inconclusive"]


class SavingsEntryRead(BaseModel):
    """One entry in the savings ledger.

    ``basis`` is what keeps the buckets apart. Only a ``verified`` entry
    represents money that has actually stopped being spent.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    aws_account_id: str
    finding_id: str | None = None
    basis: SavingsBasis
    monthly_amount: Decimal
    currency: str = "USD"
    evidence: dict[str, object] | None = None
    measured_from: datetime | None = None
    measured_to: datetime | None = None
    created_by: str | None = None
    created_at: datetime
    # The detector that produced the originating finding, resolved on read.
    # Null for an entry with no finding. Carried here so a client can group
    # potential savings by detector without a second request per entry.
    detector: str | None = None


class SavingsLedgerRead(BaseModel):
    """Totals per basis, with potential and verified kept separate."""

    currency: str
    potential_monthly_savings: Decimal
    approved_monthly_savings: Decimal
    implemented_monthly_savings: Decimal
    verified_monthly_savings: Decimal
    inconclusive_monthly_savings: Decimal
    potential_count: int
    approved_count: int
    implemented_count: int
    verified_count: int
    inconclusive_count: int
    annualised_verified_savings: Decimal
    entries: list[SavingsEntryRead] = Field(default_factory=list)


class SavingsAdvanceRequest(BaseModel):
    """Request to move a finding's ledger entry to the next basis.

    ``evidence``, ``measured_from`` and ``measured_to`` are required when
    advancing to ``verified``; the service rejects the transition without them,
    because an unmeasured figure must not be labelled as achieved.
    """

    model_config = ConfigDict(extra="forbid")

    target_basis: SavingsBasis
    monthly_amount: Decimal | None = Field(default=None, ge=0)
    evidence: dict[str, object] | None = None
    measured_from: datetime | None = None
    measured_to: datetime | None = None
    note: str | None = Field(default=None, max_length=2000)


class CostObservationRead(BaseModel):
    """A reported cost figure, kept apart from savings.

    This is what AWS billed for a service in a window. It is not a saving and
    it is not attributable to a finding.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    aws_account_id: str
    scan_id: str | None = None
    service: str
    amount: Decimal
    currency: str
    period_start: str
    period_end: str
    created_at: datetime


class CostSummaryRead(BaseModel):
    """Reported spend, grouped by service.

    ``available`` is False when Cost Explorer could not be read — a missing
    permission, for example. The totals are then absent rather than zero, so a
    caller cannot mistake "we could not read the bill" for "the bill is $0".
    """

    available: bool
    currency: str
    period_start: str | None = None
    period_end: str | None = None
    total_amount: Decimal | None = None
    by_service: list[CostObservationRead] = Field(default_factory=list)
