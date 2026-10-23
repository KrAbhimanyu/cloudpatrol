"""Billing data ingestion from AWS Cost Explorer.

Inventory and billing are separated on purpose, and this module is the billing
half:

* **Different API.** Cost Explorer (``ce:GetCostAndUsage``) is a global service
  reached through us-east-1, regardless of which region the account's resources
  live in.
* **Different permission.** ``ce:GetCostAndUsage`` is not part of the EC2 or
  CloudWatch read permissions. A customer may grant resource discovery and
  withhold cost data, and that is a legitimate configuration.
* **Different meaning.** A reported cost is what AWS billed. It is not a
  saving, and it is not attributable to a finding.

Because the permission is separate, a denial here must not fail a scan. It is
reported as a partial failure and the billing figures are simply absent — never
zero. Reporting "cost: $0.00" when the permission was missing would be a lie
about the customer's bill, which is the worst possible failure mode for a cost
tool.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol

from app.aws.adapter import AwsAdapter, AwsCredentials
from app.core.errors import AppError, ErrorCode
from app.repositories.models import CostObservationRecord, new_id, utc_now

logger = logging.getLogger(__name__)

# Cost Explorer retains 12 months of daily data and 36 of monthly. One month is
# the useful default: it is what a "this month's bill" figure means.
DEFAULT_LOOKBACK_DAYS = 30


class BillingErrorCode(Protocol):  # pragma: no cover - documentation only
    """Marker for the error codes this module distinguishes."""


@dataclass(frozen=True, slots=True)
class BillingResult:
    """The outcome of a billing collection attempt.

    ``observations`` empty with ``failure`` set is the honest representation of
    "we could not read the bill". ``observations`` empty with ``failure`` None
    means the account genuinely reported no cost in the window.
    """

    observations: list[CostObservationRecord]
    failure: dict[str, Any] | None = None

    @property
    def total_amount(self) -> Decimal:
        return sum((o.amount for o in self.observations), start=Decimal("0"))


class BillingService:
    """Collects Cost Explorer data and normalises it into observations."""

    def __init__(self, adapter: AwsAdapter) -> None:
        self._adapter = adapter

    def collect(
        self,
        credentials: AwsCredentials,
        *,
        organization_id: str,
        aws_account_id: str,
        scan_id: str | None,
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
        today: date | None = None,
    ) -> BillingResult:
        """Fetch cost grouped by service for the lookback window.

        A denial or any other AWS failure is returned as ``failure`` rather than
        raised, so the caller can record it as a partial failure and continue.
        """
        end = today or datetime.now(UTC).date()
        start = end - timedelta(days=lookback_days)

        try:
            results = self._adapter.get_cost_and_usage(
                credentials,
                start_date=start.isoformat(),
                end_date=end.isoformat(),
            )
        except AppError as exc:
            logger.info(
                "Cost Explorer collection failed",
                extra={"code": str(exc.code), "account_id": aws_account_id},
            )
            return BillingResult(
                observations=[],
                failure={
                    "service": "ce",
                    "region": None,
                    "code": str(exc.code),
                    "message": exc.message,
                    "occurrences": 1,
                },
            )

        observations = self._normalise(
            results,
            organization_id=organization_id,
            aws_account_id=aws_account_id,
            scan_id=scan_id,
        )
        return BillingResult(observations=observations, failure=None)

    def _normalise(
        self,
        results: list[dict[str, Any]],
        *,
        organization_id: str,
        aws_account_id: str,
        scan_id: str | None,
    ) -> list[CostObservationRecord]:
        """Convert Cost Explorer ``ResultsByTime`` into one row per service.

        The response shape is::

            [{"TimePeriod": {"Start": "...", "End": "..."},
              "Groups": [{"Keys": ["Amazon Elastic Compute Cloud - Compute"],
                          "Metrics": {"UnblendedCost": {"Amount": "12.34",
                                                       "Unit": "USD"}}}],
              "Total": {...}}]

        A row that cannot be parsed is skipped and logged rather than guessed
        at: a fabricated cost figure is worse than a missing one.
        """
        observations: list[CostObservationRecord] = []

        for period in results:
            window = period.get("TimePeriod") or {}
            period_start = str(window.get("Start") or "")
            period_end = str(window.get("End") or "")
            if not period_start or not period_end:
                logger.warning("Cost Explorer result had no time period; skipping")
                continue

            groups = period.get("Groups") or []
            if not groups:
                # No Groups means the call was made without GroupBy, so only a
                # total is available. Record it under a single label so the
                # figure is not lost.
                total = period.get("Total") or {}
                record = self._row_from_metrics(
                    total,
                    service="__total__",
                    organization_id=organization_id,
                    aws_account_id=aws_account_id,
                    scan_id=scan_id,
                    period_start=period_start,
                    period_end=period_end,
                )
                if record is not None:
                    observations.append(record)
                continue

            for group in groups:
                keys = group.get("Keys") or []
                service = str(keys[0]) if keys else "unknown"
                record = self._row_from_metrics(
                    group.get("Metrics") or {},
                    service=service,
                    organization_id=organization_id,
                    aws_account_id=aws_account_id,
                    scan_id=scan_id,
                    period_start=period_start,
                    period_end=period_end,
                )
                if record is not None:
                    observations.append(record)

        return observations

    def _row_from_metrics(
        self,
        metrics: dict[str, Any],
        *,
        service: str,
        organization_id: str,
        aws_account_id: str,
        scan_id: str | None,
        period_start: str,
        period_end: str,
    ) -> CostObservationRecord | None:
        unblended = metrics.get("UnblendedCost") or {}
        raw_amount = unblended.get("Amount")
        if raw_amount is None:
            return None
        try:
            amount = Decimal(str(raw_amount))
        except (InvalidOperation, ValueError):
            logger.warning(
                "Cost Explorer returned an unparsable amount", extra={"service": service}
            )
            return None

        return CostObservationRecord(
            id=new_id(),
            organization_id=organization_id,
            aws_account_id=aws_account_id,
            scan_id=scan_id,
            service=service,
            amount=amount,
            currency=str(unblended.get("Unit") or "USD"),
            period_start=period_start,
            period_end=period_end,
            created_at=utc_now(),
        )


def is_billing_permission_denied(error_code: str) -> bool:
    """Whether a failure was specifically a missing Cost Explorer permission.

    Worth distinguishing, because the fix is a policy change the customer can
    make, and the UI can say so precisely instead of reporting a generic error.
    """
    return error_code == str(ErrorCode.AWS_PERMISSION_DENIED)
