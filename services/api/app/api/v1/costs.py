"""Billing (Cost Explorer) routes.

Read-only, and deliberately reported separately from savings. A caller must not
be able to mistake reported spend for money saved, so the two live at different
paths and are never combined into one figure.
"""

from __future__ import annotations

import logging
from decimal import Decimal

from fastapi import APIRouter, Query, Request

from app.core.dependencies import OrganizationContext
from app.schemas.scan import CostObservationRead, CostSummaryRead

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/costs", tags=["costs"])


@router.get(
    "/summary",
    response_model=CostSummaryRead,
    summary="Reported AWS spend, grouped by service",
)
async def get_cost_summary(
    context: OrganizationContext,
    request: Request,
    aws_account_id: str | None = Query(default=None),
) -> CostSummaryRead:
    _principal, membership = context
    records = request.app.state.container.costs.list_for_org(
        membership.organization_id, aws_account_id=aws_account_id
    )

    if not records:
        # No observations is not the same as zero spend. The caller is told the
        # figures are unavailable, which is the honest answer when the billing
        # permission was never granted or a scan has not run.
        return CostSummaryRead(available=False, currency="USD")

    # A "total" is only meaningful within one currency and one billing period.
    # Summing observations that span several months would report a figure that
    # matches no invoice, and summing across currencies would add USD to EUR.
    # The latest period is the one a user means by "my bill", so that is the
    # period reported, and observations outside it are excluded from the total
    # rather than silently folded in.
    latest_end = max(r.period_end for r in records)
    current = [r for r in records if r.period_end == latest_end]

    currencies = {r.currency for r in current}
    if len(currencies) > 1:
        # Mixed currencies in one period is a data problem, not something to
        # paper over with a sum. Report the rows, withhold the total.
        logger.warning(
            "Cost observations span multiple currencies; withholding a total",
            extra={"org_id": membership.organization_id, "currencies": sorted(currencies)},
        )
        return CostSummaryRead(
            available=True,
            currency=next(iter(sorted(currencies))),
            period_start=min(r.period_start for r in current),
            period_end=latest_end,
            total_amount=None,
            by_service=[CostObservationRead.model_validate(r) for r in current],
        )

    currency = next(iter(currencies))
    total = sum((r.amount for r in current), start=Decimal("0"))
    return CostSummaryRead(
        available=True,
        currency=currency,
        period_start=min(r.period_start for r in current),
        period_end=latest_end,
        total_amount=total,
        by_service=[CostObservationRead.model_validate(r) for r in current],
    )
