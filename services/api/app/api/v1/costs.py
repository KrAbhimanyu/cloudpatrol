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

    currency = records[0].currency
    total = sum((r.amount for r in records), start=Decimal("0"))
    return CostSummaryRead(
        available=True,
        currency=currency,
        period_start=min(r.period_start for r in records),
        period_end=max(r.period_end for r in records),
        total_amount=total,
        by_service=[CostObservationRead.model_validate(r) for r in records],
    )
