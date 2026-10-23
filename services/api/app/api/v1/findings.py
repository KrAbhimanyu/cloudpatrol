"""Finding routes: list, detail, review transitions, savings summary.

Review transitions are constrained. A finding may move to ``acknowledged`` or
``dismissed`` through this API. It cannot be moved to ``verified`` here,
because verification requires post-change evidence that this phase cannot
produce; allowing the state to be set by hand would let an estimate be
relabelled as an achieved saving.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request

from app.core.dependencies import OrganizationContext
from app.core.errors import ConflictError, NotFoundError
from app.schemas.scan import FindingList, FindingRead, FindingReviewUpdate
from app.services.savings import summarise_savings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])

_REVIEWABLE_STATES = frozenset({"estimated", "acknowledged"})


@router.get("", response_model=FindingList, summary="List findings")
async def list_findings(
    context: OrganizationContext,
    request: Request,
    state: str | None = None,
    aws_account_id: str | None = None,
) -> FindingList:
    _principal, membership = context
    records = request.app.state.container.findings.list_for_org(
        membership.organization_id,
        state=state,
        aws_account_id=aws_account_id,
    )
    return FindingList(
        items=[FindingRead.model_validate(r) for r in records],
        total=len(records),
    )


@router.get("/{finding_id}", response_model=FindingRead, summary="Get a finding")
async def get_finding(
    finding_id: str, context: OrganizationContext, request: Request
) -> FindingRead:
    _principal, membership = context
    record = request.app.state.container.findings.get(membership.organization_id, finding_id)
    if record is None:
        raise NotFoundError("Finding not found.")
    return FindingRead.model_validate(record)


@router.patch(
    "/{finding_id}",
    response_model=FindingRead,
    summary="Review a finding",
)
async def review_finding(
    finding_id: str,
    payload: FindingReviewUpdate,
    context: OrganizationContext,
    request: Request,
) -> FindingRead:
    principal, membership = context
    container = request.app.state.container

    record = container.findings.get(membership.organization_id, finding_id)
    if record is None:
        raise NotFoundError("Finding not found.")

    if record.state not in _REVIEWABLE_STATES:
        raise ConflictError(
            f"A finding in state '{record.state}' cannot be reviewed.",
            details={"current_state": record.state, "allowed_from": sorted(_REVIEWABLE_STATES)},
        )

    updated = container.findings.update(finding_id, state=payload.state)

    # Dismissing an opportunity must withdraw its potential saving, or the
    # dashboard keeps advertising money the user has explicitly rejected.
    if payload.state == "dismissed":
        request.app.state.savings_ledger_service.withdraw(
            organization_id=membership.organization_id,
            finding_id=finding_id,
            actor_user_id=principal.user_id,
        )

    container.audit.record(
        organization_id=membership.organization_id,
        actor_user_id=principal.user_id,
        action=f"finding.{payload.state}",
        target_type="finding",
        target_id=finding_id,
        metadata={"note": payload.note, "previous_state": record.state},
    )
    return FindingRead.model_validate(updated)


@router.get("/summary/savings", summary="Potential and verified savings")
async def savings_summary(context: OrganizationContext, request: Request) -> dict[str, object]:
    """Aggregate savings, keeping potential and verified strictly apart.

    Only ``verified_monthly_savings`` represents realised money. In this phase
    it is always zero, because no remediation has occurred.
    """
    _principal, membership = context
    records = request.app.state.container.findings.list_for_org(membership.organization_id)
    return summarise_savings(records).as_dict()
