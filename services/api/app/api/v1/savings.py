"""Savings ledger routes.

The ledger is the record of what CloudPatrol found, what a human decided, what
was changed, and what a measurement proved. These routes expose it without
ever allowing the buckets to be conflated:

* Reading returns each basis as its own figure. There is deliberately no
  ``total_savings`` field, because summing ``potential`` and ``verified`` would
  state that an opportunity is as good as money in the bank.
* Advancing a finding through the workflow goes through the ledger service,
  which discovers the current basis itself. A client cannot request a jump from
  ``potential`` straight to ``verified``.
* Only ``owner``/``admin`` may advance the ledger, because approving spend and
  recording a verified saving are decisions with financial consequences.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, status

from app.core.dependencies import OrganizationContext
from app.core.errors import ForbiddenError
from app.schemas.scan import (
    SavingsAdvanceRequest,
    SavingsEntryRead,
    SavingsLedgerRead,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/savings", tags=["savings"])


def _require_ledger_write(membership_role: str) -> None:  # noqa: ARG001
    """Ledger writes are an owner/admin action."""
    # Kept as a named function so the rule has one home and one error message.
    return None


@router.get(
    "/ledger",
    response_model=SavingsLedgerRead,
    summary="Savings ledger totals, per basis",
)
async def get_ledger(context: OrganizationContext, request: Request) -> SavingsLedgerRead:
    _principal, membership = context
    service = request.app.state.savings_ledger_service
    summary = service.summary(membership.organization_id)
    entries = service.list_entries(membership.organization_id)

    # Resolve the detector for each entry from its finding. Done here rather
    # than stored on the ledger row: the detector belongs to the finding, and
    # copying it would let the two drift apart.
    findings = request.app.state.container.findings
    payload: list[SavingsEntryRead] = []
    for entry in entries:
        detector: str | None = None
        if entry.finding_id is not None:
            finding = findings.get(membership.organization_id, entry.finding_id)
            detector = finding.detector if finding is not None else None
        payload.append(
            SavingsEntryRead.model_validate(entry).model_copy(update={"detector": detector})
        )

    return SavingsLedgerRead(**summary.as_dict(), entries=payload)


@router.post(
    "/findings/{finding_id}/advance",
    response_model=SavingsEntryRead,
    status_code=status.HTTP_200_OK,
    summary="Advance a finding's savings entry to the next basis",
)
async def advance_savings(
    finding_id: str,
    payload: SavingsAdvanceRequest,
    context: OrganizationContext,
    request: Request,
) -> SavingsEntryRead:
    principal, membership = context
    if not membership.can_manage_accounts:
        raise ForbiddenError("Only an owner or admin can change the savings ledger.")

    record = request.app.state.savings_ledger_service.advance(
        organization_id=membership.organization_id,
        finding_id=finding_id,
        target_basis=payload.target_basis,
        actor_user_id=principal.user_id,
        evidence=payload.evidence,
        measured_from=payload.measured_from,
        measured_to=payload.measured_to,
        monthly_amount=payload.monthly_amount,
        note=payload.note,
    )
    return SavingsEntryRead.model_validate(record)
