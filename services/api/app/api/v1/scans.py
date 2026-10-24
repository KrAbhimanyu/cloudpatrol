"""Scan routes: queue a scan, read its status, list history.

A scan is *accepted* here and executed on a background worker. Reading many
services across many regions takes far longer than a request should be held
open, so this returns 202 with the queued scan and the client polls
``GET /scans/{id}`` for the outcome.

The role is assumed before the scan row is created. If the assumption fails
the request fails and nothing is left behind — a `queued` row with no worker
behind it counts as an active scan and would block the account indefinitely.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, status

from app.core.dependencies import OrganizationContext
from app.core.errors import ConflictError, NotFoundError
from app.repositories.models import utc_now
from app.schemas.scan import ScanCreate, ScanList, ScanRead
from app.services.scan_runner import ScanJob

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=ScanList, summary="List scan history")
async def list_scans(context: OrganizationContext, request: Request) -> ScanList:
    _principal, membership = context
    records = request.app.state.container.scans.list_for_org(membership.organization_id)
    return ScanList(
        items=[ScanRead.model_validate(r) for r in records],
        total=len(records),
    )


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a read-only scan for an AWS account",
)
async def create_scan(
    payload: ScanCreate,
    context: OrganizationContext,
    request: Request,
) -> ScanRead:
    principal, membership = context
    container = request.app.state.container

    account = container.aws_accounts.get(membership.organization_id, payload.aws_account_id)
    if account is None:
        raise NotFoundError("AWS account not found.")

    # Prove the connection still works before accepting the job, so a customer
    # who has revoked the trust policy learns immediately rather than through a
    # scan that fails a moment later.
    request.app.state.aws_connection_service.validate_connection(
        organization_id=membership.organization_id,
        account_id=account.account_id,
        role_arn=account.role_arn,
        external_id=_resolve_external_id(request, account),
        region=account.regions[0],
    )

    # Overlapping scans for one account would duplicate work and race on the
    # same findings. ``create_if_no_active`` performs the check and the insert as
    # one operation, so this route no longer reaches into the store's lock: the
    # in-memory repository takes its own lock, and the PostgreSQL repository uses
    # a guarded insert backed by a partial unique index.
    scan = container.scans.create_if_no_active(
        organization_id=membership.organization_id,
        aws_account_id=account.id,
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by=principal.user_id,
    )

    try:
        request.app.state.scan_pool.submit(
            ScanJob(
                scan_id=scan.id,
                organization_id=membership.organization_id,
                aws_account_id=account.id,
                created_by=principal.user_id,
            )
        )
    except ConflictError:
        # The queue refused the job, so no worker will ever pick it up. Failing
        # the row immediately keeps it from blocking this account forever,
        # which a stranded `queued` row would do.
        container.scans.update(
            scan.id,
            status="failed",
            finished_at=utc_now(),
            error_message="The scan could not be queued. Please retry.",
        )
        raise

    return ScanRead.model_validate(scan)


def _resolve_external_id(request: Request, account: object) -> str:
    """Load the external ID from the vault using the account's reference.

    The vault reference is the only thing stored on the account row. If it is
    missing or the secret has been evicted, the scan cannot proceed — failing
    loudly here is correct, because proceeding without the external ID would
    mean assuming a role without the control that makes the assumption safe.
    """
    reference = getattr(account, "external_id_ref", None)
    if not reference:
        raise ConflictError(
            "This AWS account has no stored external ID. Reconnect the account to store it."
        )
    value = request.app.state.secret_vault.get(reference)
    if not value:
        raise ConflictError(
            "The stored external ID for this account is unavailable. Reconnect the account."
        )
    return value


@router.get("/{scan_id}", response_model=ScanRead, summary="Get scan status")
async def get_scan(scan_id: str, context: OrganizationContext, request: Request) -> ScanRead:
    _principal, membership = context
    record = request.app.state.container.scans.get(membership.organization_id, scan_id)
    if record is None:
        raise NotFoundError("Scan not found.")
    return ScanRead.model_validate(record)
