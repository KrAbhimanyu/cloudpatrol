"""AWS account routes: register, list, validate.

Authorization notes:

* Every route requires a verified bearer token.
* Listing and creating are scoped to the organization named in the
  ``X-Organization-Id`` header, and the caller's membership is proven
  server-side before the handler runs.
* Connecting an account is a privileged action, so it additionally requires an
  owner or admin role.
* The external ID is accepted on write and never returned.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, status

from app.core.dependencies import OrganizationContext
from app.core.errors import ConflictError, ForbiddenError, NotFoundError
from app.schemas.aws_account import (
    AwsAccountCreate,
    AwsAccountList,
    AwsAccountRead,
    AwsConnectionValidation,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/aws/accounts", tags=["aws-accounts"])


@router.get("", response_model=AwsAccountList, summary="List connected AWS accounts")
async def list_accounts(context: OrganizationContext, request: Request) -> AwsAccountList:
    principal, membership = context
    repository = request.app.state.container.aws_accounts
    records = repository.list_for_org(membership.organization_id)
    return AwsAccountList(
        items=[AwsAccountRead.model_validate(r) for r in records],
        total=len(records),
    )


@router.post(
    "",
    response_model=AwsAccountRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register and validate an AWS account",
)
async def create_account(
    payload: AwsAccountCreate,
    context: OrganizationContext,
    request: Request,
) -> AwsAccountRead:
    principal, membership = context

    if not membership.can_manage_accounts:
        raise ForbiddenError("Only an owner or admin can connect an AWS account.")

    container = request.app.state.container
    accounts = container.aws_accounts

    # The role ARN embeds an account ID. If it disagrees with the submitted
    # account ID, the connection is misconfigured; reject it before any AWS
    # call so the user gets a clear message.
    if payload.role_arn_account_id() != payload.account_id:
        raise ForbiddenError("The account ID does not match the account embedded in the role ARN.")

    if accounts.find_by_account_id(membership.organization_id, payload.account_id):
        raise ConflictError("This AWS account is already connected to this organization.")

    service = request.app.state.aws_connection_service

    # Validation performs the AssumeRole and identity check. Credentials are
    # used immediately and never stored.
    _credentials, caller_arn, expires_at = service.validate_connection(
        organization_id=membership.organization_id,
        account_id=payload.account_id,
        role_arn=payload.role_arn,
        external_id=payload.external_id,
        region=payload.regions[0],
    )

    record = accounts.create(
        organization_id=membership.organization_id,
        created_by=principal.user_id,
        label=payload.label,
        account_id=payload.account_id,
        role_arn=payload.role_arn,
        regions=payload.regions,
        status="validated",
        status_message=None,
        last_validated_at=None,
        external_id_ref=None,
    )

    # The external ID is a shared secret, so it goes to the vault and the row
    # keeps only an opaque reference.
    vault = request.app.state.secret_vault
    vault.put(f"aws-account/{record.id}/external-id", payload.external_id)
    record = accounts.update(record.id, external_id_ref=f"aws-account/{record.id}/external-id")

    container.audit.record(
        organization_id=membership.organization_id,
        actor_user_id=principal.user_id,
        action="aws_account.connected",
        target_type="aws_account",
        target_id=record.id,
        metadata={"account_id": payload.account_id, "regions": payload.regions},
    )

    logger.info(
        "AWS account connected",
        extra={"org_id": membership.organization_id, "account_id": payload.account_id},
    )
    return AwsAccountRead.model_validate(record)


@router.post(
    "/{account_pk}/validate",
    response_model=AwsConnectionValidation,
    summary="Re-validate an existing AWS connection",
)
async def validate_account(
    account_pk: str,
    context: OrganizationContext,
    request: Request,
) -> AwsConnectionValidation:
    """Re-check that a stored connection still works.

    The external ID is not stored, so re-validation cannot re-assume the role
    on its own. It reports the stored connection state instead, and the user
    re-enters the external ID to refresh it. This is a deliberate trade-off:
    persisting an external ID in a plaintext column would be a worse risk than
    an extra step at re-validation time.
    """
    principal, membership = context

    if not membership.can_manage_accounts:
        raise ForbiddenError("Only an owner or admin can validate an AWS account.")

    record = request.app.state.container.aws_accounts.get(membership.organization_id, account_pk)
    if record is None:
        raise NotFoundError("AWS account not found.")

    return AwsConnectionValidation(
        account_id=record.account_id,
        status=record.status,
        message=(
            record.status_message
            or "Stored connection metadata is present. Run a scan to re-validate against AWS."
        ),
        caller_identity_arn=None,
        assumed_role_arn=record.role_arn,
        credentials_expire_at=None,
    )
