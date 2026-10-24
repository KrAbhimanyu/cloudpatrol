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
from app.core.errors import AppError, ConflictError, ForbiddenError, NotFoundError
from app.repositories.models import utc_now
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

    # The allowed-region list is a real constraint, not documentation. A scan
    # makes outbound AWS calls per configured region, so an unbounded list is
    # both a cost and an operational risk. Rejecting here means a typo or a
    # hostile payload cannot widen the scan's reach.
    unsupported = sorted(set(payload.regions) - set(request.app.state.settings.aws_allowed_regions))
    if unsupported:
        raise ForbiddenError(
            "One or more regions are not enabled for CloudPatrol.",
            details={"unsupported_regions": unsupported},
        )

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
    """Re-assume the stored role and confirm the connection still works.

    This performs a real ``sts:AssumeRole`` followed by ``GetCallerIdentity``
    against the customer's account. It proves three things at once: the trust
    policy still lists CloudPatrol, the external ID still matches, and the role
    still resolves to the account that was originally connected.

    The external ID is read from the vault using the account's opaque
    reference. It is never returned, logged, or written to the account row.

    Temporary credentials are used immediately and discarded. The expiry is
    reported so the caller can see that the session was short-lived, and the
    stored connection status is updated to reflect the outcome — a connection
    that no longer validates must not keep claiming to be ``validated``.
    """
    principal, membership = context

    if not membership.can_manage_accounts:
        raise ForbiddenError("Only an owner or admin can validate an AWS account.")

    container = request.app.state.container
    record = container.aws_accounts.get(membership.organization_id, account_pk)
    if record is None:
        raise NotFoundError("AWS account not found.")

    reference = record.external_id_ref
    if not reference:
        raise ConflictError(
            "This AWS account has no stored external ID. Reconnect the account to store it."
        )
    external_id = request.app.state.secret_vault.get(reference)
    if not external_id:
        raise ConflictError(
            "The stored external ID for this account is unavailable. Reconnect the account."
        )

    connection_service = request.app.state.aws_connection_service
    try:
        _credentials, caller_arn, expires_at = connection_service.revalidate_connection(
            organization_id=membership.organization_id,
            account_id=record.account_id,
            role_arn=record.role_arn,
            external_id=external_id,
            region=record.regions[0],
        )
    except AppError as exc:
        # A failed re-validation is a real state change, not just an error
        # response: the connection is no longer working, so the row must stop
        # advertising that it is validated. The reason is a safe message; the
        # underlying AWS text stays in the logs.
        container.aws_accounts.update(
            account_pk,
            status="failed",
            status_message=exc.message,
        )
        container.audit.record(
            organization_id=membership.organization_id,
            actor_user_id=principal.user_id,
            action="aws_account.validation_failed",
            target_type="aws_account",
            target_id=account_pk,
            metadata={"code": str(exc.code)},
        )
        logger.warning(
            "AWS account re-validation failed",
            extra={"org_id": membership.organization_id, "code": str(exc.code)},
        )
        raise

    updated = container.aws_accounts.update(
        account_pk,
        status="validated",
        status_message=None,
        last_validated_at=utc_now(),
    )
    container.audit.record(
        organization_id=membership.organization_id,
        actor_user_id=principal.user_id,
        action="aws_account.validated",
        target_type="aws_account",
        target_id=account_pk,
        metadata={"account_id": record.account_id},
    )

    return AwsConnectionValidation(
        account_id=updated.account_id,
        status=updated.status,
        message="The role was assumed and the identity matches the connected account.",
        caller_identity_arn=caller_arn,
        assumed_role_arn=updated.role_arn,
        credentials_expire_at=expires_at,
    )
