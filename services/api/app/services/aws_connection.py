"""AWS connection validation.

Validating a connection means proving three things, in order:

1. The role can actually be assumed with the supplied external ID.
2. The temporary credentials resolve to the account the user claimed. This
   catches a role ARN and account ID that disagree — a common misconfiguration
   that would otherwise cause every later scan to read the wrong account.
3. The credentials are still valid for the identity call.

Nothing here writes to AWS, and no credential is ever logged or persisted. The
session name is derived from the organization and account so an action in the
customer's CloudTrail can be traced back to CloudPatrol.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from app.aws.adapter import AwsAdapter, AwsCredentials
from app.core.errors import AppError, ErrorCode
from app.repositories.models import AwsAccountRecord, new_id, utc_now

logger = logging.getLogger(__name__)


class AccountMismatchError(AppError):
    """The assumed role resolves to a different account than was supplied.

    Treated as a client error because it is a configuration mistake on the
    customer side, and catching it here prevents every later scan from reading
    the wrong account.
    """

    status_code = 400
    code = ErrorCode.AWS_ACCOUNT_MISMATCH
    message = (
        "The role belongs to a different account than the one supplied. "
        "Check that the role ARN and the account ID refer to the same account."
    )

    def __init__(self, *, expected_account_id: str, resolved_account_id: str) -> None:
        super().__init__(
            details={
                "expected_account_id": expected_account_id,
                "resolved_account_id": resolved_account_id,
            }
        )


class AwsConnectionService:
    """Validates AWS role assumptions without persisting credentials."""

    def __init__(self, adapter: AwsAdapter) -> None:
        self._adapter = adapter

    def _session_name(self, organization_id: str, account_id: str) -> str:
        # STS allows alphanumerics and a limited punctuation set. Truncated so
        # the name stays well inside the 64-character limit.
        return f"cloudpatrol-{organization_id[:8]}-{account_id}"[:64]

    def validate_connection(
        self,
        *,
        organization_id: str,
        account_id: str,
        role_arn: str,
        external_id: str,
        region: str,
    ) -> tuple[AwsCredentials, str, datetime | None]:
        """Assume the role and confirm the resulting identity.

        Returns the temporary credentials, the resolved caller ARN, and the
        credential expiry. Raises a typed :class:`AppError` on any failure.

        Credentials are returned to the caller for immediate use and are never
        written to a store or a log line.
        """
        credentials = self._adapter.assume_role(
            role_arn=role_arn,
            external_id=external_id,
            region=region,
            session_name=self._session_name(organization_id, account_id),
        )

        identity = self._adapter.get_caller_identity(credentials)

        if identity.account_id != account_id:
            raise AccountMismatchError(
                expected_account_id=account_id,
                resolved_account_id=identity.account_id,
            )

        return credentials, identity.arn, credentials.expiration

    def revalidate_connection(
        self,
        *,
        organization_id: str,
        account_id: str,
        role_arn: str,
        external_id: str,
        region: str,
    ) -> tuple[AwsCredentials, str, datetime | None]:
        """Re-assume a stored connection and confirm the identity still matches.

        Same checks as :meth:`validate_connection`; kept as a named method
        because the caller's intent differs — this one re-tests an existing
        connection rather than vetting a new one, and the audit trail should
        record that distinction.
        """
        return self.validate_connection(
            organization_id=organization_id,
            account_id=account_id,
            role_arn=role_arn,
            external_id=external_id,
            region=region,
        )

    def build_account_record(
        self,
        *,
        organization_id: str,
        created_by: str,
        label: str,
        account_id: str,
        role_arn: str,
        regions: list[str],
        status: str,
        status_message: str | None,
        validated_at: datetime | None,
    ) -> AwsAccountRecord:
        """Build the non-secret connection metadata row.

        Note the absence of any credential argument: there is no code path in
        which an access key could reach this record.
        """
        return AwsAccountRecord(
            id=new_id(),
            organization_id=organization_id,
            label=label,
            account_id=account_id,
            role_arn=role_arn,
            regions=regions,
            status=status,
            status_message=status_message,
            last_validated_at=validated_at or utc_now(),
            created_at=utc_now(),
            created_by=created_by,
        )


def is_credential_expired(credentials: AwsCredentials, *, now: datetime | None = None) -> bool:
    """Whether temporary credentials have expired."""
    return credentials.is_expired(now=now or datetime.now(UTC))
