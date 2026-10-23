"""AWS adapter boundary: protocol, credential model and error translation.

Design rules enforced here:

* CloudPatrol never stores or accepts long-lived customer access keys. It
  assumes a customer-side role with an external ID and uses the temporary
  credentials STS returns.
* Every AWS failure is translated into a typed application error, so callers
  cannot mistake a failed call for an empty result. This is what prevents a
  permission error from being silently rendered as "no resources found".
* The adapter surface is a protocol, so tests substitute a fake without any
  live AWS access.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from app.core.errors import AppError, ErrorCode, UpstreamError


@dataclass(frozen=True, slots=True)
class AwsCredentials:
    """Temporary credentials from STS. Never persisted."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime | None = None

    def is_expired(self, *, now: datetime) -> bool:
        if self.expiration is None:
            return False
        return self.expiration <= now


@dataclass(frozen=True, slots=True)
class CallerIdentity:
    """Result of sts:GetCallerIdentity."""

    account_id: str
    arn: str
    user_id: str


@dataclass(frozen=True, slots=True)
class AssumedSession:
    """An assumed role session plus the identity it resolves to."""

    credentials: AwsCredentials
    identity: CallerIdentity
    assumed_role_arn: str
    region: str


class AwsCallError(AppError):
    """An AWS call failed in a way the caller must not treat as empty data.

    ``status_code`` and ``code`` are set per instance so one class covers the
    whole family of AWS failures without a subclass per error code.
    """

    def __init__(
        self,
        message: str,
        *,
        code: ErrorCode,
        status_code: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details=details)
        self.code = code
        self.status_code = status_code


_PERMISSION_CODES = frozenset(
    {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthFailure"}
)
_THROTTLE_CODES = frozenset(
    {"Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException"}
)
_EXPIRED_CODES = frozenset({"ExpiredToken", "ExpiredTokenException", "RequestExpired"})
_INVALID_PARAM_CODES = frozenset({"NoSuchEntity", "ValidationError"})


def translate_client_error(exc: ClientError, *, service: str) -> AppError:
    """Map a botocore ``ClientError`` onto a typed application error.

    The AWS error message is used only to classify the failure; it is not
    forwarded verbatim to the client, because error text can contain account
    identifiers and resource names.
    """
    error = exc.response.get("Error", {})
    aws_code = str(error.get("Code", "Unknown"))
    http_status = int(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 500))

    if aws_code in _PERMISSION_CODES:
        return AwsCallError(
            "AWS denied the request. Check that the read-only policy is attached to the role.",
            code=ErrorCode.AWS_PERMISSION_DENIED,
            status_code=403,
            details={"service": service, "aws_code": aws_code},
        )

    if aws_code in _THROTTLE_CODES:
        return AwsCallError(
            "AWS throttled the request. Retry later.",
            code=ErrorCode.AWS_THROTTLED,
            status_code=429,
            details={"service": service, "aws_code": aws_code},
        )

    if aws_code in _EXPIRED_CODES:
        return AwsCallError(
            "The temporary AWS credentials expired during the request.",
            code=ErrorCode.AWS_ASSUME_ROLE_FAILED,
            status_code=401,
            details={"service": service, "aws_code": aws_code},
        )

    if aws_code in _INVALID_PARAM_CODES:
        return AwsCallError(
            "AWS rejected the request parameters.",
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
            details={"service": service, "aws_code": aws_code},
        )

    return AwsCallError(
        "The AWS request failed.",
        code=ErrorCode.UPSTREAM_ERROR,
        status_code=502,
        details={"service": service, "aws_code": aws_code, "http_status": http_status},
    )


def translate_transport_error(exc: Exception, *, service: str) -> AppError:
    """Map a network-level botocore failure onto a typed application error."""
    if isinstance(exc, (ConnectTimeoutError, ReadTimeoutError, EndpointConnectionError)):
        return AwsCallError(
            "The AWS request timed out.",
            code=ErrorCode.AWS_TIMEOUT,
            status_code=504,
            details={"service": service},
        )
    return UpstreamError(
        "The AWS request failed unexpectedly.",
        details={"service": service},
    )


class AwsAdapter(Protocol):
    """The AWS operations CloudPatrol performs in this phase.

    Every method is read-only. There is deliberately no method that creates,
    modifies or deletes an AWS resource.
    """

    def assume_role(
        self,
        *,
        role_arn: str,
        external_id: str,
        region: str,
        session_name: str,
    ) -> AwsCredentials: ...

    def get_caller_identity(self, credentials: AwsCredentials) -> CallerIdentity: ...

    def describe_volumes(
        self, credentials: AwsCredentials, *, region: str
    ) -> list[dict[str, Any]]: ...

    def describe_addresses(
        self, credentials: AwsCredentials, *, region: str
    ) -> list[dict[str, Any]]: ...

    def describe_instances(
        self, credentials: AwsCredentials, *, region: str
    ) -> list[dict[str, Any]]: ...

    def get_metric_statistics(
        self,
        credentials: AwsCredentials,
        *,
        region: str,
        namespace: str,
        metric_name: str,
        dimensions: list[dict[str, str]],
        start_time: datetime,
        end_time: datetime,
        period_seconds: int,
        statistics: list[str],
    ) -> list[dict[str, Any]]: ...

    def get_cost_and_usage(
        self,
        credentials: AwsCredentials,
        *,
        start_date: str,
        end_date: str,
    ) -> list[dict[str, Any]]: ...
