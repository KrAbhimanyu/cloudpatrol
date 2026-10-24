"""Structured error types and a consistent error envelope.

Every API error returned to a client has the same shape, so the frontend can
render failures uniformly. Internal details (exception strings, AWS error
bodies) are never echoed to the client; they are logged server-side and
replaced with a stable code plus a safe message.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Stable, machine-readable error codes."""

    VALIDATION_ERROR = "validation_error"
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate_limited"
    AWS_ASSUME_ROLE_FAILED = "aws_assume_role_failed"
    AWS_PERMISSION_DENIED = "aws_permission_denied"
    # AssumeRole failures that need distinct advice. AWS reports a wrong
    # external ID, a missing trust relationship and a nonexistent role in ways
    # that a single "permission denied" code cannot separate, and the fix for
    # each is different.
    AWS_EXTERNAL_ID_INVALID = "aws_external_id_invalid"
    AWS_ROLE_NOT_FOUND = "aws_role_not_found"
    AWS_THROTTLED = "aws_throttled"
    AWS_TIMEOUT = "aws_timeout"
    AWS_ACCOUNT_MISMATCH = "aws_account_mismatch"
    UPSTREAM_ERROR = "upstream_error"
    OVERLOADED = "overloaded"
    INTERNAL_ERROR = "internal_error"


class AppError(Exception):
    """Base class for all handled application errors.

    Subclasses set ``status_code`` and ``code``; the message is safe to show
    to a client. ``details`` carries non-sensitive context (for example the
    offending field name).
    """

    status_code: int = 500
    code: ErrorCode = ErrorCode.INTERNAL_ERROR
    message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message or self.message)
        if message:
            self.message = message
        self.details = details or {}

    def to_payload(self, request_id: str | None = None) -> dict[str, Any]:
        """Render the error as the standard response envelope."""
        payload: dict[str, Any] = {
            "error": {
                "code": str(self.code),
                "message": self.message,
                "details": self.details,
            }
        }
        if request_id:
            payload["error"]["request_id"] = request_id
        return payload


class ValidationError(AppError):
    status_code = 422
    code = ErrorCode.VALIDATION_ERROR
    message = "The request payload is invalid."


class UnauthenticatedError(AppError):
    status_code = 401
    code = ErrorCode.UNAUTHENTICATED
    message = "Authentication is required."


class ForbiddenError(AppError):
    status_code = 403
    code = ErrorCode.FORBIDDEN
    message = "You do not have access to this resource."


class NotFoundError(AppError):
    status_code = 404
    code = ErrorCode.NOT_FOUND
    message = "The requested resource was not found."


class ConflictError(AppError):
    status_code = 409
    code = ErrorCode.CONFLICT
    message = "The request conflicts with the current state."


class RateLimitedError(AppError):
    status_code = 429
    code = ErrorCode.RATE_LIMITED
    message = "Too many requests. Please retry later."


class ServiceUnavailableError(AppError):
    """A dependency or capacity limit is temporarily unable to accept work.

    Distinct from :class:`RateLimitedError`: this is not the caller misbehaving,
    it is the service having no capacity. Retrying later is still the right
    advice, but the cause and the operational response differ.
    """

    status_code = 503
    code = ErrorCode.OVERLOADED
    message = "The service is temporarily unable to accept new work."


class UpstreamError(AppError):
    status_code = 502
    code = ErrorCode.UPSTREAM_ERROR
    message = "An upstream dependency returned an unexpected response."
