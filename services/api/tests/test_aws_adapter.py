"""Tests for the AWS adapter boundary: error translation and retry behaviour."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from botocore.exceptions import ClientError, ConnectTimeoutError

from app.aws.adapter import (
    AwsCallError,
    AwsCredentials,
    translate_client_error,
    translate_transport_error,
)
from app.aws.boto3_adapter import Boto3AwsAdapter
from app.core.config import Settings
from app.core.errors import ErrorCode
from app.services.aws_connection import is_credential_expired


def client_error(code: str, status: int = 400) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": "internal detail that must not leak"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        "DescribeVolumes",
    )


@pytest.mark.parametrize(
    ("aws_code", "expected"),
    [
        ("AccessDenied", ErrorCode.AWS_PERMISSION_DENIED),
        ("UnauthorizedOperation", ErrorCode.AWS_PERMISSION_DENIED),
        ("Throttling", ErrorCode.AWS_THROTTLED),
        ("RequestLimitExceeded", ErrorCode.AWS_THROTTLED),
        ("ExpiredToken", ErrorCode.AWS_ASSUME_ROLE_FAILED),
        ("ValidationError", ErrorCode.VALIDATION_ERROR),
        ("SomethingElse", ErrorCode.UPSTREAM_ERROR),
    ],
)
def test_client_error_translation(aws_code: str, expected: ErrorCode) -> None:
    translated = translate_client_error(client_error(aws_code), service="ec2")
    assert translated.code == expected


def test_permission_error_maps_to_403() -> None:
    translated = translate_client_error(client_error("AccessDenied"), service="ec2")
    assert translated.status_code == 403


def test_throttle_maps_to_429() -> None:
    translated = translate_client_error(client_error("Throttling"), service="ec2")
    assert translated.status_code == 429


def test_aws_error_message_is_not_forwarded_to_client() -> None:
    """AWS error text can contain account IDs and resource names."""
    translated = translate_client_error(client_error("AccessDenied"), service="ec2")
    assert "internal detail that must not leak" not in translated.message
    payload = translated.to_payload()
    assert "internal detail that must not leak" not in str(payload)


def test_timeout_translation() -> None:
    translated = translate_transport_error(
        ConnectTimeoutError(endpoint_url="https://x"), service="ec2"
    )
    assert translated.code == ErrorCode.AWS_TIMEOUT
    assert translated.status_code == 504


def test_credentials_expiry_detection() -> None:
    expired = AwsCredentials(
        access_key_id="a",
        secret_access_key="b",
        session_token="c",
        expiration=datetime.now(UTC) - timedelta(minutes=1),
    )
    valid = AwsCredentials(
        access_key_id="a",
        secret_access_key="b",
        session_token="c",
        expiration=datetime.now(UTC) + timedelta(minutes=30),
    )
    assert is_credential_expired(expired) is True
    assert is_credential_expired(valid) is False


def test_credentials_without_expiry_are_not_treated_as_expired() -> None:
    credentials = AwsCredentials(access_key_id="a", secret_access_key="b", session_token="c")
    assert is_credential_expired(credentials) is False


def test_adapter_configures_explicit_timeouts() -> None:
    settings = Settings(
        app_env="test",
        aws_connect_timeout_seconds=3.0,
        aws_read_timeout_seconds=11.0,
    )
    adapter = Boto3AwsAdapter(settings)
    config = adapter._client_config  # noqa: SLF001 - verifying the wiring is the point
    assert config.connect_timeout == 3.0
    assert config.read_timeout == 11.0
    # Retries are handled explicitly, so botocore's own retry loop is disabled
    # to avoid multiplying attempts invisibly.
    assert config.retries["max_attempts"] == 1


def test_adapter_retries_throttling_then_succeeds() -> None:
    """Throttling must be retried with backoff, not surfaced immediately."""
    settings = Settings(app_env="test", aws_max_retry_attempts=4)
    slept: list[float] = []
    adapter = Boto3AwsAdapter(settings, sleep=slept.append)

    attempts = {"count": 0}

    def flaky() -> str:
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise client_error("Throttling", status=429)
        return "ok"

    assert adapter._call("ec2", "DescribeVolumes", flaky) == "ok"  # noqa: SLF001
    assert attempts["count"] == 3
    assert len(slept) == 2


def test_adapter_gives_up_after_max_attempts() -> None:
    settings = Settings(app_env="test", aws_max_retry_attempts=3)
    slept: list[float] = []
    adapter = Boto3AwsAdapter(settings, sleep=slept.append)

    attempts = {"count": 0}

    def always_throttled() -> str:
        attempts["count"] += 1
        raise client_error("Throttling", status=429)

    with pytest.raises(AwsCallError) as excinfo:
        adapter._call("ec2", "DescribeVolumes", always_throttled)  # noqa: SLF001

    assert attempts["count"] == 3
    assert excinfo.value.code == ErrorCode.AWS_THROTTLED


def test_adapter_does_not_retry_permission_errors() -> None:
    """A permission error is deterministic; retrying it only wastes time."""
    settings = Settings(app_env="test", aws_max_retry_attempts=4)
    slept: list[float] = []
    adapter = Boto3AwsAdapter(settings, sleep=slept.append)

    attempts = {"count": 0}

    def denied() -> str:
        attempts["count"] += 1
        raise client_error("AccessDenied", status=403)

    with pytest.raises(AwsCallError) as excinfo:
        adapter._call("ec2", "DescribeVolumes", denied)  # noqa: SLF001

    assert excinfo.value.code == ErrorCode.AWS_PERMISSION_DENIED
    assert attempts["count"] == 1
    assert slept == []


def test_backoff_is_capped_and_jittered() -> None:
    settings = Settings(app_env="test")
    slept: list[float] = []
    adapter = Boto3AwsAdapter(settings, sleep=slept.append)
    for attempt in range(1, 7):
        adapter._backoff(attempt)  # noqa: SLF001
    assert len(slept) == 6
    # Base delay caps at 8s, plus at most 0.5s jitter.
    assert all(delay <= 8.5 for delay in slept)
    assert all(delay > 0 for delay in slept)
