"""boto3-backed implementation of the AWS adapter.

The concrete adapter is the only place that touches the AWS SDK. It applies
explicit timeouts, bounded retries with exponential backoff, and pagination on
every list operation.

A customer account may hold thousands of volumes or addresses, so every list
call paginates. Unpaginated calls are both incomplete and prone to throttling.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any, TypeVar

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.aws.adapter import (
    AwsCredentials,
    CallerIdentity,
    translate_assume_role_error,
    translate_client_error,
    translate_transport_error,
)
from app.core.config import Settings

logger = logging.getLogger(__name__)

T = TypeVar("T")

_RETRYABLE_CODES = frozenset(
    {"Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException"}
)


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code", ""))
        return code in _RETRYABLE_CODES
    return isinstance(exc, BotoCoreError)


class Boto3AwsAdapter:
    """Concrete AWS adapter. Read-only operations only."""

    def __init__(self, settings: Settings, *, sleep: Callable[[float], None] = time.sleep) -> None:
        self._settings = settings
        # ``sleep`` is injectable so tests exercise the retry loop instantly.
        self._sleep = sleep
        self._client_config = Config(
            connect_timeout=settings.aws_connect_timeout_seconds,
            read_timeout=settings.aws_read_timeout_seconds,
            # Retries are handled explicitly below so behaviour is observable
            # and testable rather than hidden inside botocore.
            retries={"max_attempts": 1, "mode": "standard"},
        )

    # -- internal helpers -------------------------------------------------

    def _client(
        self,
        service: str,
        *,
        region: str,
        credentials: AwsCredentials | None = None,
    ) -> Any:
        kwargs: dict[str, Any] = {
            "region_name": region,
            "config": self._client_config,
        }
        if credentials is not None:
            kwargs["aws_access_key_id"] = credentials.access_key_id
            kwargs["aws_secret_access_key"] = credentials.secret_access_key
            kwargs["aws_session_token"] = credentials.session_token
        # The service name is dynamic by design: this helper builds a client
        # for whichever service the caller names. boto3-stubs types the
        # parameter as a Literal per service, so the dynamic call cannot be
        # statically narrowed.
        return boto3.client(service, **kwargs)  # type: ignore[call-overload]

    def _call(self, service: str, operation: str, func: Callable[[], T]) -> T:
        """Run an AWS call with bounded retries and error translation.

        On exhaustion the original failure is raised as a typed application
        error. It is never swallowed into an empty result.
        """
        attempts = max(1, self._settings.aws_max_retry_attempts)
        last_exc: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                return func()
            except ClientError as exc:
                last_exc = exc
                if attempt < attempts and _is_retryable(exc):
                    self._backoff(attempt)
                    continue
                raise translate_client_error(exc, service=service) from exc
            except (BotoCoreError, OSError) as exc:
                last_exc = exc
                if attempt < attempts and _is_retryable(exc):
                    self._backoff(attempt)
                    continue
                raise translate_transport_error(exc, service=service) from exc

        # Unreachable: the loop either returns or raises.
        raise translate_transport_error(last_exc or RuntimeError("unknown"), service=service)

    def _call_assume_role(self, func: Callable[[], T]) -> T:
        """Run sts:AssumeRole with retries and AssumeRole-specific translation.

        Separate from :meth:`_call` because an ``AccessDenied`` here means
        something different from an ``AccessDenied`` on a read: it is a trust
        policy or external ID problem, and the customer needs to be told which.
        """
        attempts = max(1, self._settings.aws_max_retry_attempts)

        for attempt in range(1, attempts + 1):
            try:
                return func()
            except ClientError as exc:
                if attempt < attempts and _is_retryable(exc):
                    self._backoff(attempt)
                    continue
                raise translate_assume_role_error(exc) from exc
            except (BotoCoreError, OSError) as exc:
                if attempt < attempts and _is_retryable(exc):
                    self._backoff(attempt)
                    continue
                raise translate_transport_error(exc, service="sts") from exc

        raise translate_transport_error(RuntimeError("unknown"), service="sts")

    def _backoff(self, attempt: int) -> None:
        """Exponential backoff with jitter, capped.

        Jitter spreads retries from concurrent scans so they do not all
        retry in lockstep and re-trigger throttling. Randomness here is
        scheduling, not security, so a pseudo-random source is correct.
        """
        delay = min(2 ** (attempt - 1), 8) + random.uniform(0, 0.5)  # noqa: S311
        logger.warning("Retrying AWS call", extra={"attempt": attempt, "delay_s": round(delay, 2)})
        self._sleep(delay)

    def _paginate(
        self,
        client: Any,
        operation: str,
        result_key: str,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Collect every page of a paginated AWS operation."""
        paginator = client.get_paginator(operation)
        collected: list[dict[str, Any]] = []
        for page in paginator.paginate(**kwargs):
            collected.extend(page.get(result_key, []) or [])
        return collected

    # -- adapter interface ------------------------------------------------

    def assume_role(
        self,
        *,
        role_arn: str,
        external_id: str,
        region: str,
        session_name: str,
    ) -> AwsCredentials:
        client = self._client("sts", region=region)

        def _assume() -> Any:
            return client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                ExternalId=external_id,
                DurationSeconds=3600,
            )

        response = self._call_assume_role(_assume)
        creds = response["Credentials"]
        return AwsCredentials(
            access_key_id=creds["AccessKeyId"],
            secret_access_key=creds["SecretAccessKey"],
            session_token=creds["SessionToken"],
            expiration=creds.get("Expiration"),
        )

    def get_caller_identity(self, credentials: AwsCredentials) -> CallerIdentity:
        client = self._client(
            "sts", region=self._settings.aws_default_region, credentials=credentials
        )
        response = self._call("sts", "GetCallerIdentity", client.get_caller_identity)
        return CallerIdentity(
            account_id=str(response["Account"]),
            arn=str(response["Arn"]),
            user_id=str(response["UserId"]),
        )

    def describe_volumes(self, credentials: AwsCredentials, *, region: str) -> list[dict[str, Any]]:
        client = self._client("ec2", region=region, credentials=credentials)
        return self._call(
            "ec2",
            "DescribeVolumes",
            lambda: self._paginate(client, "describe_volumes", "Volumes"),
        )

    def describe_addresses(
        self, credentials: AwsCredentials, *, region: str
    ) -> list[dict[str, Any]]:
        client = self._client("ec2", region=region, credentials=credentials)
        return self._call(
            "ec2",
            "DescribeAddresses",
            lambda: self._paginate(client, "describe_addresses", "Addresses"),
        )

    def describe_instances(
        self, credentials: AwsCredentials, *, region: str
    ) -> list[dict[str, Any]]:
        client = self._client("ec2", region=region, credentials=credentials)

        def _describe() -> list[dict[str, Any]]:
            reservations = self._paginate(client, "describe_instances", "Reservations")
            return [
                instance
                for reservation in reservations
                for instance in reservation.get("Instances", [])
            ]

        return self._call("ec2", "DescribeInstances", _describe)

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
    ) -> list[dict[str, Any]]:
        client = self._client("cloudwatch", region=region, credentials=credentials)

        def _get() -> Any:
            return client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start_time,
                EndTime=end_time,
                Period=period_seconds,
                Statistics=statistics,
            )

        response = self._call("cloudwatch", "GetMetricStatistics", _get)
        return list(response.get("Datapoints", []) or [])

    def get_cost_and_usage(
        self,
        credentials: AwsCredentials,
        *,
        start_date: str,
        end_date: str,
    ) -> list[dict[str, Any]]:
        """Fetch monthly cost grouped by service, following pagination.

        ``GroupBy`` is required, not optional. Without it Cost Explorer returns
        a single ``Total`` and no ``Groups``, so the caller can never attribute
        spend to a service — which is the whole point of the call.

        The response is paginated: an account with many services returns a
        ``NextPageToken``. Reading only the first page would silently understate
        the bill, so every page is collected.
        """
        # Cost Explorer is a global service reached through us-east-1.
        client = self._client("ce", region="us-east-1", credentials=credentials)

        def _get() -> list[dict[str, Any]]:
            results: list[dict[str, Any]] = []
            token: str | None = None
            while True:
                kwargs: dict[str, Any] = {
                    "TimePeriod": {"Start": start_date, "End": end_date},
                    "Granularity": "MONTHLY",
                    "Metrics": ["UnblendedCost"],
                    "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
                }
                if token:
                    kwargs["NextPageToken"] = token
                response = client.get_cost_and_usage(**kwargs)
                results.extend(response.get("ResultsByTime", []) or [])
                token = response.get("NextPageToken")
                if not token:
                    return results

        return self._call("ce", "GetCostAndUsage", _get)


def build_adapter(settings: Settings) -> Boto3AwsAdapter:
    return Boto3AwsAdapter(settings)
