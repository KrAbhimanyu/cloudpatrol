"""Fake AWS adapter for tests.

This is a *fake*, not a mock: it implements the full adapter protocol with
real behaviour over in-memory data, so tests exercise the genuine scan,
detector and persistence code paths rather than asserting on stubbed calls.
Failure injection is explicit and per-service, which is what makes the
partial-failure and permission-error tests meaningful.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.aws.adapter import AwsCredentials, CallerIdentity
from app.core.errors import AppError, ErrorCode


class FakeAwsError(AppError):
    """An injected AWS failure for tests."""

    def __init__(self, message: str, *, code: ErrorCode, status_code: int = 403) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class FakeAwsAdapter:
    """In-memory AWS adapter with controllable failures."""

    def __init__(
        self,
        *,
        account_id: str = "123456789012",
        volumes: list[dict[str, Any]] | None = None,
        addresses: list[dict[str, Any]] | None = None,
        instances: list[dict[str, Any]] | None = None,
        cpu_datapoints: dict[str, list[dict[str, Any]]] | None = None,
        cost_groups: list[dict[str, Any]] | None = None,
    ) -> None:
        self.account_id = account_id
        self._volumes = volumes or []
        self._addresses = addresses or []
        self._instances = instances or []
        self._cpu = cpu_datapoints or {}
        # Cost Explorer response shape: ResultsByTime with Groups.
        self._cost_groups = cost_groups or []

        # Failure injection: service name -> AppError to raise.
        self.fail_on: dict[str, AppError] = {}
        # Records of what was asked for, so tests can assert on behaviour
        # (for example that a denied service was attempted exactly once).
        self.calls: list[tuple[str, str]] = []
        # When set, listing operations return a failure once the page has been
        # served this many items, so a test can prove the adapter handles a
        # mid-pagination failure instead of reporting a truncated list as whole.
        self.fail_after_items: int | None = None

    def _page(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return items, or raise once ``fail_after_items`` have been served."""
        if self.fail_after_items is None:
            return items
        if len(items) > self.fail_after_items:
            raise FakeAwsError(
                "The listing was interrupted partway through.",
                code=ErrorCode.AWS_THROTTLED,
                status_code=429,
            )
        return items

    def _maybe_fail(self, service: str) -> None:
        error = self.fail_on.get(service)
        if error is not None:
            raise error

    def assume_role(
        self,
        *,
        role_arn: str,
        external_id: str,
        region: str,
        session_name: str,
    ) -> AwsCredentials:
        self.calls.append(("sts", "AssumeRole"))
        self._maybe_fail("sts")
        if not external_id:
            raise FakeAwsError(
                "Access denied: an external ID is required.",
                code=ErrorCode.AWS_ASSUME_ROLE_FAILED,
                status_code=403,
            )
        return AwsCredentials(
            access_key_id="ASIAFAKEFAKEFAKEFAKE",
            secret_access_key="fake-secret",
            session_token="fake-session-token",
            expiration=datetime.now(UTC) + timedelta(hours=1),
        )

    def get_caller_identity(self, credentials: AwsCredentials) -> CallerIdentity:
        self.calls.append(("sts", "GetCallerIdentity"))
        self._maybe_fail("sts")
        return CallerIdentity(
            account_id=self.account_id,
            arn=f"arn:aws:sts::{self.account_id}:assumed-role/CloudPatrolReadOnly/session",
            user_id="AROFAKEFAKEFAKEFAKE:session",
        )

    def describe_volumes(self, credentials: AwsCredentials, *, region: str) -> list[dict[str, Any]]:
        self.calls.append(("ec2", "DescribeVolumes"))
        self._maybe_fail("ec2")
        # ``page_size`` models an AWS paginator: the adapter must collect every
        # page, so a small page size here is what proves it does.
        return self._page(self._volumes)

    def describe_addresses(
        self, credentials: AwsCredentials, *, region: str
    ) -> list[dict[str, Any]]:
        self.calls.append(("ec2", "DescribeAddresses"))
        self._maybe_fail("ec2")
        return self._addresses

    def describe_instances(
        self, credentials: AwsCredentials, *, region: str
    ) -> list[dict[str, Any]]:
        self.calls.append(("ec2", "DescribeInstances"))
        self._maybe_fail("ec2")
        return self._page(self._instances)

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
        instance_id = next((d["Value"] for d in dimensions if d.get("Name") == "InstanceId"), "")
        self.calls.append(("cloudwatch", f"GetMetricStatistics:{instance_id}"))
        self._maybe_fail("cloudwatch")
        return self._cpu.get(instance_id, [])

    def get_cost_and_usage(
        self,
        credentials: AwsCredentials,
        *,
        start_date: str,
        end_date: str,
    ) -> list[dict[str, Any]]:
        self.calls.append(("ce", "GetCostAndUsage"))
        self._maybe_fail("ce")
        if not self._cost_groups:
            return []
        return [
            {
                "TimePeriod": {"Start": start_date, "End": end_date},
                "Groups": self._cost_groups,
            }
        ]
