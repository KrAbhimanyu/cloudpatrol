"""Tests for ingestion robustness, savings deduplication and worker reliability.

All AWS interaction is served by the in-memory fake. No network call is made.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from app.core.errors import ConflictError, ErrorCode
from app.repositories.memory import build_container
from app.repositories.models import new_id, utc_now
from app.services.billing import BillingService
from app.services.detectors import build_detectors
from app.services.savings_ledger import BASIS_POTENTIAL, SavingsLedgerService
from app.services.scan_runner import ScanExecutor, ScanJob, ScanWorkerPool
from app.services.scan_service import ScanService
from app.services.secrets import InMemorySecretVault
from tests.fake_aws import FakeAwsAdapter, FakeAwsError

ACCOUNT_ID = "123456789012"
ROLE_ARN = "arn:aws:iam::123456789012:role/CloudPatrolReadOnly"


# --- fixtures -----------------------------------------------------------


def _volume(volume_id: str, size: int = 100) -> dict:  # type: ignore[type-arg]
    return {
        "VolumeId": volume_id,
        "State": "available",
        "Size": size,
        "VolumeType": "gp3",
        "AvailabilityZone": "us-east-1a",
        "CreateTime": datetime.now(UTC) - timedelta(days=60),
        "Tags": [],
    }


def _address(allocation_id: str) -> dict:  # type: ignore[type-arg]
    return {"AllocationId": allocation_id, "PublicIp": "203.0.113.10", "Domain": "vpc"}


@pytest.fixture
def wired():  # type: ignore[no-untyped-def]
    """A ScanService over a fresh container and a controllable fake adapter."""
    container = build_container()
    adapter = FakeAwsAdapter()
    ledger = SavingsLedgerService(
        savings=container.savings,
        findings=container.findings,
        audit=container.audit,
    )
    service = ScanService(
        adapter=adapter,
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=build_detectors(),
        savings_ledger=ledger,
        costs=container.costs,
        billing=BillingService(adapter),
    )
    return container, adapter, service, ledger


def _run(container, service, *, regions=("us-east-1",), account_pk="acct-1"):  # type: ignore[no-untyped-def]
    from app.aws.adapter import AwsCredentials

    scan = container.scans.create(
        organization_id="org-1",
        aws_account_id=account_pk,
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by="user-1",
    )
    credentials = AwsCredentials(
        access_key_id="ASIAX",
        secret_access_key="s",
        session_token="t",
        expiration=datetime.now(UTC) + timedelta(hours=1),
    )
    return service.run_scan(
        organization_id="org-1",
        aws_account_id=account_pk,
        account_id=ACCOUNT_ID,
        regions=list(regions),
        credentials=credentials,
        created_by="user-1",
        scan_id=scan.id,
    )


# --- pagination and partial collection ----------------------------------


def test_a_mid_pagination_failure_marks_the_scan_partial(wired) -> None:
    """A truncated listing must not be reported as a complete one.

    Something must still be collected, or the scan is ``failed`` rather than
    ``partial`` — so the address listing succeeds while the volume listing is
    interrupted.
    """
    container, adapter, service, _ledger = wired
    adapter._volumes = [_volume(f"vol-{i}") for i in range(5)]
    adapter._addresses = [_address("eipalloc-1")]
    adapter.fail_after_items = 2

    record = _run(container, service)

    assert record.status == "partial"
    assert any(f["service"] == "ec2" for f in record.partial_failures)
    # The throttle is recorded with its real code, not a generic error.
    assert any(f["code"] == str(ErrorCode.AWS_THROTTLED) for f in record.partial_failures)


def test_a_fully_failed_region_with_nothing_collected_is_failed(wired) -> None:
    """When every listing fails and nothing was collected, it is not partial."""
    container, adapter, service, _ledger = wired
    adapter._volumes = [_volume(f"vol-{i}") for i in range(5)]
    adapter.fail_after_items = 2

    record = _run(container, service)

    assert record.status == "failed"
    assert record.resource_count == 0


def test_every_region_is_attempted_even_when_one_fails(wired) -> None:
    container, adapter, service, _ledger = wired
    adapter._volumes = [_volume("vol-1")]

    record = _run(container, service, regions=("us-east-1", "us-west-2", "eu-west-1"))

    # One EC2 DescribeVolumes per region: a failure in one does not skip others.
    assert adapter.calls.count(("ec2", "DescribeVolumes")) == 3
    assert record.resource_count >= 3


def test_no_resources_and_a_failure_is_a_failed_scan_not_an_empty_account(wired) -> None:
    container, adapter, service, _ledger = wired
    adapter.fail_on["ec2"] = FakeAwsError(
        "Access denied.", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )

    record = _run(container, service)

    assert record.status == "failed"
    assert record.error_message is not None


def test_a_cloudwatch_denial_keeps_the_instance_but_records_the_gap(wired) -> None:
    """The instance is still inventoried; only the metric evidence is missing."""
    container, adapter, service, _ledger = wired
    adapter._instances = [
        {"InstanceId": "i-1", "State": {"Name": "running"}, "InstanceType": "m5.large"}
    ]
    adapter.fail_on["cloudwatch"] = FakeAwsError(
        "Access denied.", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )

    record = _run(container, service)

    assert record.status == "partial"
    assert any(f["service"] == "cloudwatch" for f in record.partial_failures)
    # The instance was collected, but no low-utilisation finding was invented.
    assert record.resource_count >= 1
    assert record.finding_count == 0


def test_a_cloudwatch_denial_is_recorded_once_per_region_not_per_instance(wired) -> None:
    """300 instances must not produce 300 identical failure entries."""
    container, adapter, service, _ledger = wired
    adapter._instances = [
        {"InstanceId": f"i-{i}", "State": {"Name": "running"}, "InstanceType": "m5.large"}
        for i in range(50)
    ]
    adapter.fail_on["cloudwatch"] = FakeAwsError(
        "Access denied.", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )

    record = _run(container, service)

    cloudwatch_failures = [f for f in record.partial_failures if f["service"] == "cloudwatch"]
    assert len(cloudwatch_failures) == 1
    assert cloudwatch_failures[0]["occurrences"] == 50


# --- billing ------------------------------------------------------------


def test_a_cost_explorer_denial_does_not_fail_the_scan(wired) -> None:
    """Resource discovery and cost data are separately permissioned."""
    container, adapter, service, _ledger = wired
    adapter._volumes = [_volume("vol-1")]
    adapter.fail_on["ce"] = FakeAwsError(
        "Access denied.", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )

    record = _run(container, service)

    assert record.status == "partial"
    assert any(f["service"] == "ce" for f in record.partial_failures)
    # Cost is absent, never zero.
    assert container.costs.list_for_org("org-1") == []


def test_reported_cost_is_stored_separately_from_findings(wired) -> None:
    container, adapter, service, ledger = wired
    adapter._cost_groups = [
        {
            "Keys": ["Amazon Elastic Compute Cloud - Compute"],
            "Metrics": {"UnblendedCost": {"Amount": "42.50", "Unit": "USD"}},
        }
    ]

    record = _run(container, service)

    costs = container.costs.list_for_org("org-1")
    assert len(costs) == 1
    assert costs[0].amount == Decimal("42.50")
    # Reported spend is not a saving: the ledger stays empty.
    assert ledger.summary("org-1").potential_monthly_savings == Decimal("0.00")
    assert record.status == "completed"


def test_a_rescan_does_not_duplicate_a_reported_cost(wired) -> None:
    container, adapter, service, _ledger = wired
    adapter._cost_groups = [
        {
            "Keys": ["Amazon S3"],
            "Metrics": {"UnblendedCost": {"Amount": "5.00", "Unit": "USD"}},
        }
    ]

    _run(container, service)
    _run(container, service)

    # The natural key is (account, scan, service, period), and the two scans
    # differ, so both rows are kept — but neither is doubled within a scan.
    rows = container.costs.list_for_org("org-1")
    assert len(rows) == 2
    assert {r.service for r in rows} == {"Amazon S3"}


# --- duplicate prevention -----------------------------------------------


def test_a_rescan_does_not_double_the_potential_savings(wired) -> None:
    """The central guarantee: re-observing a problem is not a second saving."""
    container, adapter, service, ledger = wired
    adapter._volumes = [_volume("vol-1", size=100)]

    first = _run(container, service)
    after_first = ledger.summary("org-1").potential_monthly_savings
    second = _run(container, service)
    after_second = ledger.summary("org-1").potential_monthly_savings

    assert first.finding_count == 1
    assert after_first > Decimal("0")
    # The finding was re-confirmed, not duplicated, and the ledger did not move.
    assert second.finding_count == 1
    assert after_second == after_first


def test_a_rescan_does_not_create_a_second_finding_row(wired) -> None:
    container, adapter, service, _ledger = wired
    adapter._volumes = [_volume("vol-1")]

    _run(container, service)
    _run(container, service)

    findings = container.findings.list_for_org("org-1")
    assert len(findings) == 1


def test_a_rescan_preserves_a_human_dismissal(wired) -> None:
    """A re-scan must not resurrect an opportunity the user rejected."""
    container, adapter, service, _ledger = wired
    adapter._volumes = [_volume("vol-1")]

    _run(container, service)
    finding = container.findings.list_for_org("org-1")[0]
    container.findings.update(finding.id, state="dismissed")

    _run(container, service)

    assert container.findings.list_for_org("org-1")[0].state == "dismissed"


def test_an_unpriced_finding_writes_no_ledger_entry(wired) -> None:
    """A null estimate must not become a zero-saving ledger row."""
    container, adapter, service, ledger = wired
    adapter._instances = [
        {"InstanceId": "i-1", "State": {"Name": "running"}, "InstanceType": "m5.large"}
    ]
    adapter._cpu = {"i-1": [{"Average": 1.0, "Maximum": 2.0} for _ in range(20)]}

    _run(container, service)

    findings = container.findings.list_for_org("org-1")
    assert len(findings) == 1
    assert findings[0].estimated_monthly_savings is None
    assert ledger.list_entries("org-1") == []


def test_tenant_isolation_findings_are_not_visible_across_organizations(wired) -> None:
    container, adapter, service, _ledger = wired
    adapter._volumes = [_volume("vol-1")]

    _run(container, service)

    assert len(container.findings.list_for_org("org-1")) == 1
    assert container.findings.list_for_org("org-2") == []
    assert container.costs.list_for_org("org-2") == []
    assert container.savings.list_for_org("org-2") == []


def test_the_same_resource_in_two_organizations_stays_separate(wired) -> None:
    """Findings are tenant-scoped even when the resource id is identical."""
    container, adapter, service, _ledger = wired
    adapter._volumes = [_volume("vol-shared")]

    _run(container, service, account_pk="acct-a")
    _run(container, service, account_pk="acct-b")

    # Two different connected accounts => two findings, neither org sees the
    # other's, and the counts do not merge.
    assert len(container.findings.list_for_org("org-1")) == 2
    assert container.findings.list_for_org("org-2") == []


# --- worker reliability -------------------------------------------------


def test_queue_reports_capacity_and_saturation() -> None:
    container = build_container()
    adapter = FakeAwsAdapter()
    service = ScanService(
        adapter=adapter,
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=[],
    )
    executor = ScanExecutor(
        connection=_StubConnection(),  # type: ignore[arg-type]
        vault=InMemorySecretVault(),
        accounts=container.aws_accounts,
        scans=container.scans,
        scan_service=service,
    )
    pool = ScanWorkerPool(
        executor=executor,
        worker_count=1,
        max_queue_size=2,
        poll_timeout_seconds=0.01,
        shutdown_grace_seconds=1.0,
    )
    # Not started: no worker drains the queue, so it fills exactly.
    assert pool.metrics()["queue_capacity"] == 2
    assert pool.metrics()["saturated"] is False

    pool.submit(ScanJob("s1", "org-1", "a1", "u1"))
    pool.submit(ScanJob("s2", "org-1", "a1", "u1"))

    metrics = pool.metrics()
    assert metrics["queue_depth"] == 2
    assert metrics["queue_available"] == 0
    assert metrics["saturated"] is True

    with pytest.raises(ConflictError):
        pool.submit(ScanJob("s3", "org-1", "a1", "u1"))


def test_submitting_after_shutdown_is_refused() -> None:
    container = build_container()
    adapter = FakeAwsAdapter()
    service = ScanService(
        adapter=adapter,
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=[],
    )
    executor = ScanExecutor(
        connection=_StubConnection(),  # type: ignore[arg-type]
        vault=InMemorySecretVault(),
        accounts=container.aws_accounts,
        scans=container.scans,
        scan_service=service,
    )
    pool = ScanWorkerPool(
        executor=executor,
        worker_count=1,
        max_queue_size=4,
        poll_timeout_seconds=0.01,
        shutdown_grace_seconds=1.0,
    )
    pool.start()
    pool.stop()

    assert pool.metrics()["accepting"] is False
    with pytest.raises(ConflictError):
        pool.submit(ScanJob("s1", "org-1", "a1", "u1"))


def test_a_worker_survives_a_job_that_raises() -> None:
    """One failing scan must not take the worker thread down with it."""
    container = build_container()
    adapter = FakeAwsAdapter()
    service = ScanService(
        adapter=adapter,
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=[],
    )
    executor = ScanExecutor(
        connection=_StubConnection(),  # type: ignore[arg-type]
        vault=InMemorySecretVault(),
        accounts=container.aws_accounts,
        scans=container.scans,
        scan_service=service,
    )
    pool = ScanWorkerPool(
        executor=executor,
        worker_count=1,
        max_queue_size=4,
        poll_timeout_seconds=0.01,
        shutdown_grace_seconds=1.0,
    )
    pool.start()
    try:
        # The account does not exist, so the executor fails the job cleanly.
        pool.submit(ScanJob(new_id(), "org-1", "missing-account", "u1"))
        _wait_until(lambda: pool.depth == 0)
        # The worker is still alive and accepting further work.
        assert pool.metrics()["accepting"] is True
        pool.submit(ScanJob(new_id(), "org-1", "missing-account", "u1"))
        _wait_until(lambda: pool.depth == 0)
    finally:
        pool.stop()


def test_stale_scan_recovery_releases_the_account() -> None:
    """A scan whose worker died must be failed so the account is usable again."""
    from app.services.scan_runner import StaleScanReaper

    container = build_container()
    adapter = FakeAwsAdapter()
    service = ScanService(
        adapter=adapter,
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=[],
    )
    executor = ScanExecutor(
        connection=_StubConnection(),  # type: ignore[arg-type]
        vault=InMemorySecretVault(),
        accounts=container.aws_accounts,
        scans=container.scans,
        scan_service=service,
    )
    reaper = StaleScanReaper(
        scans=container.scans,
        executor=executor,
        stale_after_seconds=60,
        interval_seconds=1.0,
    )

    scan = container.scans.create(
        organization_id="org-1",
        aws_account_id="acct-1",
        status="running",
        started_at=utc_now() - timedelta(minutes=10),
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by="user-1",
    )

    reaped = reaper.reap_once()

    assert reaped == [scan.id]
    assert container.scans.get("org-1", scan.id).status == "failed"
    # The account is no longer blocked by an active scan.
    assert container.scans.find_active_for_account("org-1", "acct-1") is None


def test_the_reaper_leaves_a_fresh_scan_alone() -> None:
    from app.services.scan_runner import StaleScanReaper

    container = build_container()
    adapter = FakeAwsAdapter()
    service = ScanService(
        adapter=adapter,
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=[],
    )
    executor = ScanExecutor(
        connection=_StubConnection(),  # type: ignore[arg-type]
        vault=InMemorySecretVault(),
        accounts=container.aws_accounts,
        scans=container.scans,
        scan_service=service,
    )
    reaper = StaleScanReaper(
        scans=container.scans,
        executor=executor,
        stale_after_seconds=1800,
        interval_seconds=1.0,
    )
    scan = container.scans.create(
        organization_id="org-1",
        aws_account_id="acct-1",
        status="running",
        started_at=utc_now(),
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by="user-1",
    )

    assert reaper.reap_once() == []
    assert container.scans.get("org-1", scan.id).status == "running"


def test_ledger_rejects_a_second_potential_entry_for_one_finding(wired) -> None:
    """record_potential is idempotent per finding."""
    container, adapter, service, ledger = wired
    adapter._volumes = [_volume("vol-1")]
    _run(container, service)

    finding = container.findings.list_for_org("org-1")[0]
    ledger.record_potential(organization_id="org-1", finding=finding, actor_user_id="user-1")
    ledger.record_potential(organization_id="org-1", finding=finding, actor_user_id="user-1")

    entries = ledger.list_entries("org-1", basis=BASIS_POTENTIAL)
    assert len(entries) == 1


def _wait_until(predicate, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition was not met within the timeout")


class _StubConnection:
    """A connection service that returns credentials without touching AWS."""

    def validate_connection(self, **_kwargs: object):  # type: ignore[no-untyped-def]
        from app.aws.adapter import AwsCredentials

        return (
            AwsCredentials(
                access_key_id="ASIAX",
                secret_access_key="s",
                session_token="t",
                expiration=datetime.now(UTC) + timedelta(hours=1),
            ),
            f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/CloudPatrolReadOnly/session",
            datetime.now(UTC) + timedelta(hours=1),
        )
