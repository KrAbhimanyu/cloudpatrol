"""Tests for asynchronous scan execution: queue, workers, reaper.

The behaviours that matter:

* A queued scan always reaches a terminal state, even when the role cannot be
  assumed or the vault has lost the external ID. A scan that never resolves
  would block its account from ever being scanned again.
* The queue is bounded, so a burst of requests is refused rather than growing
  memory without limit.
* The reaper releases accounts whose worker died, and does not touch a scan
  that is genuinely still running.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

from app.aws.adapter import AwsCredentials
from app.core.errors import ConflictError, ErrorCode
from app.repositories.memory import build_container
from app.services.detectors import build_detectors
from app.services.scan_runner import (
    ScanExecutor,
    ScanJob,
    ScanWorkerPool,
    StaleScanReaper,
)
from app.services.scan_service import ScanService
from app.services.secrets import InMemorySecretVault
from tests.fake_aws import FakeAwsAdapter, FakeAwsError

ACCOUNT_ID = "123456789012"
ORG = "org-1"


def unattached_volume(volume_id: str = "vol-1") -> dict:
    return {
        "VolumeId": volume_id,
        "State": "available",
        "Size": 100,
        "VolumeType": "gp3",
        "AvailabilityZone": "us-east-1a",
        "CreateTime": datetime.now(UTC),
        "Tags": [],
    }


class StubConnection:
    """Stands in for AwsConnectionService.

    Returns credentials, or raises whatever ``error`` is set to, so the
    executor's failure handling is exercised without an AWS call.
    """

    def __init__(self) -> None:
        self.error: Exception | None = None
        self.calls = 0

    def validate_connection(self, **kwargs):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.error is not None:
            raise self.error
        return (
            AwsCredentials(
                access_key_id="a",
                secret_access_key="b",
                session_token="c",
                expiration=datetime.now(UTC) + timedelta(hours=1),
            ),
            "arn:aws:sts::123456789012:assumed-role/CloudPatrolReadOnly/session",
            None,
        )


def build(adapter=None):  # type: ignore[no-untyped-def]
    """Wire a container, executor and the collaborating stubs."""
    adapter = adapter or FakeAwsAdapter()
    container = build_container()
    scan_service = ScanService(
        adapter=adapter,
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=build_detectors(),
    )
    vault = InMemorySecretVault()
    connection = StubConnection()
    executor = ScanExecutor(
        connection=connection,  # type: ignore[arg-type]
        vault=vault,
        accounts=container.aws_accounts,
        scans=container.scans,
        scan_service=scan_service,
    )
    return container, executor, vault, connection, adapter


def connect_account(container, vault, *, with_external_id: bool = True) -> str:
    reference = "aws-account/ref/external-id" if with_external_id else None
    if reference:
        vault.put(reference, "ext-1234")
    account = container.aws_accounts.create(
        organization_id=ORG,
        created_by="user-alice",
        label="Production",
        account_id=ACCOUNT_ID,
        role_arn=f"arn:aws:iam::{ACCOUNT_ID}:role/CloudPatrolReadOnly",
        regions=["us-east-1"],
        status="validated",
        status_message=None,
        last_validated_at=datetime.now(UTC),
        external_id_ref=reference,
    )
    return account.id


def queue_scan(container, account_pk: str) -> str:
    record = container.scans.create(
        organization_id=ORG,
        aws_account_id=account_pk,
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by="user-alice",
    )
    return record.id


def job_for(scan_id: str, account_pk: str) -> ScanJob:
    return ScanJob(
        scan_id=scan_id,
        organization_id=ORG,
        aws_account_id=account_pk,
        created_by="user-alice",
    )


# --- executor ------------------------------------------------------------


def test_executor_completes_a_queued_scan() -> None:
    container, executor, vault, _connection, adapter = build(
        FakeAwsAdapter(volumes=[unattached_volume()])
    )
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)

    executor.execute(job_for(scan_id, account_pk))

    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "completed"
    assert record.finding_count == 1
    assert record.attempts == 1


def test_executor_fails_scan_when_role_cannot_be_assumed() -> None:
    """A revoked trust policy must resolve the scan, not strand it."""
    container, executor, vault, connection, _adapter = build()
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)
    connection.error = FakeAwsError(
        "AWS denied the request.", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )

    executor.execute(job_for(scan_id, account_pk))

    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "failed"
    assert record.finished_at is not None
    # The account is released, so the user can retry after fixing their side.
    assert container.scans.find_active_for_account(ORG, account_pk) is None


def test_executor_fails_scan_when_external_id_is_missing() -> None:
    container, executor, vault, _connection, _adapter = build()
    account_pk = connect_account(container, vault, with_external_id=False)
    scan_id = queue_scan(container, account_pk)

    executor.execute(job_for(scan_id, account_pk))

    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "failed"
    assert "external ID" in (record.error_message or "")


def test_executor_fails_scan_when_secret_was_evicted() -> None:
    """A vault miss is a definite failure, not a reason to scan unauthenticated."""
    container, executor, vault, _connection, _adapter = build()
    account_pk = connect_account(container, vault)
    vault.delete("aws-account/ref/external-id")
    scan_id = queue_scan(container, account_pk)

    executor.execute(job_for(scan_id, account_pk))

    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "failed"


def test_executor_fails_scan_when_account_was_disconnected() -> None:
    container, executor, vault, _connection, _adapter = build()
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)
    del container.store.aws_accounts[account_pk]

    executor.execute(job_for(scan_id, account_pk))

    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "failed"


def test_executor_records_audit_events_for_pre_collection_failures() -> None:
    container, executor, vault, connection, _adapter = build()
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)
    connection.error = FakeAwsError("denied", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403)

    executor.execute(job_for(scan_id, account_pk))

    actions = [e.action for e in container.audit.list_for_org(ORG)]
    assert "scan.failed" in actions


def test_executor_survives_a_scan_that_raises_unexpectedly() -> None:
    """The worker must not die because one scan hit a bug."""

    class ExplodingAdapter(FakeAwsAdapter):
        def describe_volumes(self, credentials, *, region):  # type: ignore[no-untyped-def]
            raise TypeError("unexpected payload shape")

    container, executor, vault, _connection, _adapter = build(ExplodingAdapter())
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)

    # Must not raise out of the executor.
    executor.execute(job_for(scan_id, account_pk))

    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "failed"
    assert container.scans.find_active_for_account(ORG, account_pk) is None


# --- worker pool ---------------------------------------------------------


def test_worker_pool_processes_a_job() -> None:
    container, executor, vault, _connection, adapter = build(
        FakeAwsAdapter(volumes=[unattached_volume()])
    )
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)

    pool = ScanWorkerPool(
        executor=executor,
        worker_count=1,
        max_queue_size=5,
        poll_timeout_seconds=0.01,
        shutdown_grace_seconds=5.0,
    )
    pool.start()
    try:
        pool.submit(job_for(scan_id, account_pk))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            record = container.scans.get(ORG, scan_id)
            if record is not None and record.status not in {"queued", "running"}:
                break
            time.sleep(0.01)
    finally:
        pool.stop()

    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "completed"


def test_full_queue_is_refused_rather_than_growing() -> None:
    """An unbounded queue would let a request burst exhaust memory."""
    container, executor, vault, _connection, _adapter = build()
    account_pk = connect_account(container, vault)

    # No workers started, so nothing drains the queue.
    pool = ScanWorkerPool(
        executor=executor,
        worker_count=1,
        max_queue_size=2,
        poll_timeout_seconds=0.01,
        shutdown_grace_seconds=1.0,
    )
    pool.submit(job_for(queue_scan(container, account_pk), account_pk))
    pool.submit(job_for(queue_scan(container, account_pk), account_pk))

    try:
        pool.submit(job_for(queue_scan(container, account_pk), account_pk))
    except ConflictError:
        pass
    else:  # pragma: no cover - only reached if the bound is missing
        raise AssertionError("a full queue must refuse work")

    assert pool.depth == 2


def test_submitting_after_shutdown_is_refused() -> None:
    container, executor, vault, _connection, _adapter = build()
    account_pk = connect_account(container, vault)
    pool = ScanWorkerPool(
        executor=executor,
        worker_count=1,
        max_queue_size=5,
        poll_timeout_seconds=0.01,
        shutdown_grace_seconds=1.0,
    )
    pool.start()
    pool.stop()

    try:
        pool.submit(job_for(queue_scan(container, account_pk), account_pk))
    except ConflictError:
        pass
    else:  # pragma: no cover
        raise AssertionError("submission after shutdown must be refused")


def test_worker_pool_stops_cleanly() -> None:
    container, executor, vault, _connection, _adapter = build()
    pool = ScanWorkerPool(
        executor=executor,
        worker_count=3,
        max_queue_size=5,
        poll_timeout_seconds=0.01,
        shutdown_grace_seconds=5.0,
    )
    pool.start()
    time.sleep(0.05)
    pool.stop()

    # Every worker thread has exited.
    assert all(not t.is_alive() for t in threading.enumerate() if t.name.startswith("scan-worker-"))


# --- stale scan reaper ---------------------------------------------------


def test_reaper_fails_a_stranded_running_scan() -> None:
    """A worker that died must not lock the account out of future scans."""
    container, executor, vault, _connection, _adapter = build()
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)
    # Simulate a worker that claimed the scan and then vanished.
    container.scans.mark_running(scan_id, started_at=datetime.now(UTC) - timedelta(hours=2))

    reaper = StaleScanReaper(
        scans=container.scans, executor=executor, stale_after_seconds=60, interval_seconds=1.0
    )
    reaped = reaper.reap_once()

    assert reaped == [scan_id]
    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "failed"
    # The account can be scanned again.
    assert container.scans.find_active_for_account(ORG, account_pk) is None


def test_reaper_fails_a_stranded_queued_scan() -> None:
    """A scan accepted but never picked up must also be released."""
    container, executor, vault, _connection, _adapter = build()
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)
    # Age the row past the threshold.
    container.store.scans[scan_id] = container.scans.update(
        scan_id, created_at=datetime.now(UTC) - timedelta(hours=2)
    )

    reaper = StaleScanReaper(
        scans=container.scans, executor=executor, stale_after_seconds=60, interval_seconds=1.0
    )
    reaped = reaper.reap_once()

    assert reaped == [scan_id]
    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "failed"


def test_reaper_leaves_a_fresh_scan_alone() -> None:
    """A scan that is genuinely in progress must not be failed."""
    container, executor, vault, _connection, _adapter = build()
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)
    container.scans.mark_running(scan_id, started_at=datetime.now(UTC))

    reaper = StaleScanReaper(
        scans=container.scans, executor=executor, stale_after_seconds=1800, interval_seconds=1.0
    )
    assert reaper.reap_once() == []

    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "running"


def test_reaper_does_not_fail_a_scan_claimed_after_listing() -> None:
    """The race the atomic re-check exists to close.

    The reaper lists stale scans, and before it writes, a worker claims one.
    The scan must survive: it is running, not abandoned.
    """
    container, executor, vault, _connection, _adapter = build()
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)
    container.store.scans[scan_id] = container.scans.update(
        scan_id, created_at=datetime.now(UTC) - timedelta(hours=2)
    )

    cutoff = datetime.now(UTC) - timedelta(seconds=60)
    listed = container.scans.find_stale_active(active_before=cutoff)
    assert [r.id for r in listed] == [scan_id]

    # A worker claims it in the gap between listing and reaping.
    container.scans.mark_running(scan_id, started_at=datetime.now(UTC))

    # The reaper's write must not land.
    assert container.scans.fail_if_stale(scan_id, active_before=cutoff, message="x") is False
    record = container.scans.get(ORG, scan_id)
    assert record is not None
    assert record.status == "running"


def test_reaper_records_an_audit_event() -> None:
    container, executor, vault, _connection, _adapter = build()
    account_pk = connect_account(container, vault)
    scan_id = queue_scan(container, account_pk)
    container.scans.mark_running(scan_id, started_at=datetime.now(UTC) - timedelta(hours=2))

    reaper = StaleScanReaper(
        scans=container.scans, executor=executor, stale_after_seconds=60, interval_seconds=1.0
    )
    reaper.reap_once()

    actions = [e.action for e in container.audit.list_for_org(ORG)]
    assert "scan.reaped" in actions


def test_reaper_can_be_started_and_stopped() -> None:
    container, executor, _vault, _connection, _adapter = build()
    reaper = StaleScanReaper(
        scans=container.scans, executor=executor, stale_after_seconds=60, interval_seconds=0.01
    )
    reaper.start()
    reaper.start()  # Idempotent.
    time.sleep(0.05)
    reaper.stop()
    reaper.stop()  # Idempotent.
