"""Asynchronous scan execution.

A scan reads many AWS services across many regions, so it takes far longer than
a request should be held open. The request therefore only *accepts* the work
and returns; a background worker performs it.

Three components live here:

* :class:`ScanExecutor` — performs one scan end to end: assume the role, read
  the account, persist the outcome. It owns every failure path, so a scan
  always reaches a terminal state and never strands its account.
* :class:`ScanWorkerPool` — a bounded queue and a fixed number of worker
  threads. The bound matters: an unbounded queue turns a burst of requests into
  unbounded memory growth, so a full queue is refused instead.
* :class:`StaleScanReaper` — fails scans whose worker died. Without it, a
  crashed scan would hold ``running`` forever and block that account from ever
  being scanned again.

The queue is in-process and therefore *not durable*. A scan accepted just
before a hard crash is lost, and is recovered by the reaper marking it failed
rather than by resuming it. Durable queuing is a later phase; the reaper is
what keeps the current design from deadlocking an account.
"""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.core.errors import AppError, ConflictError, ErrorCode
from app.repositories.models import ScanRecord, utc_now
from app.repositories.protocols import (
    AwsAccountRepository,
    ScanRepository,
)
from app.services.aws_connection import AwsConnectionService
from app.services.scan_service import ScanService
from app.services.secrets import SecretVault

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ScanJob:
    """A unit of work: scan one account for one organization.

    Carries identifiers only. Credentials are never queued — the worker assumes
    the role itself, so no temporary credential is held in memory longer than
    the scan that needs it, and none can be captured from the queue.
    """

    scan_id: str
    organization_id: str
    aws_account_id: str
    created_by: str


class ScanExecutor:
    """Runs one scan, resolving its own credentials from the vault."""

    def __init__(
        self,
        *,
        connection: AwsConnectionService,
        vault: SecretVault,
        accounts: AwsAccountRepository,
        scans: ScanRepository,
        scan_service: ScanService,
    ) -> None:
        # No adapter of its own: role assumption goes through the connection
        # service and collection through the scan service, so there is exactly
        # one AWS boundary to substitute in tests.
        self._connection = connection
        self._vault = vault
        self._accounts = accounts
        self._scans = scans
        self._scan_service = scan_service

    def _fail(self, job: ScanJob, *, reason: str, code: str) -> ScanRecord:
        """Move a scan to ``failed`` with a safe, non-sensitive reason."""
        record = self._scans.update(
            job.scan_id,
            status="failed",
            finished_at=utc_now(),
            error_message=reason,
            resource_count=0,
            finding_count=0,
        )
        self._scan_service.record_audit(
            organization_id=job.organization_id,
            actor_user_id=job.created_by,
            action="scan.failed",
            scan_id=job.scan_id,
            metadata={"code": code},
        )
        logger.warning(
            "Scan failed before collection",
            extra={"scan_id": job.scan_id, "code": code},
        )
        return record

    def record_reap(self, record: ScanRecord) -> None:
        """Audit a scan that the reaper had to fail.

        Recorded separately from a normal failure because the cause is
        operational — a lost worker — rather than anything the customer did.
        """
        self._scan_service.record_audit(
            organization_id=record.organization_id,
            actor_user_id=record.created_by or "system",
            action="scan.reaped",
            scan_id=record.id,
            metadata={"previous_status": record.status, "attempts": record.attempts},
        )

    def execute(self, job: ScanJob) -> None:
        """Perform a queued scan. Never raises; failures are persisted."""
        # The account is re-read here rather than trusted from the request, so
        # a scan always uses the connection as it is now. If it was deleted
        # between acceptance and execution, that is a definite failure.
        account = self._accounts.get(job.organization_id, job.aws_account_id)
        if account is None:
            self._fail(job, reason="The AWS account is no longer connected.", code="not_found")
            return

        reference = account.external_id_ref
        if not reference:
            self._fail(
                job,
                reason="This AWS account has no stored external ID. Reconnect the account.",
                code=str(ErrorCode.CONFLICT),
            )
            return

        external_id = self._vault.get(reference)
        if not external_id:
            self._fail(
                job,
                reason="The stored external ID for this account is unavailable. Reconnect it.",
                code=str(ErrorCode.CONFLICT),
            )
            return

        try:
            credentials, _caller_arn, _expires_at = self._connection.validate_connection(
                organization_id=job.organization_id,
                account_id=account.account_id,
                role_arn=account.role_arn,
                external_id=external_id,
                region=account.regions[0],
            )
        except AppError as exc:
            # AssumeRole is where a revoked trust policy or a rotated external
            # ID shows up. The scan fails with the reason, and — because the row
            # is already claimed as `running` — the account is released for a
            # retry once the customer fixes their side.
            self._fail(job, reason=exc.message, code=str(exc.code))
            return

        try:
            self._scan_service.run_scan(
                organization_id=job.organization_id,
                aws_account_id=account.id,
                account_id=account.account_id,
                regions=account.regions,
                credentials=credentials,
                created_by=job.created_by,
                scan_id=job.scan_id,
            )
        except Exception:  # noqa: BLE001 - the worker must survive any scan failure
            # run_scan already marked the scan failed and re-raised. The
            # traceback is logged; nothing is swallowed silently.
            logger.exception("Scan raised unexpectedly", extra={"scan_id": job.scan_id})


class ScanWorkerPool:
    """A bounded queue served by a fixed number of worker threads.

    Threads are used rather than asyncio tasks because the AWS SDK is
    synchronous. A scan is dominated by network waits, so a small number of
    threads handles a reasonable concurrency without an event-loop rewrite.
    """

    def __init__(
        self,
        *,
        executor: ScanExecutor,
        worker_count: int,
        max_queue_size: int,
        poll_timeout_seconds: float,
        shutdown_grace_seconds: float,
    ) -> None:
        self._executor = executor
        self._worker_count = worker_count
        self._shutdown_grace_seconds = shutdown_grace_seconds
        self._poll_timeout_seconds = poll_timeout_seconds
        self._queue: queue.Queue[ScanJob | None] = queue.Queue(maxsize=max_queue_size)
        self._threads: list[threading.Thread] = []
        self._running = threading.Event()
        self._accepting = True
        # Serialises start/stop so a double shutdown cannot join twice.
        self._lifecycle_lock = threading.Lock()

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._running.is_set():
                return
            self._running.set()
            self._accepting = True
            for index in range(self._worker_count):
                thread = threading.Thread(
                    target=self._worker_loop,
                    name=f"scan-worker-{index}",
                    daemon=True,
                )
                thread.start()
                self._threads.append(thread)
            logger.info("Scan workers started", extra={"worker_count": self._worker_count})

    def stop(self) -> None:
        """Stop accepting work and let in-flight scans finish.

        Workers are sent a ``None`` sentinel and the queue is drained of pending
        jobs first, so a scan already picked up is not abandoned mid-write.
        """
        with self._lifecycle_lock:
            if not self._running.is_set():
                return
            self._accepting = False
            self._running.clear()
            for _ in self._threads:
                # A full queue would block here; the sentinels are placed with a
                # short timeout and any that do not fit are covered by the
                # drain below.
                try:
                    self._queue.put_nowait(None)
                except queue.Full:
                    break
            threads, self._threads = self._threads, []

        for thread in threads:
            thread.join(timeout=self._shutdown_grace_seconds)
            if thread.is_alive():
                # Daemon threads, so the process can still exit. Logged because
                # a scan may not have finished writing its outcome.
                logger.warning("Scan worker did not stop within grace period")
        logger.info("Scan workers stopped")

    # -- submission -------------------------------------------------------

    @property
    def depth(self) -> int:
        """Jobs waiting to be picked up. Used by the readiness probe."""
        return self._queue.qsize()

    def submit(self, job: ScanJob) -> None:
        """Queue a scan, or refuse it if the queue is full.

        Refusing is deliberate. Accepting work that cannot be run would leave a
        `queued` scan that blocks the account while never starting.
        """
        if not self._accepting:
            raise ConflictError("The scan service is shutting down. Retry shortly.")
        try:
            self._queue.put_nowait(job)
        except queue.Full:
            raise ConflictError(
                "The scan queue is full. Retry shortly.",
                details={"queue_depth": self._queue.qsize()},
            ) from None

    # -- worker -----------------------------------------------------------

    def _worker_loop(self) -> None:
        while True:
            try:
                job = self._queue.get(timeout=self._poll_timeout_seconds)
            except queue.Empty:
                # A timeout rather than a blocking get, so a worker notices
                # shutdown even when no job arrives.
                if not self._running.is_set():
                    return
                continue

            try:
                if job is None:
                    return
                self._executor.execute(job)
            except Exception:  # noqa: BLE001 - one bad job must not kill the worker
                logger.exception("Scan worker raised outside the executor")
            finally:
                self._queue.task_done()


class StaleScanReaper:
    """Fails scans that were abandoned by a dead worker.

    A scan left in ``queued`` or ``running`` past the staleness threshold is
    treated as lost. It is marked ``failed`` rather than retried automatically:
    an automatic retry could loop forever on a scan that crashes its worker
    every time, and failing it releases the account so the user can simply
    start a new scan.
    """

    def __init__(
        self,
        *,
        scans: ScanRepository,
        executor: ScanExecutor,
        stale_after_seconds: int,
        interval_seconds: float,
    ) -> None:
        self._scans = scans
        self._executor = executor
        self._stale_after_seconds = stale_after_seconds
        self._interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="scan-reaper", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5.0)

    def reap_once(self, *, now: datetime | None = None) -> list[str]:
        """Fail every stale scan. Returns the ids it failed."""
        reference = now or datetime.now(UTC)
        cutoff = reference - timedelta(seconds=self._stale_after_seconds)
        stale = self._scans.find_stale_active(active_before=cutoff)

        message = "The scan was interrupted and did not complete."
        reaped: list[str] = []
        for record in stale:
            # Re-checked atomically: a worker may have claimed this scan since
            # the listing above, in which case it is running and must not be
            # failed.
            if not self._scans.fail_if_stale(record.id, active_before=cutoff, message=message):
                continue
            self._executor.record_reap(record)
            reaped.append(record.id)

        if reaped:
            logger.warning("Reaped stale scans", extra={"count": len(reaped)})
        return reaped

    def _loop(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            try:
                self.reap_once()
            except Exception:  # noqa: BLE001 - the reaper must keep running
                logger.exception("Stale scan reaper iteration failed")


__all__ = [
    "ScanExecutor",
    "ScanJob",
    "ScanWorkerPool",
    "StaleScanReaper",
]
