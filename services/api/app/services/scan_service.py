"""Scan orchestration.

A scan collects resources per region, records what it collected, runs the
detectors, and persists findings. The behaviour that matters most is how it
handles failure:

* Every AWS call is wrapped so a failure in one region or service is recorded
  as a partial failure instead of aborting the whole scan.
* If *any* partial failure occurred, the scan finishes as ``partial``, never
  ``completed``. A scan that could not read part of an account must never look
  like a clean, empty account — that is the difference between "you have no
  waste" and "we could not see part of your account".
* If nothing could be collected at all, the scan is ``failed`` and no findings
  are written.

The service depends on the adapter protocol and the repository protocols, so
it runs against a fake adapter in tests with no AWS access.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from app.aws.adapter import AwsAdapter, AwsCredentials
from app.core.errors import AppError, ErrorCode
from app.repositories.models import (
    FindingRecord,
    ResourceSnapshotRecord,
    ScanRecord,
    new_id,
    utc_now,
)
from app.repositories.protocols import (
    AuditRepository,
    CostRepository,
    FindingRepository,
    ResourceRepository,
    ScanRepository,
)
from app.services.billing import BillingService
from app.services.detectors.base import Detector
from app.services.savings_ledger import SavingsLedgerService

logger = logging.getLogger(__name__)

# CloudWatch CPU window used by the EC2 detector.
_METRIC_WINDOW_DAYS = 14
_METRIC_PERIOD_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class CollectedAccountData:
    """Everything one scan collected, plus what it failed to collect."""

    resources: list[ResourceSnapshotRecord]
    partial_failures: list[dict[str, Any]]


class PartialFailureLog:
    """Accumulates partial failures without repeating the same one.

    A CloudWatch denial is recorded once per instance, so an account with 300
    instances and a missing permission would otherwise store 300 identical
    entries — burying the one fact that matters under its own repetition. The
    first occurrence keeps the full detail; later ones increment ``occurrences``.

    Keyed by ``(service, region, code)`` rather than by message, because the
    message is the part that legitimately varies between occurrences.
    """

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str | None, str], dict[str, Any]] = {}

    def add(self, *, service: str, region: str | None, code: str, message: str) -> None:
        key = (service, region, code)
        existing = self._entries.get(key)
        if existing is not None:
            existing["occurrences"] = int(existing.get("occurrences", 1)) + 1
            return
        self._entries[key] = {
            "service": service,
            "region": region,
            "code": code,
            "message": message,
            "occurrences": 1,
        }

    def as_list(self) -> list[dict[str, Any]]:
        return list(self._entries.values())

    def __bool__(self) -> bool:
        return bool(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


class ScanService:
    """Orchestrates a read-only scan for one AWS account."""

    def __init__(
        self,
        *,
        adapter: AwsAdapter,
        scans: ScanRepository,
        resources: ResourceRepository,
        findings: FindingRepository,
        audit: AuditRepository,
        detectors: Sequence[Detector],
        savings_ledger: SavingsLedgerService | None = None,
        costs: CostRepository | None = None,
        billing: BillingService | None = None,
    ) -> None:
        self._adapter = adapter
        self._scans = scans
        self._resources = resources
        self._findings = findings
        self._audit = audit
        self._detectors = list(detectors)
        # Optional so a unit test can exercise scanning without a ledger. When
        # present, a priced finding is automatically entered in the ledger as a
        # *potential* saving — never as anything stronger.
        self._savings_ledger = savings_ledger
        # Billing is optional and separately permissioned. Absent, the scan
        # simply does not attempt cost collection.
        self._costs = costs
        self._billing = billing

    # -- collection -------------------------------------------------------

    def _collect(
        self,
        credentials: AwsCredentials,
        *,
        account_id: str,
        organization_id: str,
        scan_id: str,
        regions: Sequence[str],
    ) -> CollectedAccountData:
        resources: list[ResourceSnapshotRecord] = []
        failures = PartialFailureLog()

        for region in regions:
            # Temporary credentials last an hour. If they have expired, every
            # remaining call would fail one by one and be reported as an
            # ordinary per-service error, which hides the real cause. Stopping
            # here records the expiry itself and leaves the rest of the regions
            # honestly unread rather than reported as empty.
            if credentials.is_expired(now=datetime.now(UTC)):
                failures.add(
                    service="sts",
                    region=None,
                    code=str(ErrorCode.AWS_ASSUME_ROLE_FAILED),
                    message="Temporary credentials expired before this region was read.",
                )
                logger.warning("Stopping scan early: credentials expired")
                break

            resources.extend(
                self._collect_region(
                    credentials,
                    account_id=account_id,
                    organization_id=organization_id,
                    scan_id=scan_id,
                    region=region,
                    failures=failures,
                )
            )

        return CollectedAccountData(resources=resources, partial_failures=failures.as_list())

    def _collect_region(
        self,
        credentials: AwsCredentials,
        *,
        account_id: str,
        organization_id: str,
        scan_id: str,
        region: str,
        failures: PartialFailureLog,
    ) -> list[ResourceSnapshotRecord]:
        """Collect one region, recording failures rather than raising them."""
        collected: list[ResourceSnapshotRecord] = []

        def _snapshot(
            resource_type: str,
            resource_id: str,
            state: str | None,
            name: str | None,
            attributes: dict[str, Any],
        ) -> ResourceSnapshotRecord:
            return ResourceSnapshotRecord(
                id=new_id(),
                organization_id=organization_id,
                scan_id=scan_id,
                aws_account_id=account_id,
                resource_type=resource_type,
                resource_id=resource_id,
                region=region,
                name=name,
                state=state,
                attributes=attributes,
                created_at=utc_now(),
            )

        # --- EBS volumes ---
        try:
            for volume in self._adapter.describe_volumes(credentials, region=region):
                volume_id = str(volume.get("VolumeId", ""))
                if not volume_id:
                    continue
                tags = {
                    t.get("Key"): t.get("Value") for t in volume.get("Tags", []) if t.get("Key")
                }
                collected.append(
                    _snapshot(
                        "ebs_volume",
                        volume_id,
                        str(volume.get("State") or ""),
                        tags.get("Name"),
                        {
                            "size_gb": volume.get("Size"),
                            "volume_type": volume.get("VolumeType"),
                            "availability_zone": volume.get("AvailabilityZone"),
                            "create_time": _isoformat(volume.get("CreateTime")),
                            "attachments": volume.get("Attachments", []),
                            "tags": tags,
                        },
                    )
                )
        except AppError as exc:
            failures.add(service="ec2", region=region, code=str(exc.code), message=exc.message)

        # --- Elastic IPs ---
        try:
            for address in self._adapter.describe_addresses(credentials, region=region):
                allocation_id = address.get("AllocationId") or address.get("PublicIp")
                if not allocation_id:
                    continue
                collected.append(
                    _snapshot(
                        "elastic_ip",
                        str(allocation_id),
                        "associated" if address.get("AssociationId") else "unassociated",
                        address.get("PublicIp"),
                        {
                            "public_ip": address.get("PublicIp"),
                            "domain": address.get("Domain"),
                            "association_id": address.get("AssociationId"),
                            "instance_id": address.get("InstanceId"),
                            "network_interface_id": address.get("NetworkInterfaceId"),
                        },
                    )
                )
        except AppError as exc:
            failures.add(service="ec2", region=region, code=str(exc.code), message=exc.message)

        # --- EC2 instances (with CPU metrics) ---
        try:
            instances = self._adapter.describe_instances(credentials, region=region)
        except AppError as exc:
            failures.add(service="ec2", region=region, code=str(exc.code), message=exc.message)
            instances = []

        for instance in instances:
            instance_id = str(instance.get("InstanceId", ""))
            if not instance_id:
                continue
            tags = {t.get("Key"): t.get("Value") for t in instance.get("Tags", []) if t.get("Key")}
            cpu_datapoints = self._collect_cpu(
                credentials,
                region=region,
                instance_id=instance_id,
                failures=failures,
            )
            collected.append(
                _snapshot(
                    "ec2_instance",
                    instance_id,
                    str(instance.get("State", {}).get("Name") or ""),
                    tags.get("Name"),
                    {
                        "instance_type": instance.get("InstanceType"),
                        "launch_time": _isoformat(instance.get("LaunchTime")),
                        "availability_zone": instance.get("Placement", {}).get("AvailabilityZone"),
                        "tags": tags,
                        "cpu_datapoints": cpu_datapoints,
                    },
                )
            )

        return collected

    def _collect_cpu(
        self,
        credentials: AwsCredentials,
        *,
        region: str,
        instance_id: str,
        failures: PartialFailureLog,
    ) -> list[dict[str, Any]]:
        """Fetch CPU datapoints, treating failure as absent data.

        A CloudWatch failure does not abort the instance snapshot. The instance
        is still recorded, but with no datapoints, and the EC2 detector will
        decline to draw a conclusion. The failure is recorded as a partial
        failure so the scan is not reported as clean.
        """
        end = datetime.now(UTC)
        start = end - timedelta(days=_METRIC_WINDOW_DAYS)
        try:
            return self._adapter.get_metric_statistics(
                credentials,
                region=region,
                namespace="AWS/EC2",
                metric_name="CPUUtilization",
                dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                start_time=start,
                end_time=end,
                period_seconds=_METRIC_PERIOD_SECONDS,
                statistics=["Average", "Maximum"],
            )
        except AppError as exc:
            failures.add(
                service="cloudwatch", region=region, code=str(exc.code), message=exc.message
            )
            return []

    # -- orchestration ----------------------------------------------------

    def record_audit(
        self,
        *,
        organization_id: str,
        actor_user_id: str,
        action: str,
        scan_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Write an audit event for a scan.

        Exposed so the executor can record failures that happen before
        collection starts — a revoked trust policy, a missing external ID —
        which are exactly the events an auditor most wants to see.
        """
        self._audit.record(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
            target_type="scan",
            target_id=scan_id,
            metadata=metadata or {},
        )

    def run_scan(
        self,
        *,
        organization_id: str,
        aws_account_id: str,
        account_id: str,
        regions: Sequence[str],
        credentials: AwsCredentials,
        created_by: str,
        scan_id: str,
    ) -> ScanRecord:
        """Execute a scan and persist its outcome.

        ``credentials`` are passed in already-assumed, so this method performs
        no role assumption and holds no secret of its own.
        """
        # Claim the scan atomically. The attempt counter is incremented under
        # the store lock, so a scan retried after a worker crash is
        # distinguishable from one that never ran.
        self._scans.mark_running(scan_id, started_at=utc_now())

        try:
            collected = self._collect(
                credentials,
                account_id=account_id,
                organization_id=organization_id,
                scan_id=scan_id,
                regions=regions,
            )
        except Exception as exc:  # noqa: BLE001 - an unhandled error must not strand the scan
            # A non-AppError here means a bug or a surprising AWS payload. The
            # scan row was already flipped to ``running``, so leaving it there
            # would block every future scan of this account. Recording the
            # failure and re-raising keeps the row honest and lets the caller
            # return a 500 rather than pretending the scan is still working.
            logger.exception("Scan failed unexpectedly", extra={"scan_id": scan_id})
            self._scans.update(
                scan_id,
                status="failed",
                finished_at=utc_now(),
                partial_failures=[],
                error_message=f"Scan failed unexpectedly: {type(exc).__name__}",
                resource_count=0,
                finding_count=0,
            )
            self._audit.record(
                organization_id=organization_id,
                actor_user_id=created_by,
                action="scan.failed",
                target_type="scan",
                target_id=scan_id,
                metadata={"unexpected": type(exc).__name__},
            )
            raise

        # Nothing collected and something failed => a failed scan, not an
        # empty account.
        if not collected.resources and collected.partial_failures:
            first = collected.partial_failures[0]
            record = self._scans.update(
                scan_id,
                status="failed",
                finished_at=utc_now(),
                partial_failures=collected.partial_failures,
                error_message=f"{first['service']} collection failed: {first['message']}",
                resource_count=0,
                finding_count=0,
            )
            self._audit.record(
                organization_id=organization_id,
                actor_user_id=created_by,
                action="scan.failed",
                target_type="scan",
                target_id=scan_id,
                metadata={"partial_failure_count": len(collected.partial_failures)},
            )
            return record

        self._resources.add_many(collected.resources)

        finding_records = self._run_detectors(
            collected.resources,
            organization_id=organization_id,
            scan_id=scan_id,
            aws_account_id=aws_account_id,
        )
        upsert = self._findings.upsert_many(finding_records)
        self._record_potential_savings(upsert.records, created_by=created_by)

        # Billing is collected separately because it needs its own permission.
        # A denial is recorded as a partial failure and the cost figures are
        # left absent — never zeroed, which would misstate the customer's bill.
        partial_failures = list(collected.partial_failures)
        if self._billing is not None and self._costs is not None:
            billing_result = self._billing.collect(
                credentials,
                organization_id=organization_id,
                aws_account_id=aws_account_id,
                scan_id=scan_id,
            )
            if billing_result.failure is not None:
                partial_failures.append(billing_result.failure)
            elif billing_result.observations:
                self._costs.add_many(billing_result.observations)

        status = "partial" if partial_failures else "completed"
        record = self._scans.update(
            scan_id,
            status=status,
            finished_at=utc_now(),
            resource_count=len(collected.resources),
            # Count what the scan observed, not only what was newly inserted.
            # Reporting only insertions would make a re-scan that re-confirmed
            # fifty known problems look like it found nothing.
            finding_count=upsert.total,
            partial_failures=partial_failures,
            error_message=None,
        )

        self._audit.record(
            organization_id=organization_id,
            actor_user_id=created_by,
            action=f"scan.{status}",
            target_type="scan",
            target_id=scan_id,
            metadata={
                "resource_count": len(collected.resources),
                "finding_count": upsert.total,
                "findings_inserted": upsert.inserted,
                "findings_refreshed": upsert.refreshed,
                "partial_failure_count": len(partial_failures),
            },
        )
        return record

    def _record_potential_savings(
        self, findings: Sequence[FindingRecord], *, created_by: str
    ) -> None:
        """Enter each priced finding in the savings ledger as a potential saving.

        A failure here must not fail the scan: the findings are already
        persisted, and the ledger can be reconciled afterwards. It is logged
        loudly because a silently missing ledger entry would understate the
        opportunity shown to the user.
        """
        if self._savings_ledger is None:
            return
        for finding in findings:
            try:
                self._savings_ledger.record_potential(
                    organization_id=finding.organization_id,
                    finding=finding,
                    actor_user_id=created_by,
                )
            except Exception:  # noqa: BLE001 - ledger trouble must not fail a scan
                logger.exception(
                    "Failed to record potential saving",
                    extra={"finding_id": finding.id},
                )

    def _run_detectors(
        self,
        resources: Sequence[ResourceSnapshotRecord],
        *,
        organization_id: str,
        scan_id: str,
        aws_account_id: str,
    ) -> list[FindingRecord]:
        """Run every detector and convert its output into persistable rows."""
        records: list[FindingRecord] = []

        for detector in self._detectors:
            try:
                produced = detector.detect(resources)
            except Exception:  # noqa: BLE001 - one bad detector must not fail the scan
                logger.exception("Detector failed", extra={"detector": detector.name})
                continue

            for candidate in produced:
                records.append(
                    FindingRecord(
                        id=new_id(),
                        organization_id=organization_id,
                        scan_id=scan_id,
                        aws_account_id=aws_account_id,
                        detector=candidate.detector,
                        resource_type=candidate.resource_type,
                        resource_id=candidate.resource_id,
                        region=candidate.region,
                        severity=candidate.severity,
                        confidence=candidate.confidence,
                        # A detector output is always an estimate.
                        state="estimated",
                        title=candidate.title,
                        summary=candidate.summary,
                        evidence=candidate.evidence,
                        recommended_action=candidate.recommended_action,
                        estimated_monthly_savings=candidate.estimated_monthly_savings,
                        currency=candidate.currency,
                        dedupe_key=candidate.dedupe_key(aws_account_id=aws_account_id),
                        created_at=utc_now(),
                        updated_at=utc_now(),
                    )
                )

        return records


def _isoformat(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


__all__ = ["ScanService", "CollectedAccountData", "ErrorCode"]
