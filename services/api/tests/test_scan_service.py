"""Tests for scan orchestration: partial failure, empty scans, duplicates.

These are the tests that matter most. The failure mode they guard against is a
scan that could not read part of an account being reported as a clean,
completed scan — because "you have no waste" and "we could not see your
account" must never look the same to a user.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.aws.adapter import AwsCredentials
from app.core.errors import ErrorCode
from app.repositories.memory import build_container
from app.services.detectors import build_detectors
from app.services.scan_service import ScanService
from tests.fake_aws import FakeAwsAdapter, FakeAwsError

ACCOUNT_ID = "123456789012"


def make_service(adapter: FakeAwsAdapter, container=None) -> tuple[ScanService, object]:  # type: ignore[no-untyped-def]
    store_container = container or build_container()
    service = ScanService(
        adapter=adapter,
        scans=store_container.scans,
        resources=store_container.resources,
        findings=store_container.findings,
        audit=store_container.audit,
        detectors=build_detectors(),
    )
    return service, store_container


def run(service: ScanService, container, regions: list[str] | None = None):  # type: ignore[no-untyped-def]
    credentials = FakeAwsAdapter().assume_role(
        role_arn="arn:aws:iam::123456789012:role/CloudPatrolReadOnly",
        external_id="ext-1",
        region="us-east-1",
        session_name="test",
    )
    scan = container.scans.create(
        organization_id="org-1",
        aws_account_id="acct-pk-1",
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by="user-alice",
    )
    return service.run_scan(
        organization_id="org-1",
        aws_account_id="acct-pk-1",
        account_id=ACCOUNT_ID,
        regions=regions or ["us-east-1"],
        credentials=credentials,
        created_by="user-alice",
        scan_id=scan.id,
    )


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


def unassociated_address() -> dict:
    return {"AllocationId": "eipalloc-1", "PublicIp": "203.0.113.5", "Domain": "vpc"}


# --- happy path ----------------------------------------------------------


def test_successful_scan_is_completed() -> None:
    adapter = FakeAwsAdapter(volumes=[unattached_volume()], addresses=[unassociated_address()])
    service, container = make_service(adapter)
    record = run(service, container)
    assert record.status == "completed"
    assert record.resource_count == 2
    assert record.finding_count == 2
    assert record.partial_failures == []


def test_scan_records_start_and_finish_times() -> None:
    service, container = make_service(FakeAwsAdapter(volumes=[unattached_volume()]))
    record = run(service, container)
    assert record.started_at is not None
    assert record.finished_at is not None
    assert record.finished_at >= record.started_at


def test_findings_start_in_estimated_state() -> None:
    service, container = make_service(FakeAwsAdapter(volumes=[unattached_volume()]))
    run(service, container)
    findings = container.findings.list_for_org("org-1")
    assert len(findings) == 1
    # Nothing has been implemented, so nothing may be labelled verified.
    assert findings[0].state == "estimated"


# --- empty account -------------------------------------------------------


def test_empty_account_completes_with_no_findings() -> None:
    """A genuinely empty account is a success, not a failure."""
    service, container = make_service(FakeAwsAdapter())
    record = run(service, container)
    assert record.status == "completed"
    assert record.resource_count == 0
    assert record.finding_count == 0
    assert container.findings.list_for_org("org-1") == []


# --- partial failure -----------------------------------------------------


def test_cloudwatch_denied_yields_partial_not_completed() -> None:
    """The core correctness rule: a partial read is never reported as clean."""
    adapter = FakeAwsAdapter(
        volumes=[unattached_volume()],
        instances=[{"InstanceId": "i-1", "State": {"Name": "running"}, "InstanceType": "m5.large"}],
    )
    adapter.fail_on["cloudwatch"] = FakeAwsError(
        "denied", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )
    service, container = make_service(adapter)
    record = run(service, container)

    assert record.status == "partial"
    assert record.partial_failures
    assert record.partial_failures[0]["service"] == "cloudwatch"
    # The EBS finding is still produced; partial data is better than none.
    assert record.finding_count == 1


def test_partial_failure_records_region_and_code() -> None:
    """Failures are recorded with their region and code for triage."""
    adapter = FakeAwsAdapter(volumes=[unattached_volume("vol-a")])
    adapter.fail_on["cloudwatch"] = FakeAwsError(
        "denied", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )
    adapter._instances = [  # noqa: SLF001
        {"InstanceId": "i-1", "State": {"Name": "running"}, "InstanceType": "m5.large"}
    ]
    service, container = make_service(adapter)
    record = run(service, container, regions=["eu-west-1"])

    assert record.status == "partial"
    failure = record.partial_failures[0]
    assert failure["region"] == "eu-west-1"
    assert failure["code"] == ErrorCode.AWS_PERMISSION_DENIED
    assert failure["service"] == "cloudwatch"


def test_total_failure_marks_scan_failed_and_writes_no_findings() -> None:
    """Nothing collected plus errors means failed — not an empty account."""
    adapter = FakeAwsAdapter()
    adapter.fail_on["ec2"] = FakeAwsError(
        "denied", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )
    service, container = make_service(adapter)
    record = run(service, container)

    assert record.status == "failed"
    assert record.error_message
    assert record.resource_count == 0
    assert record.finding_count == 0
    assert container.findings.list_for_org("org-1") == []


def test_one_region_failing_does_not_abort_others() -> None:
    """A per-region failure must not lose a healthy region's data."""
    adapter = FakeAwsAdapter(volumes=[unattached_volume("vol-a")])
    original = adapter.describe_volumes
    calls = {"n": 0}

    def region_sensitive(credentials, *, region):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if region == "eu-west-1":
            raise FakeAwsError("denied", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403)
        return original(credentials, region=region)

    adapter.describe_volumes = region_sensitive  # type: ignore[method-assign]
    service, container = make_service(adapter)
    record = run(service, container, regions=["us-east-1", "eu-west-1"])

    assert record.status == "partial"
    assert record.resource_count == 1
    assert calls["n"] == 2


def test_audit_event_records_partial_scan() -> None:
    adapter = FakeAwsAdapter(
        volumes=[unattached_volume()],
        instances=[{"InstanceId": "i-1", "State": {"Name": "running"}, "InstanceType": "m5.large"}],
    )
    adapter.fail_on["cloudwatch"] = FakeAwsError(
        "denied", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )
    service, container = make_service(adapter)
    run(service, container)
    actions = [e.action for e in container.audit.list_for_org("org-1")]
    assert "scan.partial" in actions


def test_cloudwatch_is_not_probed_when_there_are_no_instances() -> None:
    """Metrics are a per-instance input, so an instance-free account needs none.

    With no instances there is no EC2 finding to make, so a missing CloudWatch
    permission cannot cause a misleading result — and skipping the calls avoids
    a pointless permission error on an empty account.
    """
    adapter = FakeAwsAdapter()
    adapter.fail_on["cloudwatch"] = FakeAwsError(
        "denied", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )
    service, container = make_service(adapter)
    record = run(service, container)

    assert record.status == "completed"
    assert not any(call[0] == "cloudwatch" for call in adapter.calls)


# --- duplicate suppression ----------------------------------------------


def test_rerunning_a_scan_does_not_duplicate_findings() -> None:
    adapter = FakeAwsAdapter(volumes=[unattached_volume()])
    service, container = make_service(adapter)
    first = run(service, container)
    second = run(service, container)

    assert first.finding_count == 1
    # The second scan re-observes the same opportunity. It is counted because
    # the scan did see it, but it must not become a second row.
    assert second.finding_count == 1
    assert len(container.findings.list_for_org("org-1")) == 1


def test_rescan_refreshes_evidence_but_preserves_the_decision() -> None:
    """A re-scan must update the observation without reverting a human decision.

    If a refresh reset ``state``, acknowledging or dismissing a finding would be
    undone by the next scan — which would make the review workflow unusable.
    """
    adapter = FakeAwsAdapter(volumes=[unattached_volume()])
    service, container = make_service(adapter)
    run(service, container)

    finding = container.findings.list_for_org("org-1")[0]
    container.findings.update(finding.id, state="acknowledged")
    first_scan_id = finding.scan_id

    second = run(service, container)
    refreshed = container.findings.list_for_org("org-1")[0]

    # Same row, same decision, same first-seen time.
    assert refreshed.id == finding.id
    assert refreshed.state == "acknowledged"
    assert refreshed.created_at == finding.created_at
    # But the observation now points at the scan that confirmed it.
    assert refreshed.scan_id == second.id
    assert refreshed.scan_id != first_scan_id
    assert refreshed.updated_at is not None
    assert refreshed.updated_at >= refreshed.created_at


def test_distinct_resources_produce_distinct_findings() -> None:
    adapter = FakeAwsAdapter(volumes=[unattached_volume("vol-1"), unattached_volume("vol-2")])
    service, container = make_service(adapter)
    record = run(service, container)
    assert record.finding_count == 2


# --- detector isolation --------------------------------------------------


def test_a_failing_detector_does_not_fail_the_scan() -> None:
    class ExplodingDetector:
        name = "exploding"
        resource_type = "ebs_volume"

        def detect(self, resources):  # type: ignore[no-untyped-def]
            raise RuntimeError("detector bug")

    container = build_container()
    service = ScanService(
        adapter=FakeAwsAdapter(volumes=[unattached_volume()]),
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=[ExplodingDetector(), *build_detectors()],
    )
    record = run(service, container)
    # The good detectors still ran.
    assert record.status == "completed"
    assert record.finding_count == 1


# --- partial failure de-duplication --------------------------------------


def test_repeated_identical_failures_are_collapsed() -> None:
    """A missing CloudWatch permission must not produce one entry per instance.

    The failure is identical for every instance, so recording it 300 times
    buries the single fact that matters. The entry keeps an occurrence count.
    """
    adapter = FakeAwsAdapter(
        instances=[
            {"InstanceId": f"i-{n:04d}", "State": {"Name": "running"}, "InstanceType": "m5.large"}
            for n in range(50)
        ]
    )
    adapter.fail_on["cloudwatch"] = FakeAwsError(
        "denied", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )
    service, container = make_service(adapter)
    record = run(service, container)

    assert record.status == "partial"
    assert len(record.partial_failures) == 1
    failure = record.partial_failures[0]
    assert failure["service"] == "cloudwatch"
    assert failure["occurrences"] == 50


def test_distinct_failures_are_kept_separate() -> None:
    """De-duplication must not merge genuinely different failures."""
    adapter = FakeAwsAdapter(
        instances=[{"InstanceId": "i-1", "State": {"Name": "running"}, "InstanceType": "m5.large"}]
    )

    # Fail the Elastic IP call, so instances are still discovered and the
    # CloudWatch path is reached. Failing ``describe_instances`` instead would
    # leave nothing to probe and never exercise the second failure.
    def denied_addresses(credentials, *, region):  # type: ignore[no-untyped-def]
        raise FakeAwsError("denied", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403)

    adapter.describe_addresses = denied_addresses  # type: ignore[method-assign]
    adapter.fail_on["cloudwatch"] = FakeAwsError(
        "denied", code=ErrorCode.AWS_PERMISSION_DENIED, status_code=403
    )
    service, container = make_service(adapter)
    record = run(service, container)

    services = {f["service"] for f in record.partial_failures}
    # Both services failed, so both are reported despite the same code.
    assert services == {"ec2", "cloudwatch"}
    assert len(record.partial_failures) == 2


# --- unexpected errors ---------------------------------------------------


def test_unexpected_error_marks_scan_failed_and_reraises() -> None:
    """A non-AppError must not leave the scan stuck in ``running``.

    A stranded ``running`` row would block every future scan of the account,
    because the duplicate-scan check treats it as active.
    """

    class ExplodingAdapter(FakeAwsAdapter):
        def describe_volumes(self, credentials, *, region):  # type: ignore[no-untyped-def]
            raise TypeError("unexpected payload shape")

    container = build_container()
    service = ScanService(
        adapter=ExplodingAdapter(),
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=build_detectors(),
    )

    with pytest.raises(TypeError):
        run(service, container)

    scans = container.scans.list_for_org("org-1")
    assert scans[0].status == "failed"
    assert scans[0].finished_at is not None
    # The account is not left locked out.
    assert container.scans.find_active_for_account("org-1", "acct-pk-1") is None


def test_unexpected_error_records_an_audit_event() -> None:
    class ExplodingAdapter(FakeAwsAdapter):
        def describe_volumes(self, credentials, *, region):  # type: ignore[no-untyped-def]
            raise TypeError("unexpected payload shape")

    container = build_container()
    service = ScanService(
        adapter=ExplodingAdapter(),
        scans=container.scans,
        resources=container.resources,
        findings=container.findings,
        audit=container.audit,
        detectors=build_detectors(),
    )

    with pytest.raises(TypeError):
        run(service, container)

    actions = [e.action for e in container.audit.list_for_org("org-1")]
    assert "scan.failed" in actions


# --- credential expiry ---------------------------------------------------


def test_expired_credentials_stop_the_scan_cleanly() -> None:
    """An expired session is reported once, not as one failure per call."""
    adapter = FakeAwsAdapter(volumes=[unattached_volume("vol-a")])
    service, container = make_service(adapter)

    expired = AwsCredentials(
        access_key_id="a",
        secret_access_key="b",
        session_token="c",
        expiration=datetime.now(UTC) - timedelta(minutes=5),
    )
    scan = container.scans.create(
        organization_id="org-1",
        aws_account_id="acct-pk-1",
        status="queued",
        started_at=None,
        finished_at=None,
        resource_count=0,
        finding_count=0,
        partial_failures=[],
        error_message=None,
        created_by="user-alice",
    )
    record = service.run_scan(
        organization_id="org-1",
        aws_account_id="acct-pk-1",
        account_id=ACCOUNT_ID,
        regions=["us-east-1", "eu-west-1"],
        credentials=expired,
        created_by="user-alice",
        scan_id=scan.id,
    )

    # Nothing was read, and the reason is stated plainly.
    assert record.status == "failed"
    assert record.partial_failures[0]["service"] == "sts"
    assert record.partial_failures[0]["code"] == ErrorCode.AWS_ASSUME_ROLE_FAILED
    # No AWS call was attempted with dead credentials.
    assert adapter.calls == []


def test_scan_records_attempt_count() -> None:
    """Attempts are counted so a retried scan is distinguishable from a new one."""
    adapter = FakeAwsAdapter(volumes=[unattached_volume()])
    service, container = make_service(adapter)
    record = run(service, container)
    assert record.attempts == 1
