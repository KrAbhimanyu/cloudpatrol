"""Tests for detector logic and savings arithmetic.

These exercise the real detectors over real ``ResourceSnapshotRecord`` objects
— no mocking. The point is to prove the detectors' *judgement*: that they
refuse to conclude anything from absent evidence, and that they never emit a
savings figure they cannot justify.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from app.repositories.models import ResourceSnapshotRecord, new_id, utc_now
from app.services.detectors.low_utilisation_ec2 import (
    LowUtilisationEc2Detector,
    summarise_cpu_datapoints,
)
from app.services.detectors.unassociated_eip import UnassociatedElasticIpDetector
from app.services.detectors.unattached_ebs import UnattachedEbsVolumeDetector
from app.services.pricing import PriceBook


def make_resource(
    resource_type: str,
    resource_id: str,
    *,
    state: str | None = None,
    attributes: dict | None = None,
    region: str = "us-east-1",
) -> ResourceSnapshotRecord:
    return ResourceSnapshotRecord(
        id=new_id(),
        organization_id="org-1",
        scan_id="scan-1",
        aws_account_id="123456789012",
        resource_type=resource_type,
        resource_id=resource_id,
        region=region,
        name=None,
        state=state,
        attributes=attributes or {},
        created_at=utc_now(),
    )


def cpu_datapoints(count: int, value: float) -> list[dict]:
    return [{"Average": value, "Maximum": value} for _ in range(count)]


# --- Unattached EBS ------------------------------------------------------


def test_unattached_volume_is_flagged() -> None:
    detector = UnattachedEbsVolumeDetector()
    findings = detector.detect(
        [
            make_resource(
                "ebs_volume",
                "vol-123",
                state="available",
                attributes={"size_gb": 100, "volume_type": "gp3"},
            )
        ]
    )
    assert len(findings) == 1
    assert findings[0].resource_id == "vol-123"
    assert findings[0].confidence in {"medium", "high"}


def test_attached_volume_is_not_flagged() -> None:
    detector = UnattachedEbsVolumeDetector()
    findings = detector.detect(
        [
            make_resource(
                "ebs_volume",
                "vol-attached",
                state="in-use",
                attributes={"size_gb": 100, "volume_type": "gp3"},
            )
        ]
    )
    assert findings == []


def test_unattached_volume_savings_uses_price_book() -> None:
    price_book = PriceBook(source="test-book", captured_on=datetime.now(UTC).date())
    detector = UnattachedEbsVolumeDetector(price_book=price_book)
    findings = detector.detect(
        [
            make_resource(
                "ebs_volume",
                "vol-100",
                state="available",
                attributes={"size_gb": 100, "volume_type": "gp3"},
            )
        ]
    )
    # 100 GiB * 0.08 per GB-month = 8.00
    assert findings[0].estimated_monthly_savings == Decimal("8.00")


def test_unknown_volume_type_yields_no_savings_figure() -> None:
    detector = UnattachedEbsVolumeDetector()
    findings = detector.detect(
        [
            make_resource(
                "ebs_volume",
                "vol-unknown",
                state="available",
                attributes={"size_gb": 50, "volume_type": "io2-unknown-tier"},
            )
        ]
    )
    # No price is known, so no number is emitted. Guessing would be worse.
    assert findings[0].estimated_monthly_savings is None


def test_old_unattached_volume_has_higher_confidence() -> None:
    old = (datetime.now(UTC) - timedelta(days=90)).isoformat()
    detector = UnattachedEbsVolumeDetector()
    findings = detector.detect(
        [
            make_resource(
                "ebs_volume",
                "vol-old",
                state="available",
                attributes={"size_gb": 10, "volume_type": "gp3", "create_time": old},
            )
        ]
    )
    assert findings[0].confidence == "high"
    assert findings[0].evidence["age_days"] >= 89


def test_retention_tagged_volume_is_low_confidence() -> None:
    detector = UnattachedEbsVolumeDetector()
    findings = detector.detect(
        [
            make_resource(
                "ebs_volume",
                "vol-tagged",
                state="available",
                attributes={
                    "size_gb": 10,
                    "volume_type": "gp3",
                    "tags": {"backup": "true"},
                },
            )
        ]
    )
    assert findings[0].confidence == "low"
    assert findings[0].evidence["retention_tag_present"] is True


def test_evidence_records_price_source() -> None:
    detector = UnattachedEbsVolumeDetector()
    findings = detector.detect(
        [
            make_resource(
                "ebs_volume",
                "vol-ev",
                state="available",
                attributes={"size_gb": 10, "volume_type": "gp3"},
            )
        ]
    )
    evidence = findings[0].evidence
    assert evidence["price_source"]
    assert evidence["price_captured_on"]
    assert evidence["assumption"]


# --- Unassociated Elastic IP --------------------------------------------


def test_unassociated_eip_is_flagged() -> None:
    detector = UnassociatedElasticIpDetector()
    findings = detector.detect(
        [make_resource("elastic_ip", "eipalloc-1", state="unassociated", attributes={})]
    )
    assert len(findings) == 1
    assert findings[0].estimated_monthly_savings is not None


def test_associated_eip_is_not_flagged() -> None:
    detector = UnassociatedElasticIpDetector()
    findings = detector.detect(
        [
            make_resource(
                "elastic_ip",
                "eipalloc-2",
                state="associated",
                attributes={"association_id": "eipassoc-1", "public_ip": "203.0.113.10"},
            )
        ]
    )
    assert findings == []


def test_eip_savings_is_hourly_rate_times_month_hours() -> None:
    price_book = PriceBook(source="test", captured_on=datetime.now(UTC).date())
    detector = UnassociatedElasticIpDetector(price_book=price_book)
    findings = detector.detect([make_resource("elastic_ip", "eip-x", state="unassociated")])
    expected = (price_book.elastic_ip_per_hour * price_book.hours_per_month).quantize(
        Decimal("0.01")
    )
    assert findings[0].estimated_monthly_savings == expected


# --- Low utilisation EC2 ------------------------------------------------


def test_low_cpu_instance_is_flagged() -> None:
    detector = LowUtilisationEc2Detector()
    findings = detector.detect(
        [
            make_resource(
                "ec2_instance",
                "i-low",
                state="running",
                attributes={
                    "instance_type": "m5.large",
                    "cpu_datapoints": cpu_datapoints(20, 1.5),
                },
            )
        ]
    )
    assert len(findings) == 1
    assert findings[0].evidence["average_cpu_percent"] == "1.50"


def test_busy_instance_is_not_flagged() -> None:
    detector = LowUtilisationEc2Detector()
    findings = detector.detect(
        [
            make_resource(
                "ec2_instance",
                "i-busy",
                state="running",
                attributes={
                    "instance_type": "m5.large",
                    "cpu_datapoints": cpu_datapoints(20, 65.0),
                },
            )
        ]
    )
    assert findings == []


def test_instance_with_no_metrics_is_not_flagged() -> None:
    """Absent metrics are not evidence of idleness."""
    detector = LowUtilisationEc2Detector()
    findings = detector.detect(
        [
            make_resource(
                "ec2_instance",
                "i-nometrics",
                state="running",
                attributes={"instance_type": "m5.large", "cpu_datapoints": []},
            )
        ]
    )
    assert findings == []


def test_instance_with_too_few_datapoints_is_not_flagged() -> None:
    """A couple of datapoints is not a trend."""
    detector = LowUtilisationEc2Detector()
    findings = detector.detect(
        [
            make_resource(
                "ec2_instance",
                "i-sparse",
                state="running",
                attributes={"instance_type": "m5.large", "cpu_datapoints": cpu_datapoints(3, 0.1)},
            )
        ]
    )
    assert findings == []


def test_stopped_instance_is_not_flagged() -> None:
    detector = LowUtilisationEc2Detector()
    findings = detector.detect(
        [
            make_resource(
                "ec2_instance",
                "i-stopped",
                state="stopped",
                attributes={"instance_type": "m5.large", "cpu_datapoints": cpu_datapoints(20, 0.0)},
            )
        ]
    )
    assert findings == []


def test_ec2_detector_emits_no_savings_figure() -> None:
    """Rightsizing needs a target price, which is not collected in this phase."""
    detector = LowUtilisationEc2Detector()
    findings = detector.detect(
        [
            make_resource(
                "ec2_instance",
                "i-noprice",
                state="running",
                attributes={"instance_type": "m5.large", "cpu_datapoints": cpu_datapoints(20, 1.0)},
            )
        ]
    )
    assert findings[0].estimated_monthly_savings is None


def test_summarise_cpu_handles_missing_average() -> None:
    metrics = summarise_cpu_datapoints([{"Maximum": 10.0}, {"Maximum": 20.0}], window_days=14)
    assert metrics.average_cpu_percent == Decimal("15.00")
    assert metrics.datapoint_count == 2


def test_summarise_cpu_ignores_empty_datapoints() -> None:
    metrics = summarise_cpu_datapoints([{}, {}], window_days=14)
    assert metrics.average_cpu_percent is None
    assert metrics.datapoint_count == 0


# --- dedupe keys ---------------------------------------------------------


def test_dedupe_key_is_stable_across_scans() -> None:
    detector = UnattachedEbsVolumeDetector()
    resources = [
        make_resource(
            "ebs_volume",
            "vol-dup",
            state="available",
            attributes={"size_gb": 5, "volume_type": "gp3"},
        )
    ]
    first = detector.detect(resources)[0]
    second = detector.detect(resources)[0]
    assert first.dedupe_key(aws_account_id="123456789012") == second.dedupe_key(
        aws_account_id="123456789012"
    )


def test_dedupe_key_differs_between_accounts() -> None:
    detector = UnattachedEbsVolumeDetector()
    finding = detector.detect(
        [
            make_resource(
                "ebs_volume",
                "vol-shared",
                state="available",
                attributes={"size_gb": 5, "volume_type": "gp3"},
            )
        ]
    )[0]
    assert finding.dedupe_key(aws_account_id="111111111111") != finding.dedupe_key(
        aws_account_id="222222222222"
    )
