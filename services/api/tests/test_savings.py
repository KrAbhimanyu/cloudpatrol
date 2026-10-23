"""Tests for savings aggregation and the estimated/verified distinction."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from app.repositories.models import FindingRecord, new_id
from app.services.savings import summarise_savings


def make_finding(
    *,
    state: str = "estimated",
    amount: Decimal | None = Decimal("10.00"),
    detector: str = "unattached_ebs_volume",
) -> FindingRecord:
    return FindingRecord(
        id=new_id(),
        organization_id="org-1",
        scan_id="scan-1",
        aws_account_id="123456789012",
        detector=detector,
        resource_type="ebs_volume",
        resource_id=new_id(),
        region="us-east-1",
        severity="medium",
        confidence="high",
        state=state,
        title="t",
        summary="s",
        evidence={},
        recommended_action="a",
        estimated_monthly_savings=amount,
        currency="USD",
        dedupe_key=new_id(),
        created_at=datetime.now(UTC),
    )


def test_estimated_findings_count_as_potential_not_verified() -> None:
    summary = summarise_savings([make_finding(state="estimated", amount=Decimal("25.50"))])
    assert summary.potential_monthly_savings == Decimal("25.50")
    # Nothing has been changed, so nothing has been verified.
    assert summary.verified_monthly_savings == Decimal("0.00")


def test_verified_savings_are_separate_from_potential() -> None:
    summary = summarise_savings(
        [
            make_finding(state="estimated", amount=Decimal("10.00")),
            make_finding(state="verified", amount=Decimal("7.25")),
        ]
    )
    assert summary.potential_monthly_savings == Decimal("10.00")
    assert summary.verified_monthly_savings == Decimal("7.25")
    assert summary.open_finding_count == 1
    assert summary.verified_finding_count == 1


def test_dismissed_findings_are_excluded() -> None:
    summary = summarise_savings(
        [
            make_finding(state="dismissed", amount=Decimal("99.00")),
            make_finding(state="estimated", amount=Decimal("1.00")),
        ]
    )
    assert summary.potential_monthly_savings == Decimal("1.00")
    assert summary.dismissed_finding_count == 1


def test_findings_without_estimate_are_counted_not_treated_as_zero() -> None:
    summary = summarise_savings(
        [
            make_finding(state="estimated", amount=None),
            make_finding(state="estimated", amount=Decimal("5.00")),
        ]
    )
    assert summary.potential_monthly_savings == Decimal("5.00")
    assert summary.findings_without_estimate == 1
    assert summary.open_finding_count == 2


def test_annualised_is_twelve_times_monthly() -> None:
    summary = summarise_savings([make_finding(amount=Decimal("12.34"))])
    assert summary.annualised_potential_savings == Decimal("148.08")


def test_totals_are_rounded_to_cents() -> None:
    summary = summarise_savings(
        [make_finding(amount=Decimal("0.005")), make_finding(amount=Decimal("0.005"))]
    )
    # 0.01 total, rounded once at the end rather than per item.
    assert summary.potential_monthly_savings == Decimal("0.01")


def test_savings_grouped_by_detector() -> None:
    summary = summarise_savings(
        [
            make_finding(amount=Decimal("3.00"), detector="unattached_ebs_volume"),
            make_finding(amount=Decimal("2.00"), detector="unattached_ebs_volume"),
            make_finding(amount=Decimal("1.00"), detector="unassociated_elastic_ip"),
        ]
    )
    assert summary.monthly_savings_by_detector["unattached_ebs_volume"] == Decimal("5.00")
    assert summary.monthly_savings_by_detector["unassociated_elastic_ip"] == Decimal("1.00")


def test_empty_findings_summary_is_zeroed() -> None:
    summary = summarise_savings([])
    assert summary.potential_monthly_savings == Decimal("0.00")
    assert summary.verified_monthly_savings == Decimal("0.00")
    assert summary.open_finding_count == 0


def test_summary_serialises_decimals_as_strings() -> None:
    payload = summarise_savings([make_finding(amount=Decimal("1.50"))]).as_dict()
    # Strings avoid float rounding artefacts crossing the API boundary.
    assert payload["potential_monthly_savings"] == "1.50"
    assert isinstance(payload["monthly_savings_by_detector"]["unattached_ebs_volume"], str)
