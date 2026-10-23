"""Billing ingestion tests.

The property under test: billing data is separate from inventory, and a missing
Cost Explorer permission produces an honest "unavailable", never a zero bill.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest

from app.aws.adapter import AwsCredentials
from app.core.errors import ErrorCode
from app.repositories.memory import build_container
from app.services.billing import BillingService, is_billing_permission_denied
from tests.fake_aws import FakeAwsAdapter, FakeAwsError


def credentials() -> AwsCredentials:
    return AwsCredentials(
        access_key_id="AKIAEXAMPLE",
        secret_access_key="secret",
        session_token="token",
        expiration=None,  # type: ignore[arg-type]
    )


def group(service: str, amount: str, unit: str = "USD") -> dict:  # type: ignore[type-arg]
    return {
        "Keys": [service],
        "Metrics": {"UnblendedCost": {"Amount": amount, "Unit": unit}},
    }


def test_observations_are_normalised_per_service() -> None:
    adapter = FakeAwsAdapter(
        cost_groups=[
            group("Amazon Elastic Compute Cloud - Compute", "120.50"),
            group("Amazon Simple Storage Service", "9.25"),
        ]
    )
    service = BillingService(adapter)
    result = service.collect(
        credentials(),
        organization_id="org-1",
        aws_account_id="acct-1",
        scan_id="scan-1",
    )

    assert result.failure is None
    assert len(result.observations) == 2
    assert result.total_amount == Decimal("129.75")
    services = {o.service for o in result.observations}
    assert "Amazon Elastic Compute Cloud - Compute" in services


def test_a_denied_permission_is_a_failure_not_zero_spend() -> None:
    """The critical honesty property.

    A missing ``ce:GetCostAndUsage`` must not be reported as a $0 bill. The
    failure is returned so the caller can record it; no observation is written.
    """
    adapter = FakeAwsAdapter()
    adapter.fail_on["ce"] = FakeAwsError(
        "Not authorized to perform ce:GetCostAndUsage",
        code=ErrorCode.AWS_PERMISSION_DENIED,
    )
    service = BillingService(adapter)

    result = service.collect(
        credentials(),
        organization_id="org-1",
        aws_account_id="acct-1",
        scan_id="scan-1",
    )

    assert result.observations == []
    assert result.failure is not None
    assert result.failure["service"] == "ce"
    # The caller must be able to tell this apart from a genuine zero.
    assert is_billing_permission_denied(result.failure["code"])


def test_no_groups_but_a_total_is_recorded() -> None:
    """A call without GroupBy returns only a Total; the figure must not be lost."""
    adapter = FakeAwsAdapter()
    adapter.get_cost_and_usage = lambda *a, **k: [  # type: ignore[assignment,method-assign]
        {
            "TimePeriod": {"Start": "2026-01-01", "End": "2026-02-01"},
            "Total": {"UnblendedCost": {"Amount": "42.00", "Unit": "USD"}},
        }
    ]
    service = BillingService(adapter)
    result = service.collect(
        credentials(), organization_id="org-1", aws_account_id="acct-1", scan_id="s1"
    )

    assert len(result.observations) == 1
    assert result.observations[0].service == "__total__"
    assert result.observations[0].amount == Decimal("42.00")


def test_an_unparsable_amount_is_skipped_not_guessed() -> None:
    """A fabricated figure is worse than a missing one."""
    adapter = FakeAwsAdapter(
        cost_groups=[
            {"Keys": ["EC2"], "Metrics": {"UnblendedCost": {"Amount": "not-a-number"}}},
            group("S3", "5.00"),
        ]
    )
    service = BillingService(adapter)
    result = service.collect(
        credentials(), organization_id="org-1", aws_account_id="acct-1", scan_id="s1"
    )

    assert len(result.observations) == 1
    assert result.observations[0].service == "S3"


def test_a_result_without_a_time_period_is_skipped() -> None:
    adapter = FakeAwsAdapter()
    adapter.get_cost_and_usage = lambda *a, **k: [  # type: ignore[assignment,method-assign]
        {"Groups": [group("EC2", "10.00")]}
    ]
    service = BillingService(adapter)
    result = service.collect(
        credentials(), organization_id="org-1", aws_account_id="acct-1", scan_id="s1"
    )
    assert result.observations == []


def test_currency_is_carried_from_the_response() -> None:
    adapter = FakeAwsAdapter(cost_groups=[group("EC2", "10.00", unit="EUR")])
    service = BillingService(adapter)
    result = service.collect(
        credentials(), organization_id="org-1", aws_account_id="acct-1", scan_id="s1"
    )
    assert result.observations[0].currency == "EUR"


def test_the_lookback_window_is_applied() -> None:
    seen: dict[str, str] = {}

    def capture(credentials, *, start_date, end_date):  # type: ignore[no-untyped-def]
        seen["start"] = start_date
        seen["end"] = end_date
        return []

    adapter = FakeAwsAdapter()
    adapter.get_cost_and_usage = capture  # type: ignore[assignment,method-assign]
    service = BillingService(adapter)
    service.collect(
        credentials(),
        organization_id="org-1",
        aws_account_id="acct-1",
        scan_id="s1",
        lookback_days=7,
        today=date(2026, 3, 10),
    )

    assert seen["end"] == "2026-03-10"
    assert seen["start"] == "2026-03-03"


# --- repository ----------------------------------------------------------


def test_cost_repository_dedupes_across_a_rescan() -> None:
    """A re-scanned account must not report twice its real cost."""
    from app.repositories.models import CostObservationRecord, new_id, utc_now

    container = build_container()

    def record() -> CostObservationRecord:
        return CostObservationRecord(
            id=new_id(),
            organization_id="org-1",
            aws_account_id="acct-1",
            scan_id="scan-1",
            service="EC2",
            amount=Decimal("100.00"),
            currency="USD",
            period_start="2026-01-01",
            period_end="2026-02-01",
            created_at=utc_now(),
        )

    assert container.costs.add_many([record()]) == 1
    # Same (account, scan, service, period) — a duplicate must be rejected.
    assert container.costs.add_many([record()]) == 0
    assert len(container.costs.list_for_org("org-1")) == 1


def test_cost_repository_is_organization_scoped() -> None:
    from app.repositories.models import CostObservationRecord, new_id, utc_now

    container = build_container()
    container.costs.add_many(
        [
            CostObservationRecord(
                id=new_id(),
                organization_id="org-1",
                aws_account_id="acct-1",
                scan_id="s1",
                service="EC2",
                amount=Decimal("1.00"),
                currency="USD",
                period_start="2026-01-01",
                period_end="2026-02-01",
                created_at=utc_now(),
            )
        ]
    )
    assert container.costs.list_for_org("org-2") == []


def test_a_failure_code_from_a_non_denial_is_not_treated_as_denied() -> None:
    assert not is_billing_permission_denied("aws_throttled")


@pytest.mark.parametrize("amount,expected", [("0", Decimal("0")), ("1.005", Decimal("1.005"))])
def test_zero_cost_is_still_an_observation(amount: str, expected: Decimal) -> None:
    """A genuine zero differs from an unavailable bill and is kept."""
    adapter = FakeAwsAdapter(cost_groups=[group("EC2", amount)])
    service = BillingService(adapter)
    result = service.collect(
        credentials(), organization_id="org-1", aws_account_id="acct-1", scan_id="s1"
    )
    assert result.observations[0].amount == expected
