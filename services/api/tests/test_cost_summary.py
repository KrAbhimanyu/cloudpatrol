"""Tests for the reported-spend endpoint.

The endpoint must never present a total that matches no invoice: not by
summing across billing periods, and not by adding different currencies.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.repositories.models import CostObservationRecord, new_id, utc_now


def _observation(  # type: ignore[no-untyped-def]
    container,
    *,
    org: str,
    account: str,
    service: str,
    amount: str,
    currency: str = "USD",
    period_start: str,
    period_end: str,
):
    return container.costs.add_many(
        [
            CostObservationRecord(
                id=new_id(),
                organization_id=org,
                aws_account_id=account,
                scan_id="scan-1",
                service=service,
                amount=Decimal(amount),
                currency=currency,
                period_start=period_start,
                period_end=period_end,
                created_at=utc_now(),
            )
        ]
    )


@pytest.fixture
def seeded(client, app, org_headers):  # type: ignore[no-untyped-def]
    """Two periods of cost data on one connected account."""
    container = app.state.container
    org = org_headers["X-Organization-Id"]
    account = container.aws_accounts.create(
        organization_id=org,
        created_by="user-1",
        label="Prod",
        account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/CloudPatrolReadOnly",
        regions=["us-east-1"],
        status="validated",
        status_message=None,
        last_validated_at=None,
        external_id_ref=None,
    )
    _observation(
        container,
        org=org,
        account=account.id,
        service="Amazon EC2",
        amount="100.00",
        period_start="2026-08-01",
        period_end="2026-09-01",
    )
    _observation(
        container,
        org=org,
        account=account.id,
        service="Amazon S3",
        amount="25.00",
        period_start="2026-09-01",
        period_end="2026-10-01",
    )
    return container, org, account.id


def test_the_total_covers_only_the_latest_period(client, org_headers, seeded) -> None:
    """Summing both months would report $125 for a $25 month."""
    _container, _org, account_id = seeded
    body = client.get(
        "/api/v1/costs/summary", headers=org_headers, params={"aws_account_id": account_id}
    ).json()

    assert body["available"] is True
    assert body["period_start"] == "2026-09-01"
    assert body["period_end"] == "2026-10-01"
    assert Decimal(body["total_amount"]) == Decimal("25.00")
    # Only the latest period's rows are returned.
    assert [row["service"] for row in body["by_service"]] == ["Amazon S3"]


def test_mixed_currencies_withhold_the_total(client, app, org_headers, seeded) -> None:
    """USD + EUR is not a sum, so no total is given."""
    container, org, account_id = seeded
    _observation(
        container,
        org=org,
        account=account_id,
        service="Amazon RDS",
        amount="10.00",
        currency="EUR",
        period_start="2026-09-01",
        period_end="2026-10-01",
    )

    body = client.get(
        "/api/v1/costs/summary", headers=org_headers, params={"aws_account_id": account_id}
    ).json()

    assert body["available"] is True
    assert body["total_amount"] is None
    # The rows are still shown, so the user can see what is there.
    assert len(body["by_service"]) == 2


def test_no_observations_reports_unavailable_not_zero(client, org_headers) -> None:
    """'We could not read the bill' is not 'the bill is $0'."""
    body = client.get("/api/v1/costs/summary", headers=org_headers).json()
    assert body["available"] is False
    assert body["total_amount"] is None


def test_costs_are_tenant_scoped(client, app, org_headers, seeded) -> None:
    """Another organization sees none of these observations."""
    other = client.post(
        "/api/v1/organizations",
        headers={"Authorization": "Bearer test-token-bob"},
        json={"name": "Globex", "slug": "globex"},
    )
    other_headers = {
        "Authorization": "Bearer test-token-bob",
        "X-Organization-Id": other.json()["id"],
    }
    body = client.get("/api/v1/costs/summary", headers=other_headers).json()
    assert body["available"] is False


def test_reported_spend_is_never_counted_as_a_saving(client, org_headers, seeded) -> None:
    """The savings endpoint must not include reported spend."""
    body = client.get("/api/v1/findings/summary/savings", headers=org_headers).json()
    assert Decimal(body["potential_monthly_savings"]) == Decimal("0.00")
    assert Decimal(body["verified_monthly_savings"]) == Decimal("0.00")
