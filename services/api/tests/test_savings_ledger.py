"""Savings ledger tests.

The ledger exists to stop an estimate being read as money. These tests attack
that property directly: they try to skip the workflow, to verify without
evidence, to double-count across scans, and to leave a dismissed opportunity in
the potential total.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.repositories.memory import build_container
from app.repositories.models import FindingRecord, new_id, utc_now
from app.services.savings_ledger import (
    BASIS_APPROVED,
    BASIS_IMPLEMENTED,
    BASIS_INCONCLUSIVE,
    BASIS_POTENTIAL,
    BASIS_VERIFIED,
    SavingsLedgerService,
    summarise_ledger,
)

ORG = "org-1"
ACCOUNT = "acct-pk-1"
ACTOR = "user-alice"


@pytest.fixture
def container():  # type: ignore[no-untyped-def]
    return build_container()


@pytest.fixture
def service(container):  # type: ignore[no-untyped-def]
    return SavingsLedgerService(
        savings=container.savings,
        findings=container.findings,
        audit=container.audit,
    )


def make_finding(
    container,  # type: ignore[no-untyped-def]
    *,
    amount: Decimal | None = Decimal("100.00"),
    resource_id: str = "vol-1",
    detector: str = "unattached_ebs_volume",
) -> FindingRecord:
    """Persist a finding directly, bypassing the scan path."""
    record = FindingRecord(
        id=new_id(),
        organization_id=ORG,
        scan_id="scan-1",
        aws_account_id=ACCOUNT,
        detector=detector,
        resource_type="ebs_volume",
        resource_id=resource_id,
        region="us-east-1",
        severity="medium",
        confidence="high",
        state="estimated",
        title="t",
        summary="s",
        evidence={},
        recommended_action="a",
        estimated_monthly_savings=amount,
        currency="USD",
        dedupe_key=f"{ACCOUNT}:{detector}:us-east-1:{resource_id}:x",
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    container.findings.upsert_many([record])
    return container.findings.get(ORG, record.id)  # type: ignore[return-value]


# --- recording potential -------------------------------------------------


def test_a_priced_finding_becomes_a_potential_entry(container, service) -> None:  # type: ignore[no-untyped-def]
    finding = make_finding(container)
    record = service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)

    assert record is not None
    assert record.basis == BASIS_POTENTIAL
    assert record.monthly_amount == Decimal("100.00")


def test_a_finding_with_no_price_creates_no_entry(container, service) -> None:  # type: ignore[no-untyped-def]
    """No figure means no ledger row — never a zero.

    A zero would assert "this saves nothing", which is a different and stronger
    claim than "we could not price this".
    """
    finding = make_finding(container, amount=None)
    assert (
        service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR) is None
    )
    assert service.list_entries(ORG) == []


def test_recording_potential_twice_does_not_double_count(container, service) -> None:  # type: ignore[no-untyped-def]
    """A re-scan must not inflate the potential total."""
    finding = make_finding(container)
    first = service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)
    second = service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)

    assert first is not None and second is not None
    assert first.id == second.id
    assert len(service.list_entries(ORG)) == 1
    assert service.summary(ORG).potential_monthly_savings == Decimal("100.00")


def test_two_findings_sum(container, service) -> None:  # type: ignore[no-untyped-def]
    a = make_finding(container, amount=Decimal("10.00"), resource_id="vol-1")
    b = make_finding(container, amount=Decimal("15.50"), resource_id="vol-2")
    service.record_potential(organization_id=ORG, finding=a, actor_user_id=ACTOR)
    service.record_potential(organization_id=ORG, finding=b, actor_user_id=ACTOR)

    assert service.summary(ORG).potential_monthly_savings == Decimal("25.50")


# --- workflow transitions ------------------------------------------------


def test_the_full_workflow_reaches_verified(container, service) -> None:  # type: ignore[no-untyped-def]
    finding = make_finding(container)
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)

    service.advance(
        organization_id=ORG, finding_id=finding.id, target_basis=BASIS_APPROVED, actor_user_id=ACTOR
    )
    service.advance(
        organization_id=ORG,
        finding_id=finding.id,
        target_basis=BASIS_IMPLEMENTED,
        actor_user_id=ACTOR,
    )
    record = service.advance(
        organization_id=ORG,
        finding_id=finding.id,
        target_basis=BASIS_VERIFIED,
        actor_user_id=ACTOR,
        monthly_amount=Decimal("87.00"),
        evidence={"method": "Cost Explorer before/after"},
        measured_from=datetime.now(UTC) - timedelta(days=30),
        measured_to=datetime.now(UTC),
    )

    assert record.basis == BASIS_VERIFIED
    # The measured figure, not the original estimate.
    assert record.monthly_amount == Decimal("87.00")

    summary = service.summary(ORG)
    assert summary.verified_monthly_savings == Decimal("87.00")
    assert summary.potential_monthly_savings == Decimal("0.00")


def test_potential_cannot_jump_straight_to_verified(container, service) -> None:  # type: ignore[no-untyped-def]
    """Skipping the workflow would assert a measurement that never happened."""
    finding = make_finding(container)
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)

    with pytest.raises(ConflictError) as excinfo:
        service.advance(
            organization_id=ORG,
            finding_id=finding.id,
            target_basis=BASIS_VERIFIED,
            actor_user_id=ACTOR,
            monthly_amount=Decimal("50"),
            evidence={"method": "x"},
            measured_from=datetime.now(UTC) - timedelta(days=1),
            measured_to=datetime.now(UTC),
        )
    assert excinfo.value.details["current_basis"] == BASIS_POTENTIAL


def test_verified_requires_evidence(container, service) -> None:  # type: ignore[no-untyped-def]
    finding = make_finding(container)
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)
    service.advance(
        organization_id=ORG, finding_id=finding.id, target_basis=BASIS_APPROVED, actor_user_id=ACTOR
    )
    service.advance(
        organization_id=ORG,
        finding_id=finding.id,
        target_basis=BASIS_IMPLEMENTED,
        actor_user_id=ACTOR,
    )

    with pytest.raises(ValidationError) as excinfo:
        service.advance(
            organization_id=ORG,
            finding_id=finding.id,
            target_basis=BASIS_VERIFIED,
            actor_user_id=ACTOR,
            monthly_amount=Decimal("50"),
            measured_from=datetime.now(UTC) - timedelta(days=1),
            measured_to=datetime.now(UTC),
        )
    assert "evidence" in excinfo.value.details["missing"]


def test_verified_requires_a_measurement_window(container, service) -> None:  # type: ignore[no-untyped-def]
    finding = make_finding(container)
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)
    service.advance(
        organization_id=ORG, finding_id=finding.id, target_basis=BASIS_APPROVED, actor_user_id=ACTOR
    )
    service.advance(
        organization_id=ORG,
        finding_id=finding.id,
        target_basis=BASIS_IMPLEMENTED,
        actor_user_id=ACTOR,
    )

    with pytest.raises(ValidationError) as excinfo:
        service.advance(
            organization_id=ORG,
            finding_id=finding.id,
            target_basis=BASIS_VERIFIED,
            actor_user_id=ACTOR,
            monthly_amount=Decimal("50"),
            evidence={"method": "x"},
        )
    assert "measurement_window" in excinfo.value.details["missing"]


def test_verified_requires_a_measured_amount_not_the_estimate(container, service) -> None:  # type: ignore[no-untyped-def]
    """Falling back to the estimate would relabel a guess as a measurement."""
    finding = make_finding(container, amount=Decimal("100.00"))
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)
    service.advance(
        organization_id=ORG, finding_id=finding.id, target_basis=BASIS_APPROVED, actor_user_id=ACTOR
    )
    service.advance(
        organization_id=ORG,
        finding_id=finding.id,
        target_basis=BASIS_IMPLEMENTED,
        actor_user_id=ACTOR,
    )

    with pytest.raises(ValidationError):
        service.advance(
            organization_id=ORG,
            finding_id=finding.id,
            target_basis=BASIS_VERIFIED,
            actor_user_id=ACTOR,
            evidence={"method": "x"},
            measured_from=datetime.now(UTC) - timedelta(days=1),
            measured_to=datetime.now(UTC),
        )


def test_a_measurement_that_proves_nothing_is_inconclusive(container, service) -> None:  # type: ignore[no-untyped-def]
    """A failed verification must be recordable, not silently dropped."""
    finding = make_finding(container)
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)
    service.advance(
        organization_id=ORG, finding_id=finding.id, target_basis=BASIS_APPROVED, actor_user_id=ACTOR
    )
    service.advance(
        organization_id=ORG,
        finding_id=finding.id,
        target_basis=BASIS_IMPLEMENTED,
        actor_user_id=ACTOR,
    )
    record = service.advance(
        organization_id=ORG,
        finding_id=finding.id,
        target_basis=BASIS_INCONCLUSIVE,
        actor_user_id=ACTOR,
        monthly_amount=Decimal("0"),
        evidence={"method": "Cost Explorer before/after", "delta": "0.00"},
    )

    assert record.basis == BASIS_INCONCLUSIVE
    summary = service.summary(ORG)
    assert summary.inconclusive_count == 1
    # Critically: nothing landed in the verified bucket.
    assert summary.verified_monthly_savings == Decimal("0.00")
    assert summary.potential_monthly_savings == Decimal("0.00")


def test_terminal_bases_cannot_move_again(container, service) -> None:  # type: ignore[no-untyped-def]
    finding = make_finding(container)
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)
    service.advance(
        organization_id=ORG, finding_id=finding.id, target_basis=BASIS_APPROVED, actor_user_id=ACTOR
    )
    service.advance(
        organization_id=ORG,
        finding_id=finding.id,
        target_basis=BASIS_IMPLEMENTED,
        actor_user_id=ACTOR,
    )
    service.advance(
        organization_id=ORG,
        finding_id=finding.id,
        target_basis=BASIS_INCONCLUSIVE,
        actor_user_id=ACTOR,
        monthly_amount=Decimal("0"),
    )

    # inconclusive is terminal: it cannot be promoted to verified later.
    with pytest.raises(ConflictError):
        service.advance(
            organization_id=ORG,
            finding_id=finding.id,
            target_basis=BASIS_VERIFIED,
            actor_user_id=ACTOR,
            monthly_amount=Decimal("10"),
            evidence={"method": "x"},
            measured_from=datetime.now(UTC) - timedelta(days=1),
            measured_to=datetime.now(UTC),
        )


def test_advancing_a_finding_with_no_entry_conflicts(container, service) -> None:  # type: ignore[no-untyped-def]
    finding = make_finding(container, amount=None)
    with pytest.raises(ConflictError):
        service.advance(
            organization_id=ORG,
            finding_id=finding.id,
            target_basis=BASIS_APPROVED,
            actor_user_id=ACTOR,
        )


def test_advancing_an_unknown_finding_is_not_found(service) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(NotFoundError):
        service.advance(
            organization_id=ORG,
            finding_id="does-not-exist",
            target_basis=BASIS_APPROVED,
            actor_user_id=ACTOR,
        )


# --- withdrawal and isolation --------------------------------------------


def test_dismissing_withdraws_the_potential_entry(container, service) -> None:  # type: ignore[no-untyped-def]
    finding = make_finding(container)
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)
    assert service.summary(ORG).potential_monthly_savings == Decimal("100.00")

    assert service.withdraw(organization_id=ORG, finding_id=finding.id, actor_user_id=ACTOR)
    assert service.summary(ORG).potential_monthly_savings == Decimal("0.00")


def test_withdrawing_twice_is_harmless(container, service) -> None:  # type: ignore[no-untyped-def]
    finding = make_finding(container)
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)
    assert service.withdraw(organization_id=ORG, finding_id=finding.id, actor_user_id=ACTOR)
    assert not service.withdraw(organization_id=ORG, finding_id=finding.id, actor_user_id=ACTOR)


def test_another_organization_sees_nothing(container, service) -> None:  # type: ignore[no-untyped-def]
    finding = make_finding(container)
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)

    assert service.list_entries("org-other") == []
    assert service.summary("org-other").potential_monthly_savings == Decimal("0.00")


def test_audit_events_are_written(container, service) -> None:  # type: ignore[no-untyped-def]
    finding = make_finding(container)
    service.record_potential(organization_id=ORG, finding=finding, actor_user_id=ACTOR)
    service.advance(
        organization_id=ORG, finding_id=finding.id, target_basis=BASIS_APPROVED, actor_user_id=ACTOR
    )

    actions = [e.action for e in container.audit.list_for_org(ORG)]
    assert "savings.potential_recorded" in actions
    assert "savings.approved" in actions


# --- summarisation -------------------------------------------------------


def test_summary_never_combines_potential_and_verified(container, service) -> None:  # type: ignore[no-untyped-def]
    """The whole point: the two ledgers are reported apart."""
    priced = make_finding(container, amount=Decimal("100.00"), resource_id="vol-1")
    unpriced = make_finding(container, amount=None, resource_id="vol-2")
    service.record_potential(organization_id=ORG, finding=priced, actor_user_id=ACTOR)
    assert (
        service.record_potential(organization_id=ORG, finding=unpriced, actor_user_id=ACTOR) is None
    )

    payload = service.summary(ORG).as_dict()
    assert payload["potential_monthly_savings"] == "100.00"
    assert payload["verified_monthly_savings"] == "0.00"
    # There is no combined field to misread.
    assert "total_savings" not in payload


def test_legacy_estimated_basis_maps_to_potential() -> None:
    """0001 named the bucket 'estimated'; an existing row must still count."""
    from app.repositories.models import SavingsRecord

    record = SavingsRecord(
        id="s1",
        organization_id=ORG,
        aws_account_id=ACCOUNT,
        finding_id="f1",
        basis="estimated",
        monthly_amount=Decimal("42.00"),
        currency="USD",
        evidence=None,
        measured_from=None,
        measured_to=None,
        created_by=None,
        created_at=utc_now(),
    )
    summary = summarise_ledger([record])
    assert summary.potential_monthly_savings == Decimal("42.00")
    assert summary.potential_count == 1
