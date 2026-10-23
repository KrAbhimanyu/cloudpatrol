"""The savings ledger: what was found, decided, done, and *proven*.

The single rule this module exists to enforce: an estimate is never money that
has been saved. Five bases are kept strictly apart, because collapsing any two
of them produces a number that misleads the person reading it.

    potential    an estimate derived from a finding. Opportunity, not money.
    approved     a human decided to act. Still not money.
    implemented  the change was made. Still not *proven* money.
    verified     measured after the change, with evidence and a window. Money.
    inconclusive a measurement was attempted and proved nothing. Not money.

Two invariants are enforced here rather than trusted to callers:

1. **A verified entry requires evidence and a measurement window.** Without
   them, "verified" is just an estimate wearing a confident label. The database
   enforces the same rule, so the in-memory and SQL paths cannot diverge.
2. **A finding contributes at most one entry per basis.** Re-running a scan, or
   approving an already-approved finding, must not create a second row that
   gets summed into the same total.

Progression is one-directional. ``potential`` may advance to ``approved``,
``approved`` to ``implemented``, and ``implemented`` to ``verified`` or
``inconclusive``. Nothing moves backwards, and nothing skips straight from
``potential`` to ``verified``, because that would assert a measurement that
never happened.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.repositories.models import FindingRecord, SavingsRecord
from app.repositories.protocols import (
    AuditRepository,
    FindingRepository,
    SavingsRepository,
)

logger = logging.getLogger(__name__)

# The ledger buckets, in workflow order.
BASIS_POTENTIAL = "potential"
BASIS_APPROVED = "approved"
BASIS_IMPLEMENTED = "implemented"
BASIS_VERIFIED = "verified"
BASIS_INCONCLUSIVE = "inconclusive"

BASES: tuple[str, ...] = (
    BASIS_POTENTIAL,
    BASIS_APPROVED,
    BASIS_IMPLEMENTED,
    BASIS_VERIFIED,
    BASIS_INCONCLUSIVE,
)

# Bases that represent money actually realised. Exactly one.
_REALISED_BASES = frozenset({BASIS_VERIFIED})

# Legal forward transitions. A terminal basis has no entry, so it cannot move.
_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    BASIS_POTENTIAL: frozenset({BASIS_APPROVED}),
    BASIS_APPROVED: frozenset({BASIS_IMPLEMENTED}),
    BASIS_IMPLEMENTED: frozenset({BASIS_VERIFIED, BASIS_INCONCLUSIVE}),
    BASIS_VERIFIED: frozenset(),
    BASIS_INCONCLUSIVE: frozenset(),
}

# Bases where a figure is required and must be positive.
_PRICED_BASES = frozenset({BASIS_POTENTIAL, BASIS_APPROVED, BASIS_IMPLEMENTED})

# Mapping from the legacy schema value. 0001 named the estimate bucket
# 'estimated'; the ledger calls it 'potential'. Both are accepted on read so an
# existing row is not orphaned.
_BASIS_ALIASES = {"estimated": BASIS_POTENTIAL}


def normalise_basis(value: str) -> str:
    """Map a stored basis onto its canonical ledger name."""
    return _BASIS_ALIASES.get(value, value)


@dataclass(frozen=True, slots=True)
class SavingsLedgerSummary:
    """Totals per basis, plus the single realised figure.

    ``potential_monthly_savings`` and ``verified_monthly_savings`` are separate
    fields, never one combined number, because adding them would state that an
    opportunity is as good as a saving.
    """

    currency: str
    potential_monthly_savings: Decimal
    approved_monthly_savings: Decimal
    implemented_monthly_savings: Decimal
    verified_monthly_savings: Decimal
    inconclusive_monthly_savings: Decimal
    potential_count: int
    approved_count: int
    implemented_count: int
    verified_count: int
    inconclusive_count: int
    annualised_verified_savings: Decimal

    def as_dict(self) -> dict[str, object]:
        return {
            "currency": self.currency,
            "potential_monthly_savings": str(self.potential_monthly_savings),
            "approved_monthly_savings": str(self.approved_monthly_savings),
            "implemented_monthly_savings": str(self.implemented_monthly_savings),
            "verified_monthly_savings": str(self.verified_monthly_savings),
            "inconclusive_monthly_savings": str(self.inconclusive_monthly_savings),
            "potential_count": self.potential_count,
            "approved_count": self.approved_count,
            "implemented_count": self.implemented_count,
            "verified_count": self.verified_count,
            "inconclusive_count": self.inconclusive_count,
            "annualised_verified_savings": str(self.annualised_verified_savings),
        }


def _quantise(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def summarise_ledger(records: list[SavingsRecord]) -> SavingsLedgerSummary:
    """Sum each basis separately.

    Amounts are summed per basis and rounded once at the end, so repeated
    rounding cannot accumulate a drift between the parts and the total.
    """
    totals: dict[str, Decimal] = {basis: Decimal("0") for basis in BASES}
    counts: dict[str, int] = dict.fromkeys(BASES, 0)
    currency = "USD"

    for record in records:
        basis = normalise_basis(record.basis)
        if basis not in totals:
            # An unrecognised basis is surfaced as a bug rather than silently
            # dropped: a row we cannot classify must not vanish from the books.
            logger.warning("Unknown savings basis encountered", extra={"basis": record.basis})
            continue
        totals[basis] += record.monthly_amount
        counts[basis] += 1
        if record.currency:
            currency = record.currency

    verified = _quantise(totals[BASIS_VERIFIED])
    return SavingsLedgerSummary(
        currency=currency,
        potential_monthly_savings=_quantise(totals[BASIS_POTENTIAL]),
        approved_monthly_savings=_quantise(totals[BASIS_APPROVED]),
        implemented_monthly_savings=_quantise(totals[BASIS_IMPLEMENTED]),
        verified_monthly_savings=verified,
        inconclusive_monthly_savings=_quantise(totals[BASIS_INCONCLUSIVE]),
        potential_count=counts[BASIS_POTENTIAL],
        approved_count=counts[BASIS_APPROVED],
        implemented_count=counts[BASIS_IMPLEMENTED],
        verified_count=counts[BASIS_VERIFIED],
        inconclusive_count=counts[BASIS_INCONCLUSIVE],
        annualised_verified_savings=_quantise(verified * Decimal("12")),
    )


class SavingsLedgerService:
    """Reads and writes the savings ledger, enforcing the transition rules."""

    def __init__(
        self,
        *,
        savings: SavingsRepository,
        findings: FindingRepository,
        audit: AuditRepository,
    ) -> None:
        self._savings = savings
        self._findings = findings
        self._audit = audit

    # -- reads -------------------------------------------------------------

    def summary(self, organization_id: str) -> SavingsLedgerSummary:
        return summarise_ledger(self._savings.list_for_org(organization_id))

    def list_entries(
        self, organization_id: str, *, basis: str | None = None
    ) -> list[SavingsRecord]:
        return self._savings.list_for_org(organization_id, basis=basis)

    # -- writes ------------------------------------------------------------

    def record_potential(
        self,
        *,
        organization_id: str,
        finding: FindingRecord,
        actor_user_id: str,
    ) -> SavingsRecord | None:
        """Record a finding's estimate as a potential saving, once.

        Returns ``None`` when the finding carries no defensible figure. Writing
        a zero would be worse than writing nothing: it would assert "this saves
        nothing" when the truth is "we could not price this".

        Idempotent: an existing potential entry for the finding is returned
        unchanged, so a re-scan cannot double the potential total.
        """
        amount = finding.estimated_monthly_savings
        if amount is None or amount <= 0:
            return None

        existing = self._savings.find_for_finding(
            organization_id, finding.id, basis=BASIS_POTENTIAL
        )
        if existing is not None:
            return existing

        record = self._savings.create(
            organization_id=organization_id,
            aws_account_id=finding.aws_account_id,
            finding_id=finding.id,
            basis=BASIS_POTENTIAL,
            monthly_amount=amount,
            currency=finding.currency or "USD",
            evidence=None,
            measured_from=None,
            measured_to=None,
            created_by=actor_user_id,
        )
        self._audit.record(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="savings.potential_recorded",
            target_type="savings_record",
            target_id=record.id,
            metadata={
                "finding_id": finding.id,
                "monthly_amount": str(amount),
                "currency": record.currency,
            },
        )
        return record

    def advance(
        self,
        *,
        organization_id: str,
        finding_id: str,
        target_basis: str,
        actor_user_id: str,
        evidence: dict[str, Any] | None = None,
        measured_from: datetime | None = None,
        measured_to: datetime | None = None,
        monthly_amount: Decimal | None = None,
        note: str | None = None,
    ) -> SavingsRecord:
        """Move a finding's ledger entry forward by exactly one step.

        The current basis is discovered from the ledger rather than trusted from
        the request, so a client cannot skip from ``potential`` to ``verified``
        and assert a saving that was never measured.
        """
        if target_basis not in BASES:
            raise ValidationError(f"'{target_basis}' is not a valid savings basis.")

        finding = self._findings.get(organization_id, finding_id)
        if finding is None:
            raise NotFoundError("Finding not found.")

        current = self._current_basis(organization_id, finding_id)
        if current is None:
            raise ConflictError(
                "This finding has no savings entry to advance.",
                details={"finding_id": finding_id},
            )

        allowed = _ALLOWED_TRANSITIONS.get(current, frozenset())
        if target_basis not in allowed:
            raise ConflictError(
                f"A savings entry cannot move from '{current}' to '{target_basis}'.",
                details={
                    "current_basis": current,
                    "requested_basis": target_basis,
                    "allowed_next": sorted(allowed),
                },
            )

        amount = monthly_amount
        if amount is None:
            amount = finding.estimated_monthly_savings

        if target_basis in _PRICED_BASES:
            if amount is None or amount <= 0:
                raise ValidationError(f"A '{target_basis}' entry needs a positive monthly amount.")
        elif target_basis == BASIS_VERIFIED:
            self._require_verification_evidence(
                evidence=evidence, measured_from=measured_from, measured_to=measured_to
            )
            # A verified figure is the measured amount, not the original
            # estimate. Falling back to the estimate would relabel a guess as a
            # measurement, which is the exact failure this ledger prevents.
            if monthly_amount is None:
                raise ValidationError(
                    "A verified saving requires the measured monthly amount; "
                    "the original estimate is not sufficient."
                )
            amount = monthly_amount
        elif target_basis == BASIS_INCONCLUSIVE:
            # An inconclusive measurement may legitimately be zero.
            if amount is None:
                amount = Decimal("0")

        assert amount is not None  # guaranteed by the branches above

        existing = self._savings.find_for_finding(organization_id, finding_id, basis=current)
        if existing is None:  # pragma: no cover - guarded by _current_basis
            raise ConflictError("The savings entry disappeared during the update.")

        record = self._savings.update(
            existing.id,
            basis=target_basis,
            monthly_amount=_quantise(amount),
            evidence=evidence if target_basis == BASIS_VERIFIED else existing.evidence,
            measured_from=measured_from,
            measured_to=measured_to,
        )

        self._audit.record(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=f"savings.{target_basis}",
            target_type="savings_record",
            target_id=record.id,
            metadata={
                "finding_id": finding_id,
                "from_basis": current,
                "to_basis": target_basis,
                "monthly_amount": str(record.monthly_amount),
                "note": note,
            },
        )
        return record

    def withdraw(self, *, organization_id: str, finding_id: str, actor_user_id: str) -> bool:
        """Remove a finding's ledger entry, returning whether one was removed.

        Called when a finding is dismissed: an opportunity the user has
        explicitly rejected must stop contributing to the potential total.
        """
        removed = self._savings.delete_for_finding(
            organization_id, finding_id, basis=BASIS_POTENTIAL
        )
        if removed:
            self._audit.record(
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="savings.potential_withdrawn",
                target_type="finding",
                target_id=finding_id,
                metadata={},
            )
        return removed

    # -- internals ---------------------------------------------------------

    def _current_basis(self, organization_id: str, finding_id: str) -> str | None:
        """The basis a finding's single ledger entry currently sits at."""
        for basis in BASES:
            if self._savings.find_for_finding(organization_id, finding_id, basis=basis):
                return basis
        return None

    def _require_verification_evidence(
        self,
        *,
        evidence: dict[str, Any] | None,
        measured_from: datetime | None,
        measured_to: datetime | None,
    ) -> None:
        """A verification without evidence and a window is not a verification."""
        missing: list[str] = []
        if not evidence:
            missing.append("evidence")
        if measured_from is None or measured_to is None:
            missing.append("measurement_window")
        if missing:
            raise ValidationError(
                "A verified saving requires post-change evidence and a measurement window.",
                details={"missing": missing},
            )
        if measured_to < measured_from:  # type: ignore[operator]
            raise ValidationError("The measurement window ends before it starts.")
