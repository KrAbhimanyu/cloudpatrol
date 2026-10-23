"""Savings aggregation and the estimated/verified distinction.

The single most important rule in this module: an estimate is never presented
as an achieved saving. Savings are always grouped by state, and only the
``verified`` bucket is described as realised. This phase cannot produce
``verified`` figures at all, because verification requires post-change
evidence that only a later remediation phase can supply.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from app.repositories.models import FindingRecord

# States that represent money that has actually been realised.
_VERIFIED_STATES = frozenset({"verified"})
# States that represent a live, still-actionable opportunity.
_OPEN_STATES = frozenset({"estimated", "acknowledged", "implemented"})


@dataclass(frozen=True, slots=True)
class SavingsSummary:
    """Potential and verified savings for a set of findings."""

    currency: str
    potential_monthly_savings: Decimal
    verified_monthly_savings: Decimal
    annualised_potential_savings: Decimal
    open_finding_count: int
    verified_finding_count: int
    dismissed_finding_count: int
    findings_without_estimate: int
    monthly_savings_by_detector: dict[str, Decimal]

    def as_dict(self) -> dict[str, object]:
        return {
            "currency": self.currency,
            "potential_monthly_savings": str(self.potential_monthly_savings),
            "verified_monthly_savings": str(self.verified_monthly_savings),
            "annualised_potential_savings": str(self.annualised_potential_savings),
            "open_finding_count": self.open_finding_count,
            "verified_finding_count": self.verified_finding_count,
            "dismissed_finding_count": self.dismissed_finding_count,
            "findings_without_estimate": self.findings_without_estimate,
            "monthly_savings_by_detector": {
                key: str(value) for key, value in self.monthly_savings_by_detector.items()
            },
        }


def _quantise(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def summarise_savings(findings: Iterable[FindingRecord]) -> SavingsSummary:
    """Aggregate findings into potential and verified totals.

    Findings without an estimate are counted separately rather than being
    treated as zero, so the UI can distinguish "no opportunity" from "no
    figure available yet".
    """
    potential = Decimal("0")
    verified = Decimal("0")
    open_count = 0
    verified_count = 0
    dismissed_count = 0
    without_estimate = 0
    by_detector: dict[str, Decimal] = {}
    currency = "USD"

    for finding in findings:
        if finding.state == "dismissed":
            dismissed_count += 1
            continue

        if finding.state in _VERIFIED_STATES:
            verified_count += 1
            if finding.estimated_monthly_savings is not None:
                verified += finding.estimated_monthly_savings
            else:
                without_estimate += 1
            continue

        if finding.state not in _OPEN_STATES:
            continue

        open_count += 1
        amount = finding.estimated_monthly_savings
        if amount is None:
            # Counted separately so the UI can distinguish "no opportunity"
            # from "no figure available yet".
            without_estimate += 1
            continue

        currency = finding.currency or currency
        potential += amount
        by_detector[finding.detector] = by_detector.get(finding.detector, Decimal("0")) + amount

    potential = _quantise(potential)
    verified = _quantise(verified)
    annualised = _quantise(potential * Decimal("12"))

    return SavingsSummary(
        currency=currency,
        potential_monthly_savings=potential,
        verified_monthly_savings=verified,
        annualised_potential_savings=annualised,
        open_finding_count=open_count,
        verified_finding_count=verified_count,
        dismissed_finding_count=dismissed_count,
        findings_without_estimate=without_estimate,
        monthly_savings_by_detector={k: _quantise(v) for k, v in by_detector.items()},
    )
