"""Pricing inputs for savings estimation.

Prices are *inputs*, not facts baked into detectors. Every figure carries its
source and the date it was captured, so an estimate can always be traced back
to an assumption and revisited when prices change.

The values here are placeholders for the default us-east-1 on-demand rates
that must be reviewed before any production use. They are deliberately held in
one place so that a real pricing source (the AWS Price List API, or a curated
table) can replace them without touching detector logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal


@dataclass(frozen=True, slots=True)
class PriceBook:
    """A versioned set of unit prices used for estimation."""

    source: str
    captured_on: date
    currency: str = "USD"

    # Price per GB-month for gp3 EBS storage, us-east-1.
    ebs_gp3_per_gb_month: Decimal = Decimal("0.08")
    # Price per GB-month for gp2 EBS storage, us-east-1.
    ebs_gp2_per_gb_month: Decimal = Decimal("0.10")
    # Price per GB-month for standard (magnetic) EBS storage, us-east-1.
    ebs_standard_per_gb_month: Decimal = Decimal("0.05")
    # Hourly charge for an unattached Elastic IP address.
    elastic_ip_per_hour: Decimal = Decimal("0.005")
    # Hours used to convert an hourly price into a monthly estimate. 730 is
    # the conventional average month length.
    hours_per_month: Decimal = Decimal("730")

    def ebs_gb_month_price(self, volume_type: str) -> Decimal | None:
        """Return the per-GB-month price for a volume type, or ``None``."""
        mapping = {
            "gp3": self.ebs_gp3_per_gb_month,
            "gp2": self.ebs_gp2_per_gb_month,
            "standard": self.ebs_standard_per_gb_month,
        }
        return mapping.get(volume_type)


# Default book used unless a caller supplies another. The source string is
# intentionally explicit so any figure derived from it is traceable.
DEFAULT_PRICE_BOOK = PriceBook(
    source="placeholder-us-east-1-on-demand (not a live AWS price feed)",
    captured_on=date(2026, 1, 1),
)
