"""Detector: unassociated Elastic IP addresses.

An Elastic IP that is allocated but not associated with an instance or network
interface is billed hourly. This is one of the few findings where the evidence
is unambiguous — AWS reports association state directly, so no inference from
metrics is required.

The detector still recommends review rather than release: an address may be
held deliberately for a planned failover, and released addresses are not
recoverable.
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import ROUND_HALF_UP, Decimal

from app.repositories.models import ResourceSnapshotRecord
from app.services.detectors.base import DetectorFinding
from app.services.pricing import DEFAULT_PRICE_BOOK, PriceBook


class UnassociatedElasticIpDetector:
    """Flags Elastic IP addresses with no association."""

    name = "unassociated_elastic_ip"
    resource_type = "elastic_ip"

    def __init__(self, price_book: PriceBook | None = None) -> None:
        self._price_book = price_book or DEFAULT_PRICE_BOOK

    def detect(self, resources: Sequence[ResourceSnapshotRecord]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        for resource in resources:
            if resource.resource_type != self.resource_type:
                continue
            attributes = resource.attributes
            # ``association_id`` absent or null means unassociated.
            association_id = attributes.get("association_id")
            if association_id:
                continue

            public_ip = str(attributes.get("public_ip") or resource.resource_id)
            domain = str(attributes.get("domain") or "vpc")

            estimated = (
                self._price_book.elastic_ip_per_hour * self._price_book.hours_per_month
            ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

            evidence: dict[str, object] = {
                "evidence_source": "ec2:DescribeAddresses (AssociationId absent)",
                "observation_window": "point-in-time at scan execution",
                "public_ip": public_ip,
                "domain": domain,
                "association_id": None,
                "instance_id": None,
                "network_interface_id": None,
                "price_source": self._price_book.source,
                "price_captured_on": self._price_book.captured_on.isoformat(),
                "assumption": (
                    "Estimated from the hourly charge for an unassociated address "
                    f"multiplied by {self._price_book.hours_per_month} hours per month. "
                    "The hourly rate and the free-tier treatment of addresses vary by "
                    "region and account; confirm against your bill before relying on the "
                    "figure."
                ),
            }

            findings.append(
                DetectorFinding(
                    detector=self.name,
                    resource_type=self.resource_type,
                    resource_id=resource.resource_id,
                    region=resource.region,
                    severity="low",
                    confidence="high",
                    title=f"Unassociated Elastic IP in {resource.region}",
                    summary=(
                        f"Elastic IP {public_ip} is allocated but not associated with any "
                        "instance or network interface."
                    ),
                    recommended_action=(
                        "Confirm the address is not reserved for a planned failover, then "
                        "release it. A released Elastic IP cannot be recovered, so verify "
                        "first."
                    ),
                    evidence=evidence,
                    estimated_monthly_savings=estimated,
                    currency=self._price_book.currency,
                    dedupe_parts=("unassociated",),
                )
            )

        return findings
