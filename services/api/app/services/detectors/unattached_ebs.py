"""Detector: unattached EBS volumes.

An EBS volume in the ``available`` state is not attached to any instance and
still accrues storage charges. This is a *potential* opportunity: a volume may
be a deliberate backup, a snapshot staging area, or pending reattachment.

The detector therefore never recommends deletion. It recommends review, and it
attaches the evidence a human needs to decide: size, type, availability zone,
creation age, and whether any tags suggest the volume is intentional.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal

from app.repositories.models import ResourceSnapshotRecord
from app.services.detectors.base import DetectorFinding
from app.services.pricing import DEFAULT_PRICE_BOOK, PriceBook

# Tags that commonly mark a volume as intentionally retained.
_INTENTIONAL_TAG_KEYS = frozenset(
    {"backup", "retain", "do-not-delete", "dnd", "archive", "snapshot-source"}
)


def _monthly_cost(size_gb: int, volume_type: str, price_book: PriceBook) -> Decimal | None:
    unit_price = price_book.ebs_gb_month_price(volume_type)
    if unit_price is None:
        return None
    raw = unit_price * Decimal(size_gb)
    return raw.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


class UnattachedEbsVolumeDetector:
    """Flags EBS volumes in the ``available`` state."""

    name = "unattached_ebs_volume"
    resource_type = "ebs_volume"

    def __init__(self, price_book: PriceBook | None = None) -> None:
        self._price_book = price_book or DEFAULT_PRICE_BOOK

    def detect(self, resources: Sequence[ResourceSnapshotRecord]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        for resource in resources:
            if resource.resource_type != self.resource_type:
                continue
            if (resource.state or "").lower() != "available":
                continue

            attributes = resource.attributes
            size_gb = int(attributes.get("size_gb") or 0)
            volume_type = str(attributes.get("volume_type") or "unknown")
            create_time = str(attributes.get("create_time") or "")
            tags = attributes.get("tags") or {}
            tag_keys = {str(key).lower() for key in tags} if isinstance(tags, dict) else set()

            # A volume carrying a retention tag is still reported, but at low
            # confidence and with the tag called out, so a reviewer can dismiss
            # it quickly rather than acting on it blindly.
            tagged_for_retention = bool(tag_keys & _INTENTIONAL_TAG_KEYS)

            estimated = _monthly_cost(size_gb, volume_type, self._price_book) if size_gb else None

            age_days: int | None = None
            if create_time:
                try:
                    created = datetime.fromisoformat(create_time.replace("Z", "+00:00"))
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=UTC)
                    age_days = (datetime.now(UTC) - created).days
                except ValueError:
                    age_days = None

            evidence: dict[str, object] = {
                "evidence_source": "ec2:DescribeVolumes (volume State and Attachments)",
                "observation_window": "point-in-time at scan execution",
                "volume_state": resource.state,
                "size_gb": size_gb,
                "volume_type": volume_type,
                "availability_zone": attributes.get("availability_zone"),
                "create_time": create_time or None,
                "age_days": age_days,
                "tags": tags if isinstance(tags, dict) else {},
                "retention_tag_present": tagged_for_retention,
                "price_source": self._price_book.source,
                "price_captured_on": self._price_book.captured_on.isoformat(),
                "assumption": (
                    "Estimated at the on-demand storage rate for the volume type, "
                    "assuming the volume remains provisioned for a full month. "
                    "An EBS volume cannot be deleted safely without confirming it "
                    "holds no required data."
                ),
            }

            if tagged_for_retention:
                confidence = "low"
                summary = (
                    f"Volume {resource.resource_id} is unattached and carries a "
                    "retention tag. It is likely intentional; review before acting."
                )
            elif age_days is not None and age_days >= 30:
                confidence = "high"
                summary = (
                    f"Volume {resource.resource_id} ({size_gb} GiB, {volume_type}) has been "
                    f"unattached for at least {age_days} days."
                )
            else:
                confidence = "medium"
                summary = (
                    f"Volume {resource.resource_id} ({size_gb} GiB, {volume_type}) is "
                    "currently unattached."
                )

            findings.append(
                DetectorFinding(
                    detector=self.name,
                    resource_type=self.resource_type,
                    resource_id=resource.resource_id,
                    region=resource.region,
                    severity="medium",
                    confidence=confidence,
                    title=f"Unattached EBS volume in {resource.region}",
                    summary=summary,
                    recommended_action=(
                        "Review the volume's data and snapshots, confirm nothing depends on "
                        "it, then decide whether to snapshot and delete it. Do not delete "
                        "without verification."
                    ),
                    evidence=evidence,
                    estimated_monthly_savings=estimated,
                    currency=self._price_book.currency,
                    dedupe_parts=("unattached",),
                )
            )

        return findings
