"""Detector contracts.

A detector turns a normalised resource snapshot into zero or more candidate
findings. Two rules shape this interface:

1. A detector reports a *potential opportunity*, never a confirmed saving.
   Findings therefore carry ``state="estimated"`` and a ``confidence``.
2. A detector must attach the evidence it used. A finding whose reasoning
   cannot be inspected is not actionable, so ``evidence`` is required and is
   rendered in the UI.

Detectors are pure functions over already-collected data. They perform no AWS
calls, so they are fast and trivially testable.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Protocol

from app.repositories.models import ResourceSnapshotRecord


@dataclass(frozen=True, slots=True)
class DetectorFinding:
    """A candidate finding produced by a detector."""

    detector: str
    resource_type: str
    resource_id: str
    region: str
    severity: str
    confidence: str
    title: str
    summary: str
    recommended_action: str
    evidence: dict[str, Any]
    estimated_monthly_savings: Decimal | None = None
    currency: str = "USD"
    dedupe_parts: tuple[str, ...] = field(default_factory=tuple)

    def dedupe_key(self, *, aws_account_id: str) -> str:
        """Stable identity used to suppress duplicate findings.

        Scoped by account and resource so the same opportunity discovered in
        two consecutive scans is recorded once.
        """
        parts = (aws_account_id, self.detector, self.region, self.resource_id, *self.dedupe_parts)
        return ":".join(parts)


class Detector(Protocol):
    """A read-only cost optimization detector."""

    name: str
    resource_type: str

    def detect(self, resources: Sequence[ResourceSnapshotRecord]) -> list[DetectorFinding]: ...
