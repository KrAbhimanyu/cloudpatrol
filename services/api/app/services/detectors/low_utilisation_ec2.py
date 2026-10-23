"""Detector: low-utilisation EC2 instances.

This detector is deliberately the most conservative of the three. It only
reports an instance when CloudWatch data actually supports the claim, and it
records the metric window and the observed values as evidence.

Two situations are treated very differently:

* **No metrics at all** — the instance is running but CloudWatch returned no
  datapoints. This is *not* evidence of idleness. It usually means the
  CloudWatch read permission is missing, the instance was started recently, or
  detailed monitoring is off. The detector reports nothing rather than
  guessing, because "no data" and "no usage" are not the same thing.
* **Metrics below threshold** — the instance averaged under the configured CPU
  threshold across the window, so a rightsizing review is warranted.

Even then the finding says *review for rightsizing*, not *stop or terminate*.
A low-CPU instance may be a licence server, a bastion host, or a database that
is memory-bound rather than CPU-bound.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from app.repositories.models import ResourceSnapshotRecord
from app.services.detectors.base import DetectorFinding

DEFAULT_CPU_THRESHOLD_PERCENT = Decimal("5")
DEFAULT_WINDOW_DAYS = 14
DEFAULT_MIN_DATAPOINTS = 12


@dataclass(frozen=True, slots=True)
class InstanceMetrics:
    """Aggregated CloudWatch data for one instance."""

    average_cpu_percent: Decimal | None
    maximum_cpu_percent: Decimal | None
    datapoint_count: int
    window_days: int


def _to_decimal(value: Any) -> Decimal | None:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (ArithmeticError, ValueError):
        return None


def summarise_cpu_datapoints(
    datapoints: Sequence[dict[str, Any]],
    *,
    window_days: int,
) -> InstanceMetrics:
    """Reduce CloudWatch CPU datapoints to an average, maximum and count.

    An unweighted mean of the returned datapoints is used. Datapoints cover
    equal-length periods in the collection this detector performs, so an
    unweighted mean is appropriate; a detector that mixed period lengths would
    need time-weighted averaging instead.
    """
    values: list[Decimal] = []
    for point in datapoints:
        average = _to_decimal(point.get("Average"))
        if average is None:
            maximum = _to_decimal(point.get("Maximum"))
            if maximum is None:
                continue
            average = maximum
        values.append(average)

    if not values:
        return InstanceMetrics(None, None, 0, window_days)

    total = sum(values, start=Decimal("0"))
    mean = (total / Decimal(len(values))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    peak = max(values).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return InstanceMetrics(mean, peak, len(values), window_days)


class LowUtilisationEc2Detector:
    """Flags running EC2 instances with sustained low CPU utilisation."""

    name = "low_utilisation_ec2"
    resource_type = "ec2_instance"

    def __init__(
        self,
        *,
        cpu_threshold_percent: Decimal = DEFAULT_CPU_THRESHOLD_PERCENT,
        window_days: int = DEFAULT_WINDOW_DAYS,
        min_datapoints: int = DEFAULT_MIN_DATAPOINTS,
    ) -> None:
        self._threshold = cpu_threshold_percent
        self._window_days = window_days
        self._min_datapoints = min_datapoints

    def detect(self, resources: Sequence[ResourceSnapshotRecord]) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        for resource in resources:
            if resource.resource_type != self.resource_type:
                continue
            if (resource.state or "").lower() != "running":
                continue

            attributes = resource.attributes
            metrics = summarise_cpu_datapoints(
                attributes.get("cpu_datapoints") or [], window_days=self._window_days
            )

            # Insufficient evidence: report nothing rather than infer idleness.
            if (
                metrics.datapoint_count < self._min_datapoints
                or metrics.average_cpu_percent is None
            ):
                continue

            if metrics.average_cpu_percent >= self._threshold:
                continue

            instance_type = str(attributes.get("instance_type") or "unknown")
            evidence: dict[str, object] = {
                "instance_type": instance_type,
                "instance_state": resource.state,
                "average_cpu_percent": str(metrics.average_cpu_percent),
                "maximum_cpu_percent": str(metrics.maximum_cpu_percent),
                "datapoint_count": metrics.datapoint_count,
                "window_days": metrics.window_days,
                "threshold_percent": str(self._threshold),
                "metric_namespace": "AWS/EC2",
                "metric_name": "CPUUtilization",
                "launch_time": attributes.get("launch_time"),
                "assumption": (
                    "CPU is the only signal collected in this phase. A low-CPU instance may "
                    "still be load-bearing — a bastion, a licence server, or a memory-bound "
                    "service. No savings figure is produced, because rightsizing requires "
                    "the target instance type and its price."
                ),
            }

            findings.append(
                DetectorFinding(
                    detector=self.name,
                    resource_type=self.resource_type,
                    resource_id=resource.resource_id,
                    region=resource.region,
                    severity="medium",
                    confidence="medium",
                    title=f"Low-utilisation EC2 instance in {resource.region}",
                    summary=(
                        f"Instance {resource.resource_id} ({instance_type}) averaged "
                        f"{metrics.average_cpu_percent}% CPU over "
                        f"{metrics.window_days} days, below the {self._threshold}% threshold."
                    ),
                    recommended_action=(
                        "Review the workload before changing anything. If the instance is "
                        "genuinely underused, consider rightsizing to a smaller type or "
                        "scheduling it to stop outside business hours."
                    ),
                    evidence=evidence,
                    # No price for the candidate target type is known, so no
                    # figure is emitted. An unsubstantiated number would be
                    # worse than none.
                    estimated_monthly_savings=None,
                    dedupe_parts=("low_cpu",),
                )
            )

        return findings
