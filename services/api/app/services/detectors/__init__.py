"""Detector registry.

Adding a detector means adding it here and nowhere else. The scan service
iterates this registry, so a new detector is picked up without touching
orchestration code.
"""

from __future__ import annotations

from app.services.detectors.base import Detector
from app.services.detectors.low_utilisation_ec2 import LowUtilisationEc2Detector
from app.services.detectors.unassociated_eip import UnassociatedElasticIpDetector
from app.services.detectors.unattached_ebs import UnattachedEbsVolumeDetector


def build_detectors() -> list[Detector]:
    """Return the detectors enabled in this phase."""
    return [
        UnattachedEbsVolumeDetector(),
        UnassociatedElasticIpDetector(),
        LowUtilisationEc2Detector(),
    ]


__all__ = [
    "build_detectors",
    "LowUtilisationEc2Detector",
    "UnassociatedElasticIpDetector",
    "UnattachedEbsVolumeDetector",
]
