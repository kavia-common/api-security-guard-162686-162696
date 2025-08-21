"""
Shadow API Detector

Compares observed traffic (service, method, path) against known registered API
descriptors to flag potential "shadow" endpoints that are not declared.

This is a heuristic detector and emits a suggested finding payload for integration
with the FindingRepository.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Set

from .models import EventRecord, FindingSeverity
from .owasp_rules import OWASP_RULES


@dataclass
class ShadowDetectionResult:
    """Result of shadow API detection."""
    is_shadow: bool
    suggested_title: Optional[str] = None
    suggested_description: Optional[str] = None
    suggested_severity: FindingSeverity = FindingSeverity.MEDIUM
    rule_id: Optional[str] = None


class ShadowAPIDetector:
    """
    Heuristic detector for shadow APIs.

    Logic:
    - If the (service, method, path) traffic is observed but not present in the
      APIDescriptorRepository, consider it a potential shadow endpoint.
    - If path contains sensitive keywords, bump severity.
    """

    def __init__(self, known_keys: Set[str]) -> None:
        """
        Args:
            known_keys: Set of "service:METHOD:/path" known endpoint identifiers.
        """
        self._known = known_keys

    # PUBLIC_INTERFACE
    def detect(self, event: EventRecord) -> ShadowDetectionResult:
        """Detect if the event corresponds to a shadow endpoint."""
        key = f"{event.service}:{event.method.upper()}:{event.path}"
        is_shadow = key not in self._known

        if not is_shadow:
            return ShadowDetectionResult(is_shadow=False)

        title = "Potential Shadow API endpoint observed"
        desc = (
            "Observed traffic for an endpoint that is not registered in the catalog. "
            f"service={event.service}, method={event.method}, path={event.path}"
        )
        severity = FindingSeverity.MEDIUM
        # Escalate in some obvious cases
        lower = event.path.lower()
        if any(w in lower for w in ("admin", "internal", "private")):
            severity = FindingSeverity.HIGH

        # Use a generic OWASP mapping for reporting context
        rule = OWASP_RULES.get("OWASP-API8-SEC-MISCONFIG")

        return ShadowDetectionResult(
            is_shadow=True,
            suggested_title=title,
            suggested_description=desc,
            suggested_severity=severity,
            rule_id=rule.id if rule else None,
        )
