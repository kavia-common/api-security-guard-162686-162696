"""
Detection and Remediation Services Orchestrator.

Provides a cohesive service that:
- Runs shadow API detection (comparing event against known API descriptors).
- Runs anomaly detection (latency spikes, error rate, payload anomalies).
- Runs quick OWASP static rule checks (headers, methods, payload sizes).
- Creates findings via the FindingRepository with mapped remediation hints (in metadata).

This module integrates with in-memory repositories defined in storage.py and models.py.
"""

from __future__ import annotations

from typing import Dict, Optional, Set

from .models import EventRecord, FindingSeverity
from .storage import APIDescriptorRepository, EventRepository, FindingRepository
from .shadow_detector import ShadowAPIDetector
from .anomaly_detector import AnomalyDetector
from .owasp_rules import check_sensitive_header_leak, check_sensitive_path_method, check_large_payload
from .remediator import Remediator


class DetectionService:
    """Coordinates detectors and creates findings when suspicious signals are observed."""

    def __init__(
        self,
        api_catalog: APIDescriptorRepository,
        events: EventRepository,
        findings: FindingRepository,
    ) -> None:
        self._api_catalog = api_catalog
        self._events = events
        self._findings = findings

        # Initialize detectors with current catalog
        self._shadow = ShadowAPIDetector(known_keys=self._catalog_keys())
        self._anomaly = AnomalyDetector()
        self._remediator = Remediator()

    def _catalog_keys(self) -> Set[str]:
        keys: Set[str] = set()
        for desc in self._api_catalog.list():
            keys.add(f"{desc.service}:{desc.method.upper()}:{desc.path}")
        return keys

    def _refresh_shadow_catalog(self) -> None:
        self._shadow = ShadowAPIDetector(known_keys=self._catalog_keys())

    def _create_finding(
        self,
        severity: FindingSeverity,
        title: str,
        description: str,
        event: EventRecord,
        rule_id: Optional[str],
        extra: Optional[Dict[str, str]] = None,
    ) -> None:
        metadata: Dict[str, str] = {}
        if extra:
            metadata.update({k: str(v) for k, v in extra.items()})
        # Attach remediation hints when available
        rem = self._remediator.for_rule(rule_id)
        if rem:
            metadata["remediation_title"] = rem.title
            for idx, step in enumerate(rem.steps, start=1):
                metadata[f"remediation_step_{idx}"] = step
        self._findings.create(
            {
                "severity": severity,
                "title": title,
                "description": description,
                "service": event.service,
                "endpoint_id": f"{event.service}:{event.method.upper()}:{event.path}",
                "event_id": event.id,
                "rule_id": rule_id,
                "metadata": metadata,
            }
        )

    # PUBLIC_INTERFACE
    def on_event_ingested(self, event: EventRecord) -> None:
        """
        Run all detectors on a newly ingested event and create findings as needed.

        This function is intentionally non-blocking and deterministic for the MVP.
        """
        # Keep shadow detector aligned to latest catalog
        self._refresh_shadow_catalog()

        # 1) Shadow API detection
        shadow_res = self._shadow.detect(event)
        if shadow_res.is_shadow:
            self._create_finding(
                severity=shadow_res.suggested_severity,
                title=shadow_res.suggested_title or "Shadow API detected",
                description=shadow_res.suggested_description or "Observed unregistered endpoint.",
                event=event,
                rule_id=shadow_res.rule_id,
                extra={"detector": "shadow"},
            )

        # 2) Anomaly detection (latency, errors, payload spikes)
        anomaly = self._anomaly.observe(event)
        if anomaly:
            self._create_finding(
                severity=anomaly.severity,
                title=anomaly.title,
                description=anomaly.description,
                event=event,
                rule_id=anomaly.rule_id,
                extra={"detector": "anomaly"},
            )

        # 3) Static OWASP-like checks
        rule = check_sensitive_header_leak(event.response_headers)
        if rule:
            self._create_finding(
                severity=FindingSeverity.HIGH,
                title=rule.title,
                description=rule.description,
                event=event,
                rule_id=rule.id,
                extra={"detector": "rules", "header_hit": "true"},
            )

        rule = check_sensitive_path_method(event.method, event.path)
        if rule:
            self._create_finding(
                severity=FindingSeverity.MEDIUM,
                title=rule.title,
                description=f"{rule.description} method={event.method} path={event.path}",
                event=event,
                rule_id=rule.id,
                extra={"detector": "rules"},
            )

        rule = check_large_payload(event.payload_size)
        if rule:
            self._create_finding(
                severity=FindingSeverity.MEDIUM,
                title=rule.title,
                description=rule.description,
                event=event,
                rule_id=rule.id,
                extra={"detector": "rules", "payload_size": str(event.payload_size or 0)},
            )
