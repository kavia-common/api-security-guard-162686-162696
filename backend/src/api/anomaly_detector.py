"""
Anomaly Detector

Maintains lightweight per-endpoint baselines computed in-memory to flag anomalies:
- Latency spikes (z-score like heuristic)
- Error rate spikes (naive thresholds)
- Sudden payload size jumps

No external ML frameworks; it maintains rolling aggregates and simple thresholds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from .models import EventRecord, FindingSeverity
from .owasp_rules import OWASP_RULES


@dataclass
class EndpointStats:
    count: int = 0
    sum_latency: float = 0.0
    sum_latency_sq: float = 0.0
    errors: int = 0
    avg_payload: float = 0.0

    def update(self, ev: EventRecord) -> None:
        self.count += 1
        if ev.latency_ms is not None:
            self.sum_latency += ev.latency_ms
            self.sum_latency_sq += ev.latency_ms ** 2
        if ev.status_code and ev.status_code >= 500:
            self.errors += 1
        if ev.payload_size is not None:
            # simple running average
            self.avg_payload = ((self.avg_payload * (self.count - 1)) + ev.payload_size) / self.count

    def mean_latency(self) -> Optional[float]:
        return None if self.count == 0 else self.sum_latency / self.count

    def std_latency(self) -> Optional[float]:
        if self.count < 2:
            return None
        mean = self.mean_latency()
        var = (self.sum_latency_sq / self.count) - (mean ** 2)
        return var ** 0.5 if var > 0 else 0.0

    def error_rate(self) -> float:
        return 0.0 if self.count == 0 else self.errors / self.count


@dataclass
class Anomaly:
    title: str
    description: str
    severity: FindingSeverity
    rule_id: Optional[str] = None


class AnomalyDetector:
    """
    Keeps simple baselines and raises anomalies using fixed thresholds:
    - latency: > mean + 3*std
    - error rate: > 20%
    - payload jump: current > 5 * avg_payload and current > 256KB
    """

    def __init__(self) -> None:
        self._stats: Dict[str, EndpointStats] = {}

    def _key(self, ev: EventRecord) -> str:
        return f"{ev.service}:{ev.method.upper()}:{ev.path}"

    # PUBLIC_INTERFACE
    def observe(self, ev: EventRecord) -> Optional[Anomaly]:
        """
        Observe event and optionally return an anomaly finding suggestion.

        Returns an Anomaly or None.
        """
        key = self._key(ev)
        stats = self._stats.setdefault(key, EndpointStats())

        # Compute alerts before updating the baseline to detect spikes
        anomalies = []

        # Latency spike
        if ev.latency_ms is not None and stats.count >= 10:
            mean = stats.mean_latency()
            std = stats.std_latency() or 0.0
            threshold = (mean or 0.0) + 3 * std
            if std > 0 and ev.latency_ms > threshold:
                rule = OWASP_RULES.get("OWASP-API4-RATE")
                anomalies.append(
                    Anomaly(
                        title="Latency spike detected",
                        description=f"Observed latency {ev.latency_ms:.2f}ms exceeds baseline threshold {threshold:.2f}ms.",
                        severity=FindingSeverity.MEDIUM,
                        rule_id=rule.id if rule else None,
                    )
                )

        # Payload jump
        if ev.payload_size is not None and stats.count >= 5:
            if stats.avg_payload > 0 and ev.payload_size > 5 * stats.avg_payload and ev.payload_size > 262_144:
                rule = OWASP_RULES.get("OWASP-API10-MASS-ASSIGNMENT")
                anomalies.append(
                    Anomaly(
                        title="Unusual large payload observed",
                        description=f"Payload size {ev.payload_size} bytes significantly exceeds average {stats.avg_payload:.0f} bytes.",
                        severity=FindingSeverity.MEDIUM,
                        rule_id=rule.id if rule else None,
                    )
                )

        # After checks, update baseline
        stats.update(ev)

        # Error rate spike - evaluate on multiples of 20 samples
        if stats.count >= 20 and stats.count % 20 == 0:
            er = stats.error_rate()
            if er > 0.2:
                rule = OWASP_RULES.get("OWASP-API4-RATE")
                anomalies.append(
                    Anomaly(
                        title="Elevated error rate",
                        description=f"Error rate {er*100:.1f}% exceeds 20% threshold.",
                        severity=FindingSeverity.HIGH,
                        rule_id=rule.id if rule else None,
                    )
                )

        # Prefer the highest severity anomaly if multiple
        if not anomalies:
            return None
        anomalies.sort(key=lambda a: ["info", "low", "medium", "high", "critical"].index(a.severity.value))
        return anomalies[-1]
