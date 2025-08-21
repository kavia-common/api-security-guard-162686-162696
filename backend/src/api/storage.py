"""
In-memory storage implementations for Guardial API Security.

These repositories provide a minimal abstraction layer so that we can later replace
them with persistent storage without changing the rest of the code.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple
import secrets

from .models import (
    APIKey,
    APIDescriptor,
    EventRecord,
    Finding,
    FindingSeverity,
    RateLimitPolicy,
    Report,
)


def _gen_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(12)}"


class APIKeyRepository:
    """In-memory repository for API keys."""

    def __init__(self) -> None:
        self._by_id: Dict[str, APIKey] = {}

    # PUBLIC_INTERFACE
    def create(self, name: str, scopes: Iterable[str], metadata: Dict[str, str]) -> Tuple[APIKey, str]:
        """Create an API key and return the saved record and plain token (one-time reveal)."""
        key_id = _gen_id("key")
        token = APIKey.generate_token()
        # For MVP store the token as key_hash for re-display check (not secure)
        rec = APIKey(id=key_id, name=name, key_hash=token, scopes=set(scopes), metadata=dict(metadata))
        self._by_id[rec.id] = rec
        return rec, token

    # PUBLIC_INTERFACE
    def list(self) -> List[APIKey]:
        """List all API keys."""
        return list(self._by_id.values())

    # PUBLIC_INTERFACE
    def get(self, key_id: str) -> Optional[APIKey]:
        """Get an API key by id."""
        return self._by_id.get(key_id)

    # PUBLIC_INTERFACE
    def update(
        self,
        key_id: str,
        name: Optional[str] = None,
        scopes: Optional[Iterable[str]] = None,
        enabled: Optional[bool] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Optional[APIKey]:
        """Update an API key fields."""
        rec = self._by_id.get(key_id)
        if not rec:
            return None
        if name is not None:
            rec.name = name
        if scopes is not None:
            rec.scopes = set(scopes)
        if enabled is not None:
            rec.enabled = enabled
        if metadata is not None:
            rec.metadata = dict(metadata)
        return rec

    # PUBLIC_INTERFACE
    def delete(self, key_id: str) -> bool:
        """Delete an API key, returns True if deleted."""
        return self._by_id.pop(key_id, None) is not None


class APIDescriptorRepository:
    """In-memory repository for API endpoint descriptors."""

    def __init__(self) -> None:
        self._by_id: Dict[str, APIDescriptor] = {}

    # PUBLIC_INTERFACE
    def upsert(self, payload: Dict) -> APIDescriptor:
        """Create or update an API descriptor uniquely by service-method-path."""
        now = datetime.utcnow()
        # derive synthetic id
        sid = f"{payload['service']}:{payload['method']}:{payload['path']}"
        rec = self._by_id.get(sid)
        if rec is None:
            rec = APIDescriptor(
                id=sid,
                service=payload["service"],
                method=payload["method"],
                path=payload["path"],
            )
        rec.operation_id = payload.get("operation_id")
        rec.tags = list(payload.get("tags") or [])
        rec.description = payload.get("description")
        rec.request_schema = payload.get("request_schema")
        rec.response_schema = payload.get("response_schema")
        rec.updated_at = now
        self._by_id[sid] = rec
        return rec

    # PUBLIC_INTERFACE
    def list(self, service: Optional[str] = None) -> List[APIDescriptor]:
        """List descriptors, optionally filtered by service."""
        vals = list(self._by_id.values())
        if service:
            vals = [v for v in vals if v.service == service]
        return vals

    # PUBLIC_INTERFACE
    def get(self, descriptor_id: str) -> Optional[APIDescriptor]:
        """Get by id."""
        return self._by_id.get(descriptor_id)


class EventRepository:
    """In-memory event store."""

    def __init__(self) -> None:
        self._by_id: Dict[str, EventRecord] = {}

    # PUBLIC_INTERFACE
    def add(self, payload: Dict) -> EventRecord:
        """Add an event from payload."""
        eid = _gen_id("evt")
        now = datetime.utcnow()
        rec = EventRecord(
            id=eid,
            timestamp=now,
            event_type=payload["event_type"],
            service=payload["service"],
            method=payload["method"],
            path=payload["path"],
            status_code=payload.get("status_code"),
            latency_ms=payload.get("latency_ms"),
            ip=payload.get("ip"),
            api_key_id=payload.get("api_key_id"),
            request_headers=dict(payload.get("request_headers") or {}),
            response_headers=dict(payload.get("response_headers") or {}),
            payload_size=payload.get("payload_size"),
            attributes=dict(payload.get("attributes") or {}),
        )
        self._by_id[rec.id] = rec
        return rec

    # PUBLIC_INTERFACE
    def list(self, service: Optional[str] = None, path: Optional[str] = None) -> List[EventRecord]:
        """List events with optional filters."""
        vals = list(self._by_id.values())
        if service:
            vals = [v for v in vals if v.service == service]
        if path:
            vals = [v for v in vals if v.path == path]
        return sorted(vals, key=lambda e: e.timestamp, reverse=True)


class FindingRepository:
    """In-memory findings store."""

    def __init__(self) -> None:
        self._by_id: Dict[str, Finding] = {}

    # PUBLIC_INTERFACE
    def create(self, payload: Dict) -> Finding:
        """Create a finding from payload."""
        fid = _gen_id("fnd")
        now = datetime.utcnow()
        rec = Finding(
            id=fid,
            created_at=now,
            severity=payload["severity"],
            title=payload["title"],
            description=payload["description"],
            service=payload.get("service"),
            endpoint_id=payload.get("endpoint_id"),
            event_id=payload.get("event_id"),
            rule_id=payload.get("rule_id"),
            metadata=dict(payload.get("metadata") or {}),
        )
        self._by_id[rec.id] = rec
        return rec

    # PUBLIC_INTERFACE
    def list(self, severity: Optional[FindingSeverity] = None, acknowledged: Optional[bool] = None) -> List[Finding]:
        """List findings with optional filters."""
        vals = list(self._by_id.values())
        if severity is not None:
            vals = [v for v in vals if v.severity == severity]
        if acknowledged is not None:
            vals = [v for v in vals if v.acknowledged == acknowledged]
        return sorted(vals, key=lambda f: f.created_at, reverse=True)

    # PUBLIC_INTERFACE
    def set_ack(self, finding_id: str, acknowledged: bool) -> Optional[Finding]:
        """Acknowledge or un-acknowledge a finding."""
        rec = self._by_id.get(finding_id)
        if not rec:
            return None
        rec.acknowledged = acknowledged
        rec.acked_at = datetime.utcnow() if acknowledged else None
        return rec


class RateLimitRepository:
    """In-memory rate limit policies."""

    def __init__(self) -> None:
        self._by_id: Dict[str, RateLimitPolicy] = {}

    # PUBLIC_INTERFACE
    def create(self, payload: Dict) -> RateLimitPolicy:
        """Create a rate limit policy."""
        rid = _gen_id("rlp")
        now = datetime.utcnow()
        rec = RateLimitPolicy(
            id=rid,
            name=payload["name"],
            requests=payload["requests"],
            per_seconds=payload["per_seconds"],
            scope=payload["scope"],
            enabled=payload.get("enabled", True),
            created_at=now,
            updated_at=now,
        )
        self._by_id[rec.id] = rec
        return rec

    # PUBLIC_INTERFACE
    def update(self, policy_id: str, payload: Dict) -> Optional[RateLimitPolicy]:
        """Update a rate limit policy."""
        rec = self._by_id.get(policy_id)
        if not rec:
            return None
        if "name" in payload and payload["name"] is not None:
            rec.name = payload["name"]
        if "requests" in payload and payload["requests"] is not None:
            rec.requests = payload["requests"]
        if "per_seconds" in payload and payload["per_seconds"] is not None:
            rec.per_seconds = payload["per_seconds"]
        if "scope" in payload and payload["scope"] is not None:
            rec.scope = payload["scope"]
        if "enabled" in payload and payload["enabled"] is not None:
            rec.enabled = payload["enabled"]
        rec.updated_at = datetime.utcnow()
        return rec

    # PUBLIC_INTERFACE
    def list(self) -> List[RateLimitPolicy]:
        """List all rate limit policies."""
        return list(self._by_id.values())

    # PUBLIC_INTERFACE
    def get(self, policy_id: str) -> Optional[RateLimitPolicy]:
        """Get a rate limit policy by id."""
        return self._by_id.get(policy_id)

    # PUBLIC_INTERFACE
    def delete(self, policy_id: str) -> bool:
        """Delete a rate limit policy."""
        return self._by_id.pop(policy_id, None) is not None


class ReportingService:
    """Simple reporting over in-memory stores."""

    def __init__(self, events: EventRepository, findings: FindingRepository) -> None:
        self._events = events
        self._findings = findings
        self._reports: Dict[str, Report] = {}

    # PUBLIC_INTERFACE
    def generate(self, title: str, description: Optional[str], params: Dict[str, str]) -> Report:
        """Generate a basic report with trivial aggregated stats."""
        rid = _gen_id("rpt")
        now = datetime.utcnow()
        # very basic counters for MVP
        events = self._events.list(
            service=params.get("service"),
            path=None,  # Could use endpoint filter if provided
        )
        total_events = float(len(events))
        findings = self._findings.list()
        total_findings = float(len(findings))
        stats = {
            "total_events": total_events,
            "total_findings": total_findings,
        }
        rep = Report(
            id=rid,
            created_at=now,
            title=title,
            description=description,
            parameters=params,
            stats=stats,
        )
        self._reports[rep.id] = rep
        return rep

    # PUBLIC_INTERFACE
    def get(self, report_id: str) -> Optional[Report]:
        """Retrieve a report by id."""
        return self._reports.get(report_id)
