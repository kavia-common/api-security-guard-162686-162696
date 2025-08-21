"""
Domain models for the Guardial API Security backend.

These are internal models representing core entities. They are not Pydantic models and
are intended for use within the application logic and storage layers.

Note:
- Public interfaces are provided via Pydantic schemas in schemas.py.
- These models are lightweight dataclasses to keep logic separate from validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set
import secrets


class FindingSeverity(str, Enum):
    """Severity levels for security findings/alerts."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    """Represents known types of events that can be ingested."""
    REQUEST = "request"
    RESPONSE = "response"
    ERROR = "error"
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    CUSTOM = "custom"


@dataclass
class APIKey:
    """Internal representation of an API key record."""
    id: str
    name: str
    key_hash: str  # store hash or token id; for MVP we store token directly but label as hash
    scopes: Set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=datetime.utcnow)
    enabled: bool = True
    last_used_at: Optional[datetime] = None
    metadata: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def generate_token(prefix: str = "gk_", length: int = 32) -> str:
        """
        Generate a random API token.
        Note: For MVP, this returns a plain token. In production, store a hash only.
        """
        return f"{prefix}{secrets.token_urlsafe(length)}"


@dataclass
class APIDescriptor:
    """Represents an API endpoint description derived from OpenAPI or manual registration."""
    id: str
    service: str
    method: str
    path: str
    operation_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    description: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    # Minimal OpenAPI schema snippet (optional)
    request_schema: Optional[Dict] = None
    response_schema: Optional[Dict] = None


@dataclass
class EventRecord:
    """Represents an ingested API call event."""
    id: str
    timestamp: datetime
    event_type: EventType
    service: str
    method: str
    path: str
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    ip: Optional[str] = None
    api_key_id: Optional[str] = None
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    payload_size: Optional[int] = None
    # Arbitrary attributes for extensibility
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    """Represents a security finding/alert."""
    id: str
    created_at: datetime
    severity: FindingSeverity
    title: str
    description: str
    service: Optional[str] = None
    endpoint_id: Optional[str] = None
    event_id: Optional[str] = None
    rule_id: Optional[str] = None
    acknowledged: bool = False
    acked_at: Optional[datetime] = None
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class RateLimitPolicy:
    """Represents a rate limiting policy."""
    id: str
    name: str
    # Simple token-bucket like parameters
    requests: int
    per_seconds: int
    scope: str  # e.g., "ip", "api_key", "service", "endpoint"
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    # For MVP in-memory counters
    counters: Dict[str, List[datetime]] = field(default_factory=dict)

    def is_allowed(self, key: str, now: Optional[datetime] = None) -> bool:
        """
        Check if a request identified by 'key' is allowed under this policy.
        Uses a sliding window approach with timestamps.
        """
        if not self.enabled:
            return True
        now = now or datetime.utcnow()
        window_start = now - timedelta(seconds=self.per_seconds)
        bucket = self.counters.setdefault(key, [])
        # purge timestamps outside the window
        bucket[:] = [t for t in bucket if t >= window_start]
        allowed = len(bucket) < self.requests
        if allowed:
            bucket.append(now)
        return allowed


@dataclass
class Report:
    """Represents a generated report placeholder."""
    id: str
    created_at: datetime
    title: str
    description: Optional[str] = None
    parameters: Dict[str, str] = field(default_factory=dict)
    stats: Dict[str, float] = field(default_factory=dict)
