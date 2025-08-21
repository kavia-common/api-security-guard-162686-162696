"""
Pydantic schemas for Guardial API Security.

These schemas define the public API interfaces for requests and responses.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set

from pydantic import BaseModel, Field, constr


# PUBLIC_INTERFACE
class HealthResponse(BaseModel):
    """Health check response."""
    message: str = Field(..., description="Service health message.")


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    ERROR = "error"
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    CUSTOM = "custom"


# PUBLIC_INTERFACE
class APIKeyCreateRequest(BaseModel):
    """Request to create an API key."""
    name: constr(min_length=1) = Field(..., description="Friendly name for the key.")
    scopes: Set[str] = Field(default_factory=set, description="Permission scopes.")
    metadata: Dict[str, str] = Field(default_factory=dict, description="Arbitrary metadata.")


# PUBLIC_INTERFACE
class APIKeyResponse(BaseModel):
    """API Key response including secret token on creation."""
    id: str = Field(..., description="API key identifier.")
    name: str = Field(..., description="Friendly name for the key.")
    token: Optional[str] = Field(None, description="Returned only on creation.")
    scopes: Set[str] = Field(default_factory=set, description="Permission scopes.")
    created_at: datetime = Field(..., description="Creation timestamp (UTC).")
    enabled: bool = Field(..., description="Whether the key is enabled.")
    last_used_at: Optional[datetime] = Field(None, description="Last usage timestamp.")
    metadata: Dict[str, str] = Field(default_factory=dict, description="Arbitrary metadata.")


# PUBLIC_INTERFACE
class APIKeyUpdateRequest(BaseModel):
    """Request to update API key attributes."""
    name: Optional[str] = Field(None, description="New name.")
    scopes: Optional[Set[str]] = Field(None, description="Replace scopes with provided set.")
    enabled: Optional[bool] = Field(None, description="Enable/disable the key.")
    metadata: Optional[Dict[str, str]] = Field(None, description="Replace metadata map.")


# PUBLIC_INTERFACE
class EventIngestRequest(BaseModel):
    """Ingest an API event into the system."""
    event_type: EventType = Field(..., description="Type of event.")
    service: str = Field(..., description="Logical service name.")
    method: str = Field(..., description="HTTP method.")
    path: str = Field(..., description="Request path.")
    status_code: Optional[int] = Field(None, description="HTTP status code.")
    latency_ms: Optional[float] = Field(None, description="Latency in milliseconds.")
    ip: Optional[str] = Field(None, description="Source IP address.")
    api_key_id: Optional[str] = Field(None, description="Associated API key id if known.")
    request_headers: Dict[str, str] = Field(default_factory=dict, description="Request headers.")
    response_headers: Dict[str, str] = Field(default_factory=dict, description="Response headers.")
    payload_size: Optional[int] = Field(None, description="Payload size in bytes.")
    attributes: Dict[str, str] = Field(default_factory=dict, description="Additional attributes.")


# PUBLIC_INTERFACE
class EventResponse(BaseModel):
    """Response for an ingested event."""
    id: str = Field(..., description="Event identifier.")
    timestamp: datetime = Field(..., description="Event timestamp.")
    event_type: EventType = Field(..., description="Type of event.")
    service: str = Field(..., description="Logical service name.")
    method: str = Field(..., description="HTTP method.")
    path: str = Field(..., description="Request path.")
    status_code: Optional[int] = Field(None, description="HTTP status code.")
    latency_ms: Optional[float] = Field(None, description="Latency in milliseconds.")
    ip: Optional[str] = Field(None, description="Source IP address.")
    api_key_id: Optional[str] = Field(None, description="Associated API key id if known.")
    payload_size: Optional[int] = Field(None, description="Payload size in bytes.")


# PUBLIC_INTERFACE
class APIDescriptorCreateRequest(BaseModel):
    """Register or update an API endpoint descriptor."""
    service: str = Field(..., description="Service name.")
    method: str = Field(..., description="HTTP method.")
    path: str = Field(..., description="Endpoint path pattern.")
    operation_id: Optional[str] = Field(None, description="OpenAPI operation id.")
    tags: List[str] = Field(default_factory=list, description="OpenAPI tags.")
    description: Optional[str] = Field(None, description="Description.")
    request_schema: Optional[Dict] = Field(None, description="Snippet of request schema.")
    response_schema: Optional[Dict] = Field(None, description="Snippet of response schema.")


# PUBLIC_INTERFACE
class APIDescriptorResponse(BaseModel):
    """API endpoint descriptor response."""
    id: str = Field(..., description="Descriptor identifier.")
    service: str = Field(..., description="Service name.")
    method: str = Field(..., description="HTTP method.")
    path: str = Field(..., description="Endpoint path pattern.")
    operation_id: Optional[str] = Field(None, description="OpenAPI operation id.")
    tags: List[str] = Field(default_factory=list, description="OpenAPI tags.")
    description: Optional[str] = Field(None, description="Description.")
    created_at: datetime = Field(..., description="Creation time.")
    updated_at: datetime = Field(..., description="Last update time.")


# PUBLIC_INTERFACE
class FindingCreateRequest(BaseModel):
    """Create a security finding."""
    severity: FindingSeverity = Field(..., description="Finding severity.")
    title: str = Field(..., description="Short title.")
    description: str = Field(..., description="Detailed description.")
    service: Optional[str] = Field(None, description="Associated service.")
    endpoint_id: Optional[str] = Field(None, description="Associated endpoint id.")
    event_id: Optional[str] = Field(None, description="Origin event id.")
    rule_id: Optional[str] = Field(None, description="Rule identifier.")
    metadata: Dict[str, str] = Field(default_factory=dict, description="Arbitrary metadata.")


# PUBLIC_INTERFACE
class FindingResponse(BaseModel):
    """Security finding payload."""
    id: str = Field(..., description="Finding id.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    severity: FindingSeverity = Field(..., description="Finding severity.")
    title: str = Field(..., description="Title.")
    description: str = Field(..., description="Description.")
    service: Optional[str] = Field(None, description="Service.")
    endpoint_id: Optional[str] = Field(None, description="Endpoint id.")
    event_id: Optional[str] = Field(None, description="Event id.")
    rule_id: Optional[str] = Field(None, description="Rule id.")
    acknowledged: bool = Field(..., description="If acknowledged.")
    acked_at: Optional[datetime] = Field(None, description="When acknowledged.")
    metadata: Dict[str, str] = Field(default_factory=dict, description="Arbitrary metadata.")


# PUBLIC_INTERFACE
class FindingAcknowledgeRequest(BaseModel):
    """Acknowledge a finding."""
    acknowledged: bool = Field(True, description="Set to True to acknowledge, False to un-acknowledge.")


# PUBLIC_INTERFACE
class RateLimitPolicyCreateRequest(BaseModel):
    """Create or update a rate limit policy."""
    name: str = Field(..., description="Policy name.")
    requests: int = Field(..., description="Number of requests allowed within the window.")
    per_seconds: int = Field(..., description="Duration of window in seconds.")
    scope: str = Field(..., description="Scope key type: ip, api_key, service, endpoint.")
    enabled: bool = Field(default=True, description="Enable or disable policy.")


# PUBLIC_INTERFACE
class RateLimitPolicyResponse(BaseModel):
    """Rate limit policy response."""
    id: str = Field(..., description="Policy id.")
    name: str = Field(..., description="Policy name.")
    requests: int = Field(..., description="Allowed requests in window.")
    per_seconds: int = Field(..., description="Window size in seconds.")
    scope: str = Field(..., description="Scope key type.")
    enabled: bool = Field(..., description="Policy enabled flag.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    updated_at: datetime = Field(..., description="Last update timestamp.")


# PUBLIC_INTERFACE
class ReportQuery(BaseModel):
    """Parameters to generate a basic report."""
    title: str = Field(..., description="Report title.")
    description: Optional[str] = Field(None, description="Report description.")
    from_ts: Optional[datetime] = Field(None, description="Start time filter.")
    to_ts: Optional[datetime] = Field(None, description="End time filter.")
    service: Optional[str] = Field(None, description="Service filter.")
    endpoint_id: Optional[str] = Field(None, description="Endpoint filter.")


# PUBLIC_INTERFACE
class ReportResponse(BaseModel):
    """Basic report response with minimal stats."""
    id: str = Field(..., description="Report id.")
    created_at: datetime = Field(..., description="Creation timestamp.")
    title: str = Field(..., description="Title.")
    description: Optional[str] = Field(None, description="Description.")
    stats: Dict[str, float] = Field(default_factory=dict, description="Computed statistics.")
