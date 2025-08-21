from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .models import FindingSeverity
from .schemas import (
    APIDescriptorCreateRequest,
    APIDescriptorResponse,
    APIKeyCreateRequest,
    APIKeyResponse,
    APIKeyUpdateRequest,
    EventIngestRequest,
    EventResponse,
    FindingAcknowledgeRequest,
    FindingCreateRequest,
    FindingResponse,
    HealthResponse,
    RateLimitPolicyCreateRequest,
    RateLimitPolicyResponse,
    ReportQuery,
    ReportResponse,
)
from .storage import (
    APIDescriptorRepository,
    APIKeyRepository,
    EventRepository,
    FindingRepository,
    RateLimitRepository,
    ReportingService,
)
from .services import DetectionService

openapi_tags = [
    {"name": "health", "description": "Service health and info."},
    {"name": "events", "description": "Event ingestion and querying."},
    {"name": "api", "description": "API/OpenAPI endpoint management."},
    {"name": "findings", "description": "Security findings and alerts."},
    {"name": "rate_limits", "description": "Rate limiting policies."},
    {"name": "keys", "description": "API key management."},
    {"name": "reports", "description": "Reporting and analytics."},
]

app = FastAPI(
    title="Guardial API Security",
    description="API Security platform backend providing ingestion, findings, rate-limits, keys, and reporting.",
    version="0.1.0",
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory repositories (modular, replaceable later)
_api_keys = APIKeyRepository()
_api_desc = APIDescriptorRepository()
_events = EventRepository()
_findings = FindingRepository()
_rate_limits = RateLimitRepository()
_reports = ReportingService(events=_events, findings=_findings)
_detection = DetectionService(api_catalog=_api_desc, events=_events, findings=_findings)


# PUBLIC_INTERFACE
@app.get("/", response_model=HealthResponse, summary="Health check", tags=["health"])
def health_check():
    """
    Health Check
    Returns a simple message indicating the service is running.
    """
    return {"message": "Healthy"}


# Events endpoints
# PUBLIC_INTERFACE
@app.post(
    "/events",
    response_model=EventResponse,
    summary="Ingest event",
    description="Ingest an API event such as request/response/alert into the system.",
    tags=["events"],
)
def ingest_event(payload: EventIngestRequest):
    """
    Ingest an event.

    Parameters:
    - payload: EventIngestRequest - event payload.

    Returns:
    - EventResponse with generated ID and timestamp.
    """
    rec = _events.add(payload.model_dump())
    # Run lightweight detectors and auto-create findings as needed
    try:
        _detection.on_event_ingested(rec)
    except Exception:
        # Detectors should never block ingestion; fail-safe
        pass
    return EventResponse(
        id=rec.id,
        timestamp=rec.timestamp,
        event_type=rec.event_type,
        service=rec.service,
        method=rec.method,
        path=rec.path,
        status_code=rec.status_code,
        latency_ms=rec.latency_ms,
        ip=rec.ip,
        api_key_id=rec.api_key_id,
        payload_size=rec.payload_size,
    )


# PUBLIC_INTERFACE
@app.get(
    "/events",
    response_model=List[EventResponse],
    summary="List events",
    description="List recently ingested events optionally filtered by service/path.",
    tags=["events"],
)
def list_events(
    service: Optional[str] = Query(default=None, description="Filter by service."),
    path: Optional[str] = Query(default=None, description="Filter by path."),
):
    """
    List events with optional filters.

    Parameters:
    - service: optional service filter
    - path: optional path filter

    Returns a list of EventResponse sorted by time desc.
    """
    records = _events.list(service=service, path=path)
    return [
        EventResponse(
            id=r.id,
            timestamp=r.timestamp,
            event_type=r.event_type,
            service=r.service,
            method=r.method,
            path=r.path,
            status_code=r.status_code,
            latency_ms=r.latency_ms,
            ip=r.ip,
            api_key_id=r.api_key_id,
            payload_size=r.payload_size,
        )
        for r in records
    ]


# API/OpenAPI endpoints
# PUBLIC_INTERFACE
@app.post(
    "/api/endpoints",
    response_model=APIDescriptorResponse,
    summary="Register or update API endpoint",
    description="Register or update an API endpoint descriptor (OpenAPI-like).",
    tags=["api"],
)
def upsert_api_endpoint(payload: APIDescriptorCreateRequest):
    """
    Upsert an API endpoint descriptor.

    Parameters:
    - payload: APIDescriptorCreateRequest

    Returns:
    - APIDescriptorResponse
    """
    rec = _api_desc.upsert(payload.model_dump())
    return APIDescriptorResponse(
        id=rec.id,
        service=rec.service,
        method=rec.method,
        path=rec.path,
        operation_id=rec.operation_id,
        tags=rec.tags,
        description=rec.description,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
    )


# PUBLIC_INTERFACE
@app.get(
    "/api/endpoints",
    response_model=List[APIDescriptorResponse],
    summary="List API endpoints",
    description="List registered API endpoints with optional service filter.",
    tags=["api"],
)
def list_api_endpoints(service: Optional[str] = Query(default=None, description="Filter by service name.")):
    """
    List API descriptors.

    Parameters:
    - service: optional service filter

    Returns:
    - list of APIDescriptorResponse
    """
    items = _api_desc.list(service=service)
    return [
        APIDescriptorResponse(
            id=i.id,
            service=i.service,
            method=i.method,
            path=i.path,
            operation_id=i.operation_id,
            tags=i.tags,
            description=i.description,
            created_at=i.created_at,
            updated_at=i.updated_at,
        )
        for i in items
    ]


# Findings endpoints
# PUBLIC_INTERFACE
@app.post(
    "/findings",
    response_model=FindingResponse,
    summary="Create finding",
    description="Create a security finding/alert.",
    tags=["findings"],
)
def create_finding(payload: FindingCreateRequest):
    """
    Create a finding.

    Parameters:
    - payload: FindingCreateRequest

    Returns:
    - FindingResponse
    """
    rec = _findings.create(payload.model_dump())
    return FindingResponse(
        id=rec.id,
        created_at=rec.created_at,
        severity=rec.severity,
        title=rec.title,
        description=rec.description,
        service=rec.service,
        endpoint_id=rec.endpoint_id,
        event_id=rec.event_id,
        rule_id=rec.rule_id,
        acknowledged=rec.acknowledged,
        acked_at=rec.acked_at,
        metadata=rec.metadata,
    )


# PUBLIC_INTERFACE
@app.get(
    "/findings",
    response_model=List[FindingResponse],
    summary="List findings",
    description="List findings optionally filtered by severity and acknowledgment.",
    tags=["findings"],
)
def list_findings(
    severity: Optional[FindingSeverity] = Query(default=None, description="Filter by severity."),
    acknowledged: Optional[bool] = Query(default=None, description="Filter by acknowledgment."),
):
    """
    List findings.

    Parameters:
    - severity: optional severity filter
    - acknowledged: optional acknowledgment filter

    Returns a list of FindingResponse sorted by time desc.
    """
    items = _findings.list(severity=severity, acknowledged=acknowledged)
    return [
        FindingResponse(
            id=i.id,
            created_at=i.created_at,
            severity=i.severity,
            title=i.title,
            description=i.description,
            service=i.service,
            endpoint_id=i.endpoint_id,
            event_id=i.event_id,
            rule_id=i.rule_id,
            acknowledged=i.acknowledged,
            acked_at=i.acked_at,
            metadata=i.metadata,
        )
        for i in items
    ]


# PUBLIC_INTERFACE
@app.post(
    "/findings/{finding_id}/ack",
    response_model=FindingResponse,
    summary="Acknowledge finding",
    description="Set acknowledgment status on a finding.",
    tags=["findings"],
)
def ack_finding(finding_id: str, payload: FindingAcknowledgeRequest):
    """
    Acknowledge or un-acknowledge a finding.

    Parameters:
    - finding_id: id of the finding
    - payload: FindingAcknowledgeRequest with acknowledged flag

    Returns updated FindingResponse.
    """
    rec = _findings.set_ack(finding_id, payload.acknowledged)
    if not rec:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse(
        id=rec.id,
        created_at=rec.created_at,
        severity=rec.severity,
        title=rec.title,
        description=rec.description,
        service=rec.service,
        endpoint_id=rec.endpoint_id,
        event_id=rec.event_id,
        rule_id=rec.rule_id,
        acknowledged=rec.acknowledged,
        acked_at=rec.acked_at,
        metadata=rec.metadata,
    )


# Rate limit endpoints
# PUBLIC_INTERFACE
@app.post(
    "/rate-limits",
    response_model=RateLimitPolicyResponse,
    summary="Create rate limit policy",
    description="Create a rate limit policy definition.",
    tags=["rate_limits"],
)
def create_rate_limit(payload: RateLimitPolicyCreateRequest):
    """
    Create rate limit policy.
    """
    rec = _rate_limits.create(payload.model_dump())
    return RateLimitPolicyResponse(
        id=rec.id,
        name=rec.name,
        requests=rec.requests,
        per_seconds=rec.per_seconds,
        scope=rec.scope,
        enabled=rec.enabled,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
    )


# PUBLIC_INTERFACE
@app.get(
    "/rate-limits",
    response_model=List[RateLimitPolicyResponse],
    summary="List rate limit policies",
    description="List configured rate limit policies.",
    tags=["rate_limits"],
)
def list_rate_limits():
    """
    List rate limit policies.
    """
    items = _rate_limits.list()
    return [
        RateLimitPolicyResponse(
            id=i.id,
            name=i.name,
            requests=i.requests,
            per_seconds=i.per_seconds,
            scope=i.scope,
            enabled=i.enabled,
            created_at=i.created_at,
            updated_at=i.updated_at,
        )
        for i in items
    ]


# PUBLIC_INTERFACE
@app.put(
    "/rate-limits/{policy_id}",
    response_model=RateLimitPolicyResponse,
    summary="Update rate limit policy",
    description="Update fields of a rate limit policy.",
    tags=["rate_limits"],
)
def update_rate_limit(policy_id: str, payload: RateLimitPolicyCreateRequest):
    """
    Update rate limit policy.
    """
    rec = _rate_limits.update(policy_id, payload.model_dump())
    if not rec:
        raise HTTPException(status_code=404, detail="Policy not found")
    return RateLimitPolicyResponse(
        id=rec.id,
        name=rec.name,
        requests=rec.requests,
        per_seconds=rec.per_seconds,
        scope=rec.scope,
        enabled=rec.enabled,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
    )


# API key endpoints
# PUBLIC_INTERFACE
@app.post(
    "/keys",
    response_model=APIKeyResponse,
    summary="Create API key",
    description="Create a new API key (token returned once).",
    tags=["keys"],
)
def create_api_key(payload: APIKeyCreateRequest):
    """
    Create API key.

    Returns record including token once.
    """
    rec, token = _api_keys.create(payload.name, payload.scopes, payload.metadata)
    return APIKeyResponse(
        id=rec.id,
        name=rec.name,
        token=token,
        scopes=rec.scopes,
        created_at=rec.created_at,
        enabled=rec.enabled,
        last_used_at=rec.last_used_at,
        metadata=rec.metadata,
    )


# PUBLIC_INTERFACE
@app.get(
    "/keys",
    response_model=List[APIKeyResponse],
    summary="List API keys",
    description="List API keys (without secret token).",
    tags=["keys"],
)
def list_api_keys():
    """
    List API keys without exposing secret token.
    """
    items = _api_keys.list()
    return [
        APIKeyResponse(
            id=i.id,
            name=i.name,
            token=None,
            scopes=i.scopes,
            created_at=i.created_at,
            enabled=i.enabled,
            last_used_at=i.last_used_at,
            metadata=i.metadata,
        )
        for i in items
    ]


# PUBLIC_INTERFACE
@app.put(
    "/keys/{key_id}",
    response_model=APIKeyResponse,
    summary="Update API key",
    description="Update name, scopes, enabled flag, or metadata of an API key.",
    tags=["keys"],
)
def update_api_key(key_id: str, payload: APIKeyUpdateRequest):
    """
    Update an API key.
    """
    rec = _api_keys.update(
        key_id,
        name=payload.name,
        scopes=payload.scopes,
        enabled=payload.enabled,
        metadata=payload.metadata,
    )
    if not rec:
        raise HTTPException(status_code=404, detail="Key not found")
    return APIKeyResponse(
        id=rec.id,
        name=rec.name,
        token=None,
        scopes=rec.scopes,
        created_at=rec.created_at,
        enabled=rec.enabled,
        last_used_at=rec.last_used_at,
        metadata=rec.metadata,
    )


# PUBLIC_INTERFACE
@app.delete(
    "/keys/{key_id}",
    summary="Delete API key",
    description="Delete an API key.",
    tags=["keys"],
)
def delete_api_key(key_id: str):
    """
    Delete API key by id.
    """
    ok = _api_keys.delete(key_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"deleted": True}


# Reports endpoints
# PUBLIC_INTERFACE
@app.post(
    "/reports",
    response_model=ReportResponse,
    summary="Generate report",
    description="Generate a simple report with basic stats over current data.",
    tags=["reports"],
)
def generate_report(payload: ReportQuery):
    """
    Generate a report and return stats.
    """
    params = {}
    if payload.service:
        params["service"] = payload.service
    if payload.endpoint_id:
        params["endpoint_id"] = payload.endpoint_id
    rep = _reports.generate(payload.title, payload.description, params)
    return ReportResponse(
        id=rep.id,
        created_at=rep.created_at,
        title=rep.title,
        description=rep.description,
        stats=rep.stats,
    )
