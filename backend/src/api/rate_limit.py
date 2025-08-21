"""
Adaptive Rate Limiting Middleware and helpers.

This module provides a Starlette/FastAPI middleware implementing adaptive, per-key
rate limiting with dynamic limit adjustments informed by the anomaly detector.

Design highlights:
- Tracks counters per API key, endpoint, and IP using an in-memory sliding window.
- Consults RateLimitRepository for baseline policies (scope: ip | api_key | service | endpoint).
- Applies simple penalty/backoff when anomalies or breaches occur; penalties decay over time.
- Emits "rate_limit" events to EventRepository on limit breaches (429) and adjustments.
- Exposes status queries via helper functions (used by main.py endpoints).

Note:
- This is an MVP in-memory implementation intended to integrate with the existing
  repositories. It can later be replaced with Redis-based counters while preserving
  interfaces in this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .models import EventType
from .storage import RateLimitRepository, EventRepository, APIDescriptorRepository


@dataclass
class _WindowCounter:
    # Sliding window timestamps
    hits: List[datetime] = field(default_factory=list)

    def add_and_allowed(self, capacity: int, per_seconds: int, now: Optional[datetime] = None) -> bool:
        """Append a hit if allowed according to sliding window, returns True if allowed."""
        now = now or datetime.utcnow()
        start = now - timedelta(seconds=per_seconds)
        self.hits[:] = [t for t in self.hits if t >= start]
        if len(self.hits) < capacity:
            self.hits.append(now)
            return True
        return False

    def count_in_window(self, per_seconds: int, now: Optional[datetime] = None) -> int:
        now = now or datetime.utcnow()
        start = now - timedelta(seconds=per_seconds)
        self.hits[:] = [t for t in self.hits if t >= start]
        return len(self.hits)


@dataclass
class _Penalty:
    # Multiplicative penalty factor applied to capacity (lower means stricter)
    factor: float = 1.0
    # When penalty was last updated
    updated_at: datetime = field(default_factory=datetime.utcnow)
    # Expires/decays towards 1.0 over time
    def value(self) -> float:
        # Linear decay: every 60s move 20% back to 1.0
        now = datetime.utcnow()
        elapsed = (now - self.updated_at).total_seconds()
        if elapsed <= 0:
            return self.factor
        steps = int(elapsed // 60)
        val = self.factor
        for _ in range(steps):
            val = 1.0 - (1.0 - val) * 0.8  # move 80% toward 1.0 per minute
        return max(0.1, min(1.0, val))  # clamp

    def apply_penalty(self, increment: float = 0.2) -> None:
        """Increase penalty by reducing factor; increment is the additional strictness (0..1)."""
        current = self.value()
        # Increase strictness: move 'increment' fraction closer to 0.1 (min)
        target = max(0.1, current - increment)
        self.factor = target
        self.updated_at = datetime.utcnow()


class AdaptiveRateLimiter:
    """
    Core engine for adaptive rate limiting.

    Responsibilities:
    - Determine key per request based on configured scopes.
    - Calculate effective capacity for a key considering penalties.
    - Enforce sliding window; record counters per (scope, key, endpoint).
    - Emit events on breaches.
    """

    def __init__(
        self,
        rate_limits: RateLimitRepository,
        events: EventRepository,
        api_catalog: APIDescriptorRepository,
        service_name: str = "backend",
    ) -> None:
        self._rate_limits = rate_limits
        self._events = events
        self._api_catalog = api_catalog
        self._service = service_name

        # Internal per (scope:key:endpoint) window counters
        self._counters: Dict[Tuple[str, str, str], _WindowCounter] = {}
        # Internal penalties map per (scope:key:endpoint)
        self._penalties: Dict[Tuple[str, str, str], _Penalty] = {}

    def _endpoint_key(self, request: Request) -> str:
        method = request.method.upper()
        path = request.url.path
        # Attempt to map to a known API descriptor id if exists (service:METHOD:/path)
        return f"{self._service}:{method}:{path}"

    def _extract_api_key(self, request: Request) -> Optional[str]:
        # Common placements: header x-api-key or Authorization: Bearer <token>
        token = request.headers.get("x-api-key")
        if token:
            return token
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip() or None
        return None

    def _scope_key(self, scope: str, request: Request) -> Optional[str]:
        scope = scope.lower()
        if scope == "ip":
            # Prefer x-forwarded-for, fallback to client host
            xff = request.headers.get("x-forwarded-for")
            if xff:
                return xff.split(",")[0].strip()
            client = request.client.host if request.client else None
            return client
        if scope == "api_key":
            return self._extract_api_key(request)
        if scope == "service":
            return self._service
        if scope == "endpoint":
            return self._endpoint_key(request)
        # Unknown scope; ignore
        return None

    def _effective_capacity(self, base_requests: int, key: Tuple[str, str, str]) -> int:
        penalty = self._penalties.get(key)
        factor = penalty.value() if penalty else 1.0
        cap = max(1, int(base_requests * factor))
        return cap

    def _apply_penalty(self, key: Tuple[str, str, str], increment: float = 0.2) -> None:
        pen = self._penalties.setdefault(key, _Penalty())
        pen.apply_penalty(increment=increment)

    def _record_breach_event(self, request: Request, scope: str, scope_key: str, endpoint: str, status_code: int) -> None:
        try:
            self._events.add(
                {
                    "event_type": EventType.RATE_LIMIT,
                    "service": self._service,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": status_code,
                    "latency_ms": None,
                    "ip": request.client.host if request.client else None,
                    "api_key_id": None,
                    "request_headers": {"scope": scope, "scope_key": scope_key},
                    "response_headers": {},
                    "payload_size": None,
                    "attributes": {"endpoint": endpoint, "reason": "rate_limit_breach"},
                }
            )
        except Exception:
            # Never block due to event logging errors
            pass

    def evaluate(self, request: Request) -> Optional[JSONResponse]:
        """
        Evaluate request against active policies. If a breach occurs, return a Response (429).
        Otherwise, return None to allow request to proceed.
        """
        endpoint = self._endpoint_key(request)
        now = datetime.utcnow()
        policies = [p for p in self._rate_limits.list() if p.enabled]
        breached_reasons: List[Dict[str, str]] = []

        for policy in policies:
            scope_key = self._scope_key(policy.scope, request)
            if not scope_key:
                continue
            # Counter key per (scope, scope_key, endpoint)
            ckey = (policy.scope, scope_key, endpoint)
            counter = self._counters.setdefault(ckey, _WindowCounter())

            eff_capacity = self._effective_capacity(policy.requests, ckey)
            allowed = counter.add_and_allowed(eff_capacity, policy.per_seconds, now=now)
            if not allowed:
                # Apply penalty for this scope/endpoint
                self._apply_penalty(ckey, increment=0.2)
                self._record_breach_event(request, policy.scope, scope_key, endpoint, 429)
                breached_reasons.append(
                    {
                        "policy_id": policy.id,
                        "name": policy.name,
                        "scope": policy.scope,
                        "scope_key": scope_key,
                        "requests": str(policy.requests),
                        "per_seconds": str(policy.per_seconds),
                        "effective_capacity": str(eff_capacity),
                    }
                )

        if breached_reasons:
            # Combine reasons; expose rate-limit headers
            headers = {
                "Retry-After": "1",
                "X-RateLimit-Policy-Count": str(len(breached_reasons)),
            }
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "breaches": breached_reasons,
                },
                headers=headers,
            )

        return None

    # PUBLIC_INTERFACE
    def status(self) -> Dict:
        """Return current in-memory counters and penalties snapshot for observability."""
        out: Dict[str, Dict] = {}
        # Group by scope
        for (scope, scope_key, endpoint), counter in self._counters.items():
            pen = self._penalties.get((scope, scope_key, endpoint))
            key = f"{scope}:{scope_key}"
            entry = out.setdefault(key, {"endpoints": {}})
            entry["endpoints"][endpoint] = {
                "recent_hits": len(counter.hits),
                "last_hit_at": max(counter.hits).isoformat() if counter.hits else None,
                "penalty_factor": (pen.value() if pen else 1.0),
                "penalty_updated_at": (pen.updated_at.isoformat() if pen else None),
            }
        return out


class AdaptiveRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware wrapper around AdaptiveRateLimiter.

    PUBLIC_INTERFACE
    """

    def __init__(
        self,
        app,
        limiter: AdaptiveRateLimiter,
    ) -> None:
        """
        Initialize the middleware with a limiter instance.
        """
        super().__init__(app)
        self._limiter = limiter

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Intercept an incoming request and enforce adaptive rate limits.

        Returns a 429 JSONResponse when the request exceeds limits; otherwise
        forwards to the next handler.
        """
        # Skip middleware endpoints for observability to avoid recursion
        if request.url.path in ("/rate-limits", "/rate-limits/status"):
            return await call_next(request)

        breach = self._limiter.evaluate(request)
        if breach is not None:
            return breach
        return await call_next(request)


# PUBLIC_INTERFACE
def build_adaptive_rate_limiter(
    rate_limits: RateLimitRepository,
    events: EventRepository,
    api_catalog: APIDescriptorRepository,
    service_name: str = "backend",
) -> AdaptiveRateLimiter:
    """Factory for AdaptiveRateLimiter to be used from main.py."""
    return AdaptiveRateLimiter(rate_limits=rate_limits, events=events, api_catalog=api_catalog, service_name=service_name)
