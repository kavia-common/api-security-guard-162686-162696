"""
OWASP rules and lightweight checks used by detectors.

This module provides simple, explainable signatures and thresholds that approximate
common OWASP API Security Top 10 issues for an MVP. It is intentionally simple and
does not require external ML dependencies.

Rules include:
- Sensitive data exposure via headers or paths
- Potential BOLA/BOPLA indicators (resource ID access patterns)
- Suspicious methods to sensitive paths
- Excessive payload sizes

These rules are used as heuristics by detectors and mapped to remediation guidance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class Rule:
    """Represents a simple OWASP heuristic rule."""
    id: str
    title: str
    description: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"


# A small catalog of rules
OWASP_RULES: Dict[str, Rule] = {
    "OWASP-API7-HEADER-TOKEN-LEAK": Rule(
        id="OWASP-API7-HEADER-TOKEN-LEAK",
        title="Potential sensitive token in response headers",
        description="Response headers appear to include sensitive tokens or credentials.",
        severity="high",
    ),
    "OWASP-API3-BO": Rule(
        id="OWASP-API3-BO",
        title="Potential Broken Object Level Authorization",
        description="Access pattern may suggest ID-based resource access without proper authorization.",
        severity="high",
    ),
    "OWASP-API4-RATE": Rule(
        id="OWASP-API4-RATE",
        title="Potential Lack of Resource Rate Limiting",
        description="Observed traffic indicates possible rate limiting concerns at the endpoint.",
        severity="medium",
    ),
    "OWASP-API10-MASS-ASSIGNMENT": Rule(
        id="OWASP-API10-MASS-ASSIGNMENT",
        title="Potential Mass Assignment / large payload",
        description="Request payload or declared size appears unusually large for the endpoint.",
        severity="medium",
    ),
    "OWASP-API8-SEC-MISCONFIG": Rule(
        id="OWASP-API8-SEC-MISCONFIG",
        title="Potential Security Misconfiguration",
        description="Suspicious method used on a potentially sensitive path.",
        severity="medium",
    ),
}


SENSITIVE_HEADER_KEYS = {"authorization", "x-api-key", "x-auth-token", "set-cookie"}
SENSITIVE_PATH_KEYWORDS = {"admin", "internal", "private", "secret"}
SUSPECT_METHODS = {"PUT", "DELETE", "PATCH"}
LARGE_PAYLOAD_THRESHOLD_BYTES = 1_000_000  # 1 MB


def check_sensitive_header_leak(response_headers: Dict[str, str]) -> Optional[Rule]:
    """Check if response headers include potentially sensitive values."""
    for key, value in (response_headers or {}).items():
        k = (key or "").strip().lower()
        v = (value or "")
        if k in SENSITIVE_HEADER_KEYS and v:
            return OWASP_RULES["OWASP-API7-HEADER-TOKEN-LEAK"]
    return None


def check_sensitive_path_method(method: str, path: str) -> Optional[Rule]:
    """Check for sensitive path with destructive method."""
    m = (method or "").upper()
    lower_path = (path or "").lower()
    if any(word in lower_path for word in SENSITIVE_PATH_KEYWORDS) and m in SUSPECT_METHODS:
        return OWASP_RULES["OWASP-API8-SEC-MISCONFIG"]
    return None


def check_large_payload(payload_size: Optional[int]) -> Optional[Rule]:
    """Heuristic for mass-assignment or unusually large payloads."""
    if payload_size is not None and payload_size > LARGE_PAYLOAD_THRESHOLD_BYTES:
        return OWASP_RULES["OWASP-API10-MASS-ASSIGNMENT"]
    return None


def rule_to_remediation(rule_id: str) -> Tuple[str, List[str]]:
    """
    Map a rule id to a brief remediation title and steps.

    Returns:
        (short_title, steps)
    """
    mapping: Dict[str, Tuple[str, List[str]]] = {
        "OWASP-API7-HEADER-TOKEN-LEAK": (
            "Avoid leaking tokens in headers",
            [
                "Remove sensitive tokens from response headers.",
                "Use HttpOnly, Secure cookies for session where applicable.",
                "Filter and redact sensitive headers before sending responses.",
            ],
        ),
        "OWASP-API3-BO": (
            "Enforce object-level authorization",
            [
                "Implement authorization checks at the object/resource level.",
                "Use user context or roles to ensure access to owned resources only.",
                "Add explicit allow-lists for fields and IDs that can be accessed.",
            ],
        ),
        "OWASP-API4-RATE": (
            "Apply rate limiting",
            [
                "Enforce per-IP, per-key, and per-endpoint rate limits.",
                "Add exponential backoff and proper HTTP 429 responses.",
                "Monitor usage and adjust policies based on traffic patterns.",
            ],
        ),
        "OWASP-API10-MASS-ASSIGNMENT": (
            "Validate payloads and whitelist fields",
            [
                "Define explicit input schemas and whitelist accepted fields.",
                "Reject or limit large payloads for sensitive endpoints.",
                "Add server-side size validation and schema enforcement.",
            ],
        ),
        "OWASP-API8-SEC-MISCONFIG": (
            "Harden sensitive endpoints",
            [
                "Restrict methods to least privilege needed for the endpoint.",
                "Require stronger authN/Z and logging on sensitive paths.",
                "Disable or restrict access to admin/private/internal routes.",
            ],
        ),
    }
    if rule_id in mapping:
        return mapping[rule_id]
    # Fallback
    rule = OWASP_RULES.get(rule_id)
    return (rule.title if rule else "General remediation", ["Review endpoint configuration and apply secure defaults."])
