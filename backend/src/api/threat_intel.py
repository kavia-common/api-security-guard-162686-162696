"""
Threat Intelligence Enrichment (Static Heuristics)

This module provides lightweight, static threat enrichment for incoming events:
- Static IP reputation (bad ranges, known scanning networks, private/local nets)
- User-Agent heuristics (curl/wget/http client libraries, missing UA, automation hints)
- Suspicious parameter patterns in paths/headers/attributes (SQLi, path traversal, SSRF/URL payloads)

It returns a ThreatEnrichment object with:
- risk_score: integer 0-100 (heuristic)
- indicators: list of strings describing signals
- tags: set of normalized tags
- details: dict with additional attributes

No external dependencies or network calls; designed for MVP integration into DetectionService
and adaptive rate limiting risk decisions.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


_SQLI_PATTERN = re.compile(r"(?i)(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|--|#|/\*|\*/|\bOR\b\s+1=1)")
_PATH_TRAVERSAL = re.compile(r"(\.\./|\.\.\\)")
_URL_PATTERN = re.compile(r"https?://")
_SSRF_HINT = re.compile(r"(?i)(metadata\.google|latest/meta-data|169\.254\.169\.254)")
_JS_INJECTION = re.compile(r"(?i)<script|onerror=|onload=|javascript:")
_HEUR_BAD_UA = re.compile(r"(?i)\b(curl|wget|python-requests|httpclient|aiohttp|libwww|okhttp|nikto|sqlmap)\b")

# Simple lists of suspicious/bad networks (expandable)
_BAD_NETS = [
    # Known RFC1918 - not "bad", but if seen as source can indicate misconfiguration
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    # Loopback/link-local/reserved
    "127.0.0.0/8",
    "169.254.0.0/16",
    "0.0.0.0/8",
    # Example public blocks often used by scanning infra (placeholder ranges)
    "45.146.164.0/22",  # random example scan range
    "89.248.160.0/19",  # random example scan range
]

_BAD_NETWORKS = [ipaddress.ip_network(n) for n in _BAD_NETS]


@dataclass
class ThreatEnrichment:
    risk_score: int = 0
    indicators: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    details: Dict[str, str] = field(default_factory=dict)


def _score_add(enr: ThreatEnrichment, score: int, indicator: str, tag: str, detail_key: Optional[str] = None, detail_val: Optional[str] = None) -> None:
    enr.risk_score = max(0, min(100, enr.risk_score + score))
    enr.indicators.append(indicator)
    if tag:
        enr.tags.add(tag)
    if detail_key and detail_val is not None:
        enr.details[detail_key] = str(detail_val)


def _ip_reputation(ip: Optional[str]) -> ThreatEnrichment:
    enr = ThreatEnrichment()
    if not ip:
        return enr
    try:
        ip_addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        _score_add(enr, 5, "invalid_ip_format", "ip_invalid", "ip", ip)
        return enr

    for net in _BAD_NETWORKS:
        if ip_addr in net:
            # Private/reserved nets: lower severity; known scan ranges: higher
            if net.prefixlen >= 24 or str(net).startswith(("45.146", "89.248")):
                _score_add(enr, 25, f"ip_in_suspicious_range:{net}", "ip_suspicious_range", "network", str(net))
            else:
                _score_add(enr, 10, f"ip_in_private_or_reserved:{net}", "ip_private_reserved", "network", str(net))
            break
    return enr


def _ua_heuristics(headers: Dict[str, str]) -> ThreatEnrichment:
    enr = ThreatEnrichment()
    ua = (headers or {}).get("user-agent") or headers.get("User-Agent") or ""
    ua_norm = ua.strip()
    if not ua_norm:
        _score_add(enr, 10, "missing_user_agent", "ua_missing")
        return enr
    if _HEUR_BAD_UA.search(ua_norm):
        _score_add(enr, 15, "automation_or_scanner_user_agent", "ua_scanner", "ua", ua_norm[:200])
    # Very short UA strings are often automation
    if len(ua_norm) < 6:
        _score_add(enr, 5, "very_short_user_agent", "ua_short", "ua", ua_norm)
    return enr


def _suspicious_params(path: str, headers: Dict[str, str], attributes: Dict[str, str]) -> ThreatEnrichment:
    enr = ThreatEnrichment()
    text_blobs: List[str] = [path or ""]
    # Scan headers and attributes values
    text_blobs.extend((headers or {}).values())
    text_blobs.extend((attributes or {}).values())

    combined = " ".join([str(v) for v in text_blobs])[:5000]

    if _SQLI_PATTERN.search(combined):
        _score_add(enr, 20, "sqli_pattern_detected", "pattern_sqli")
    if _PATH_TRAVERSAL.search(combined):
        _score_add(enr, 15, "path_traversal_pattern", "pattern_traversal")
    if _URL_PATTERN.search(combined):
        _score_add(enr, 5, "embedded_url_detected", "pattern_url")
    if _SSRF_HINT.search(combined):
        _score_add(enr, 20, "ssrf_metadata_hint", "pattern_ssrf")
    if _JS_INJECTION.search(combined):
        _score_add(enr, 15, "javascript_injection_hint", "pattern_js_injection")

    # Flags for methods/paths
    lower_path = (path or "").lower()
    if any(w in lower_path for w in ("/admin", "/.git", "/.env", "/wp-admin", "/phpmyadmin")):
        _score_add(enr, 10, "sensitive_path_probe", "path_sensitive_probe", "path", path)

    return enr


# PUBLIC_INTERFACE
def enrich_threat_context(ip: Optional[str], path: str, request_headers: Dict[str, str], attributes: Dict[str, str]) -> ThreatEnrichment:
    """
    Enrich a request context with static threat intelligence heuristics.

    Inputs:
    - ip: source IP address of the request (if available)
    - path: request path string
    - request_headers: dict of incoming request headers
    - attributes: free-form attributes map

    Returns:
    - ThreatEnrichment with risk_score [0..100], indicators, tags, details.

    The risk_score is additive across IP reputation, UA heuristics, and suspicious
    parameter patterns. Consumers can clamp or weight further.
    """
    ip_enr = _ip_reputation(ip)
    ua_enr = _ua_heuristics(request_headers or {})
    pat_enr = _suspicious_params(path or "", request_headers or {}, attributes or {})

    # Merge results
    out = ThreatEnrichment()
    for part in (ip_enr, ua_enr, pat_enr):
        out.risk_score = max(0, min(100, out.risk_score + part.risk_score))
        out.indicators.extend(part.indicators)
        out.tags.update(part.tags)
        out.details.update(part.details)

    # Normalize: cap total and provide quick severity bucket
    if out.risk_score >= 60:
        out.tags.add("risk_high")
    elif out.risk_score >= 30:
        out.tags.add("risk_medium")
    elif out.risk_score > 0:
        out.tags.add("risk_low")
    else:
        out.tags.add("risk_none")
    return out
