"""
Remediation Guidance

Maps detected rule ids and findings into actionable remediation guidance for users.
This module is intentionally lightweight and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .owasp_rules import rule_to_remediation


@dataclass
class Remediation:
    rule_id: Optional[str]
    title: str
    steps: List[str]


class Remediator:
    """Provides remediation guidance for a given rule id."""

    # PUBLIC_INTERFACE
    def for_rule(self, rule_id: Optional[str]) -> Optional[Remediation]:
        """
        Return remediation for a rule. If rule_id is None, return None to keep responses concise.
        """
        if not rule_id:
            return None
        title, steps = rule_to_remediation(rule_id)
        return Remediation(rule_id=rule_id, title=title, steps=steps)
