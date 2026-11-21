"""Rule data model."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sentrix.models import Confidence, Severity


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    header: str
    title: str
    severity: Severity
    recommendation: str
    https_only: bool = False
    # None: a "missing header" rule, which fires when the header is absent
    # or empty. A predicate: a "value" rule, which fires when the header IS
    # present and the predicate says its value is a problem. The value is
    # only inspected, never copied into a finding.
    is_weak: Callable[[str], bool] | None = None
    evidence_type: str = "missing_response_header"
    confidence: Confidence = Confidence.HIGH
