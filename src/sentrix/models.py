"""Typed finding model shared by rules, normalization, and reporting."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    """Rule-based triage label. Not a CVSS score."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Lower rank means more severe (HIGH = 0)."""
        return _SEVERITY_RANKS[self]


# Kept as a module constant so the ordering has a single definition.
_SEVERITY_RANKS = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.INFO: 3,
}

SEVERITY_ORDER: tuple[str, ...] = tuple(
    severity.value for severity in Severity
)


class Confidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class Evidence:
    """What was observed. Never stores response header *values*."""

    type: str
    header: str

    def to_dict(self) -> dict[str, str]:
        return {"type": self.type, "header": self.header}


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    evidence: Evidence
    recommendation: str
    status: str = "observed"

    @property
    def fingerprint(self) -> str:
        """Stable identity for the same observation across scans.

        Derived from the rule id and the evidence only, so that wording
        changes to title/recommendation or severity re-triage do not make
        the same observation look like a new one.
        """
        raw = "|".join((self.id, self.evidence.type, self.evidence.header))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        """JSON-serializable form; key order is part of the report format."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence.to_dict(),
            "recommendation": self.recommendation,
            "status": self.status,
        }
