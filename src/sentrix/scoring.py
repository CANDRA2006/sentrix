"""Security scoring and grading (A–F) ala securityheaders.com.

Provides a deterministic score based on findings and their severity.
The score is a simple weighted sum; the grade maps it to A–F.
"""

from __future__ import annotations

from dataclasses import dataclass


# Weight per finding severity (subtracted from 100)
_SEVERITY_WEIGHTS = {
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 8,
    "INFO": 3,
}

# Grade thresholds
_GRADE_THRESHOLDS = (
    (90, "A"),
    (80, "B"),
    (65, "C"),
    (50, "D"),
    (35, "E"),
    (0, "F"),
)


@dataclass(frozen=True, slots=True)
class SecurityScore:
    """Numerical score (0–100) and letter grade (A–F)."""
    score: int
    grade: str
    max_score: int = 100

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "max_score": self.max_score,
        }


def compute_score(findings: list[dict]) -> SecurityScore:
    """Compute a security score from a list of finding dicts.

    Starts at 100 and subtracts based on severity weights.
    Score is clamped to [0, 100].
    """
    penalty = 0
    for finding in findings:
        severity = finding.get("severity", "INFO")
        penalty += _SEVERITY_WEIGHTS.get(severity, 3)

    score = max(0, min(100, 100 - penalty))

    grade = "F"
    for threshold, letter in _GRADE_THRESHOLDS:
        if score >= threshold:
            grade = letter
            break

    return SecurityScore(score=score, grade=grade)
