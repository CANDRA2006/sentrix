"""Evaluation engine for response headers."""

from __future__ import annotations

import httpx

from sentrix.models import Evidence, Finding
from sentrix.rules.builtin import RULES
from sentrix.rules.models import Rule


def evaluate_headers(
    headers: httpx.Headers,
    is_https: bool,
    rules: tuple[Rule, ...] = RULES,
) -> list[Finding]:
    """Return one raw finding per rule that applies to the response.

    A missing-header rule applies when its header is absent or empty; a value
    rule applies when the header is present and its value is judged weak.

    Output is not deduplicated or sorted; pass it through
    ``sentrix.normalize.normalize_findings`` for that.
    """
    findings: list[Finding] = []

    for rule in rules:
        if rule.https_only and not is_https:
            continue

        value = headers.get(rule.header)

        if rule.is_weak is None:
            if value:
                continue
        elif not value or not rule.is_weak(value):
            continue

        findings.append(
            Finding(
                id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                evidence=Evidence(
                    type=rule.evidence_type,
                    header=rule.header,
                ),
                recommendation=rule.recommendation,
            )
        )

    return findings
