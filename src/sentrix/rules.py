"""Deterministic response-header rules."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from sentrix.models import Confidence, Evidence, Finding, Severity


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    header: str
    title: str
    severity: Severity
    recommendation: str
    https_only: bool = False


RULES: tuple[Rule, ...] = (
    Rule(
        id="HTTP-001",
        header="content-security-policy",
        title="Content Security Policy tidak ditemukan",
        severity=Severity.MEDIUM,
        recommendation=(
            "Evaluasi Content-Security-Policy sesuai "
            "arsitektur aplikasi dan uji sebelum diterapkan."
        ),
    ),
    Rule(
        id="HTTP-002",
        header="strict-transport-security",
        title="HSTS tidak ditemukan",
        severity=Severity.MEDIUM,
        recommendation=(
            "Untuk situs HTTPS, evaluasi Strict-Transport-Security "
            "setelah memastikan seluruh alur mendukung HTTPS."
        ),
        https_only=True,
    ),
    Rule(
        id="HTTP-003",
        header="x-content-type-options",
        title="X-Content-Type-Options tidak ditemukan",
        severity=Severity.LOW,
        recommendation="Evaluasi penggunaan X-Content-Type-Options: nosniff.",
    ),
    Rule(
        id="HTTP-004",
        header="referrer-policy",
        title="Referrer-Policy tidak ditemukan",
        severity=Severity.LOW,
        recommendation="Tentukan Referrer-Policy yang sesuai kebutuhan privasi.",
    ),
    Rule(
        id="HTTP-005",
        header="permissions-policy",
        title="Permissions-Policy tidak ditemukan",
        severity=Severity.INFO,
        recommendation="Evaluasi pembatasan fitur browser yang tidak diperlukan.",
    ),
)


def evaluate_headers(
    headers: httpx.Headers,
    is_https: bool,
    rules: tuple[Rule, ...] = RULES,
) -> list[Finding]:
    """Return one raw finding per rule whose header is absent or empty.

    Output is not deduplicated or sorted; pass it through
    ``sentrix.normalize.normalize_findings`` for that.
    """
    findings: list[Finding] = []

    for rule in rules:
        if rule.https_only and not is_https:
            continue

        if headers.get(rule.header):
            continue

        findings.append(
            Finding(
                id=rule.id,
                title=rule.title,
                severity=rule.severity,
                confidence=Confidence.HIGH,
                evidence=Evidence(
                    type="missing_response_header",
                    header=rule.header,
                ),
                recommendation=rule.recommendation,
            )
        )

    return findings
