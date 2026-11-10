"""Deterministic response-header rules."""

from __future__ import annotations

import re
from collections.abc import Callable
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
    # None: a "missing header" rule, which fires when the header is absent
    # or empty. A predicate: a "value" rule, which fires when the header IS
    # present and the predicate says its value is a problem. The value is
    # only inspected, never copied into a finding.
    is_weak: Callable[[str], bool] | None = None
    evidence_type: str = "missing_response_header"
    confidence: Confidence = Confidence.HIGH


# Roughly 180 days, a common baseline for HSTS.
HSTS_MIN_MAX_AGE = 15_552_000
_CSP_BROAD_SOURCES = frozenset({"*", "http:", "https:", "data:"})
_CSP_NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
_WEAK_REFERRER_POLICIES = frozenset({"unsafe-url", "no-referrer-when-downgrade"})


def hsts_is_weak(value: str) -> bool:
    """No usable ``max-age`` directive, or one shorter than the baseline."""
    for part in value.split(";"):
        name, _, raw = part.strip().partition("=")
        if name.strip().lower() != "max-age":
            continue
        raw = raw.strip().strip('"')
        return not raw.isdecimal() or int(raw) < HSTS_MIN_MAX_AGE
    return True


def csp_script_is_loose(value: str) -> bool:
    """The effective script policy allows inline/eval code or any origin.

    Follows the spec: the first occurrence of a directive wins, and
    ``script-src`` falls back to ``default-src``. Browsers ignore
    ``'unsafe-inline'`` when a nonce or hash is present, so that case is not
    reported.
    """
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(
                tokens[0].lower(), [token.lower() for token in tokens[1:]]
            )

    sources = directives.get("script-src", directives.get("default-src"))
    if sources is None:
        return False

    has_nonce_or_hash = any(
        source.startswith(_CSP_NONCE_OR_HASH) or source == "'strict-dynamic'"
        for source in sources
    )
    if "'unsafe-eval'" in sources:
        return True
    if "'unsafe-inline'" in sources and not has_nonce_or_hash:
        return True
    return any(source in _CSP_BROAD_SOURCES for source in sources)


def nosniff_is_wrong(value: str) -> bool:
    """``nosniff`` is the only value browsers act on."""
    return value.split(",")[0].strip().lower() != "nosniff"


def referrer_policy_is_weak(value: str) -> bool:
    """The last listed policy is the one that applies."""
    tokens = [token.strip().lower() for token in value.split(",")]
    effective = next((token for token in reversed(tokens) if token), "")
    return effective in _WEAK_REFERRER_POLICIES


def server_reveals_version(value: str) -> bool:
    return re.search(r"\d+\.\d+", value) is not None


def reveals_technology(value: str) -> bool:
    return bool(value.strip())


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
    Rule(
        id="HTTP-101",
        header="strict-transport-security",
        title="HSTS tidak efektif (max-age hilang, nol, atau kurang dari 180 hari)",
        severity=Severity.LOW,
        recommendation=(
            "Gunakan max-age minimal 15552000 (180 hari) setelah HTTPS "
            "stabil; max-age=0 justru menghapus kebijakan HSTS di browser."
        ),
        https_only=True,
        is_weak=hsts_is_weak,
        evidence_type="weak_header_value",
    ),
    Rule(
        id="HTTP-102",
        header="content-security-policy",
        title="Content-Security-Policy mengizinkan script yang longgar",
        severity=Severity.MEDIUM,
        recommendation=(
            "Hindari 'unsafe-inline', 'unsafe-eval', wildcard, dan skema "
            "umum (http:, https:, data:) pada kebijakan script; gunakan "
            "nonce atau hash."
        ),
        is_weak=csp_script_is_loose,
        evidence_type="weak_header_value",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        id="HTTP-103",
        header="x-content-type-options",
        title="X-Content-Type-Options bukan 'nosniff'",
        severity=Severity.LOW,
        recommendation="Satu-satunya nilai yang dikenali browser adalah nosniff.",
        is_weak=nosniff_is_wrong,
        evidence_type="weak_header_value",
    ),
    Rule(
        id="HTTP-104",
        header="referrer-policy",
        title="Referrer-Policy mengirim URL lengkap ke pihak lain",
        severity=Severity.LOW,
        recommendation=(
            "Pertimbangkan strict-origin-when-cross-origin atau kebijakan "
            "yang lebih ketat."
        ),
        is_weak=referrer_policy_is_weak,
        evidence_type="weak_header_value",
    ),
    Rule(
        id="HTTP-201",
        header="server",
        title="Header Server membocorkan versi perangkat lunak",
        severity=Severity.LOW,
        recommendation=(
            "Sembunyikan atau sederhanakan nilai Server agar versi tidak "
            "mudah dipetakan."
        ),
        is_weak=server_reveals_version,
        evidence_type="information_disclosure",
    ),
    Rule(
        id="HTTP-202",
        header="x-powered-by",
        title="X-Powered-By membocorkan teknologi aplikasi",
        severity=Severity.LOW,
        recommendation="Nonaktifkan X-Powered-By bila tidak dibutuhkan.",
        is_weak=reveals_technology,
        evidence_type="information_disclosure",
    ),
)


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
