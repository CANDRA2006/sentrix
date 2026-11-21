"""Built-in rules: core foundational rules and extended rules."""

from __future__ import annotations

from sentrix.models import Confidence, Severity
from sentrix.rules.models import Rule
from sentrix.rules.predicates import (
    HSTS_MIN_MAX_AGE,
    cache_control_is_unprotected,
    coep_is_weak,
    coop_is_weak,
    corp_is_weak,
    cors_is_wildcard,
    csp_missing_frame_ancestors,
    csp_script_is_loose,
    hsts_is_weak,
    nosniff_is_wrong,
    referrer_policy_is_weak,
    reveals_technology,
    server_reveals_version,
    xfo_is_invalid,
)

CORE_RULES: tuple[Rule, ...] = (
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

EXTENDED_RULES: tuple[Rule, ...] = (
    Rule(
        id="HTTP-006",
        header="x-frame-options",
        title="X-Frame-Options tidak ditemukan",
        severity=Severity.MEDIUM,
        recommendation=(
            "Gunakan X-Frame-Options: DENY atau SAMEORIGIN untuk "
            "mencegah clickjacking, atau gunakan CSP frame-ancestors."
        ),
    ),
    Rule(
        id="HTTP-007",
        header="cross-origin-opener-policy",
        title="Cross-Origin-Opener-Policy (COOP) tidak ditemukan",
        severity=Severity.INFO,
        recommendation="Evaluasi penggunaan COOP: same-origin untuk isolasi side-channel.",
    ),
    Rule(
        id="HTTP-008",
        header="cross-origin-embedder-policy",
        title="Cross-Origin-Embedder-Policy (COEP) tidak ditemukan",
        severity=Severity.INFO,
        recommendation="Evaluasi penggunaan COEP: require-corp.",
    ),
    Rule(
        id="HTTP-009",
        header="cross-origin-resource-policy",
        title="Cross-Origin-Resource-Policy (CORP) tidak ditemukan",
        severity=Severity.INFO,
        recommendation="Evaluasi penggunaan CORP: same-origin.",
    ),
    Rule(
        id="HTTP-105",
        header="x-frame-options",
        title="X-Frame-Options bernilai tidak valid atau deprecated",
        severity=Severity.MEDIUM,
        recommendation="Gunakan X-Frame-Options: DENY atau SAMEORIGIN.",
        is_weak=xfo_is_invalid,
        evidence_type="weak_header_value",
    ),
    Rule(
        id="HTTP-106",
        header="content-security-policy",
        title="CSP tidak memiliki direktif frame-ancestors",
        severity=Severity.LOW,
        recommendation="Tambahkan frame-ancestors pada CSP untuk perlindungan clickjacking.",
        is_weak=csp_missing_frame_ancestors,
        evidence_type="weak_header_value",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        id="HTTP-107",
        header="access-control-allow-origin",
        title="CORS terbuka: Access-Control-Allow-Origin: *",
        severity=Severity.MEDIUM,
        recommendation="Hindari wildcard origin kecuali untuk resource publik tanpa autentikasi.",
        is_weak=cors_is_wildcard,
        evidence_type="cors_misconfiguration",
        confidence=Confidence.MEDIUM,
    ),
    Rule(
        id="HTTP-108",
        header="cache-control",
        title="Cache-Control tidak menggunakan no-store atau private",
        severity=Severity.LOW,
        recommendation="Gunakan Cache-Control: no-store pada halaman sensitif/autentikasi.",
        is_weak=cache_control_is_unprotected,
        evidence_type="weak_header_value",
        confidence=Confidence.LOW,
    ),
    Rule(
        id="HTTP-203",
        header="x-aspnet-version",
        title="X-AspNet-Version membocorkan versi framework",
        severity=Severity.LOW,
        recommendation="Nonaktifkan X-AspNet-Version di web.config.",
        is_weak=reveals_technology,
        evidence_type="information_disclosure",
    ),
    Rule(
        id="HTTP-204",
        header="x-aspnetmvc-version",
        title="X-AspNetMvc-Version membocorkan versi framework MVC",
        severity=Severity.LOW,
        recommendation="Nonaktifkan X-AspNetMvc-Version di Application_Start.",
        is_weak=reveals_technology,
        evidence_type="information_disclosure",
    ),
)

# RULES points to CORE_RULES for full backward compatibility
RULES: tuple[Rule, ...] = CORE_RULES

ALL_RULES: tuple[Rule, ...] = CORE_RULES + EXTENDED_RULES
