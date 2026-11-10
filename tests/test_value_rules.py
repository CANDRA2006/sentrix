"""Rules that judge the *value* of a header that is present."""

import httpx
import pytest

from sentrix.models import Confidence, Severity
from sentrix.policy import apply_policy, load_policy
from sentrix.rules import (
    HSTS_MIN_MAX_AGE,
    RULES,
    csp_script_is_loose,
    evaluate_headers,
    hsts_is_weak,
    nosniff_is_wrong,
    referrer_policy_is_weak,
    server_reveals_version,
)

GOOD = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


def ids(headers: dict[str, str], *, https: bool = True) -> set[str]:
    return {
        finding.id
        for finding in evaluate_headers(httpx.Headers(headers), https)
    }


def test_rule_ids_are_unique():
    assert len({rule.id for rule in RULES}) == len(RULES)


def test_well_configured_response_has_no_findings():
    assert ids(GOOD) == set()


def test_missing_and_value_rules_never_fire_for_the_same_header():
    # An absent header is a missing-header finding only; value rules need a
    # value to judge.
    assert ids({}) == {f"HTTP-00{n}" for n in range(1, 6)}


# --- HSTS -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "weak"),
    [
        ("max-age=0", True),
        ("max-age=300", True),
        ("includeSubDomains", True),
        ("max-age=", True),
        ("max-age=abc", True),
        ("xmax-age=31536000", True),          # bukan direktif max-age
        (f"max-age={HSTS_MIN_MAX_AGE - 1}", True),
        (f"max-age={HSTS_MIN_MAX_AGE}", False),
        ('max-age="31536000"', False),
        ("includeSubDomains; MAX-AGE = 31536000", False),
    ],
)
def test_hsts_is_weak(value, weak):
    assert hsts_is_weak(value) is weak


def test_weak_hsts_is_reported_over_https_only():
    headers = {**GOOD, "Strict-Transport-Security": "max-age=0"}

    assert "HTTP-101" in ids(headers, https=True)
    assert "HTTP-101" not in ids(headers, https=False)


# --- CSP ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("policy", "loose"),
    [
        ("default-src 'self'", False),
        ("default-src 'self'; frame-ancestors 'none'", False),
        ("default-src 'self'; script-src 'self' 'unsafe-inline'", True),
        ("script-src 'self' 'unsafe-eval'", True),
        ("script-src *", True),
        ("default-src https:", True),
        ("script-src 'self' data:", True),
        ("SCRIPT-SRC 'SELF' 'UNSAFE-INLINE'", True),
        # browsers ignore 'unsafe-inline' next to a nonce or hash
        ("script-src 'nonce-abc123' 'unsafe-inline'", False),
        ("script-src 'sha256-abc=' 'unsafe-inline'", False),
        # a loose directive that does not govern scripts is not reported
        ("default-src 'self'; img-src *", False),
        # script-src overrides default-src
        ("default-src *; script-src 'self'", False),
        # first occurrence of a directive wins
        ("script-src 'self'; script-src *", False),
        ("", False),
    ],
)
def test_csp_script_is_loose(policy, loose):
    assert csp_script_is_loose(policy) is loose


def test_loose_csp_finding_has_medium_confidence():
    findings = evaluate_headers(
        httpx.Headers({**GOOD, "Content-Security-Policy": "script-src *"}),
        True,
    )
    finding = next(f for f in findings if f.id == "HTTP-102")

    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.MEDIUM


# --- nosniff / referrer ---------------------------------------------------


@pytest.mark.parametrize(
    ("value", "wrong"),
    [("nosniff", False), ("NoSniff", False), ("nosniff, nosniff", False),
     ("sniff", True), ("1", True), ("", True)],
)
def test_nosniff_is_wrong(value, wrong):
    assert nosniff_is_wrong(value) is wrong


@pytest.mark.parametrize(
    ("value", "weak"),
    [
        ("unsafe-url", True),
        ("no-referrer-when-downgrade", True),
        ("no-referrer", False),
        ("strict-origin-when-cross-origin", False),
        ("unsafe-url, strict-origin", False),   # the last value applies
        ("strict-origin, unsafe-url", True),
        ("UNSAFE-URL", True),
    ],
)
def test_referrer_policy_is_weak(value, weak):
    assert referrer_policy_is_weak(value) is weak


# --- disclosure -----------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "reveals"),
    [
        ("nginx/1.18.0", True),
        ("Apache/2.4.41 (Ubuntu)", True),
        ("Microsoft-IIS/10.0", True),
        ("nginx", False),
        ("cloudflare", False),
    ],
)
def test_server_reveals_version(value, reveals):
    assert server_reveals_version(value) is reveals


def test_x_powered_by_is_reported_when_present_and_non_empty():
    assert "HTTP-202" in ids({**GOOD, "X-Powered-By": "Express"})
    assert "HTTP-202" not in ids({**GOOD, "X-Powered-By": "  "})
    assert "HTTP-202" not in ids(GOOD)


# --- privacy & policy -----------------------------------------------------


def test_header_values_never_appear_in_findings():
    secret = "nginx/9.9.9-SECRET-BUILD"
    findings = evaluate_headers(
        httpx.Headers({**GOOD, "Server": secret}), True
    )

    assert any(f.id == "HTTP-201" for f in findings)
    for finding in findings:
        assert secret not in repr(finding)
        assert secret not in repr(finding.to_dict())


def test_value_rules_use_their_own_evidence_type_and_fingerprint():
    weak = next(
        f
        for f in evaluate_headers(
            httpx.Headers({**GOOD, "Strict-Transport-Security": "max-age=1"}),
            True,
        )
        if f.id == "HTTP-101"
    )
    missing = next(
        f
        for f in evaluate_headers(httpx.Headers({}), True)
        if f.id == "HTTP-002"
    )

    assert weak.evidence.type == "weak_header_value"
    assert missing.evidence.type == "missing_response_header"
    assert weak.fingerprint != missing.fingerprint


def test_policy_can_disable_and_retriage_value_rules(tmp_path):
    config = tmp_path / "sentrix.toml"
    config.write_text(
        '[rules.HTTP-102]\nenabled = false\n'
        '[rules.HTTP-201]\nseverity = "MEDIUM"\n',
        encoding="utf-8",
    )
    effective = apply_policy(RULES, load_policy(config))
    headers = httpx.Headers(
        {**GOOD, "Content-Security-Policy": "script-src *", "Server": "x/1.0"}
    )

    findings = {f.id: f for f in evaluate_headers(headers, True, effective)}

    assert "HTTP-102" not in findings
    assert findings["HTTP-201"].severity is Severity.MEDIUM
