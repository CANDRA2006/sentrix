import httpx

from sentrix.models import Confidence, Evidence, Finding, Severity
from sentrix.normalize import normalize_findings
from sentrix.rules import evaluate_headers


def finding(rule_id: str, header: str, severity: Severity) -> Finding:
    return Finding(
        id=rule_id,
        title=f"{header} missing",
        severity=severity,
        confidence=Confidence.HIGH,
        evidence=Evidence("missing_response_header", header),
        recommendation="Review.",
    )


def test_empty_input_returns_empty_list():
    assert normalize_findings([]) == []


def test_duplicates_are_collapsed():
    a = finding("HTTP-001", "content-security-policy", Severity.MEDIUM)

    assert normalize_findings([a, a, a]) == [a]


def test_most_severe_duplicate_wins_regardless_of_order():
    low = finding("HTTP-001", "content-security-policy", Severity.LOW)
    high = finding("HTTP-001", "content-security-policy", Severity.HIGH)

    assert normalize_findings([low, high])[0].severity is Severity.HIGH
    assert normalize_findings([high, low])[0].severity is Severity.HIGH


def test_equal_severity_duplicates_keep_first_seen():
    first = finding("HTTP-001", "content-security-policy", Severity.LOW)
    second = Finding(
        id=first.id,
        title="other title",
        severity=first.severity,
        confidence=first.confidence,
        evidence=first.evidence,
        recommendation=first.recommendation,
    )

    assert normalize_findings([first, second]) == [first]
    assert normalize_findings([second, first]) == [second]


def test_output_is_sorted_by_severity_then_id_and_input_order_is_irrelevant():
    items = [
        finding("HTTP-005", "permissions-policy", Severity.INFO),
        finding("HTTP-004", "referrer-policy", Severity.LOW),
        finding("HTTP-002", "strict-transport-security", Severity.MEDIUM),
        finding("HTTP-003", "x-content-type-options", Severity.LOW),
        finding("HTTP-001", "content-security-policy", Severity.MEDIUM),
    ]

    forward = [f.id for f in normalize_findings(items)]
    backward = [f.id for f in normalize_findings(reversed(items))]

    assert forward == ["HTTP-001", "HTTP-002", "HTTP-003", "HTTP-004", "HTTP-005"]
    assert backward == forward


def test_accepts_any_iterable_and_does_not_mutate_input():
    items = [
        finding("HTTP-003", "x-content-type-options", Severity.LOW),
        finding("HTTP-001", "content-security-policy", Severity.MEDIUM),
    ]
    snapshot = list(items)

    normalize_findings(iter(items))

    assert items == snapshot


def test_rules_produce_one_finding_per_missing_header():
    findings = evaluate_headers(httpx.Headers({}), is_https=True)

    assert [f.id for f in findings] == [
        "HTTP-001",
        "HTTP-002",
        "HTTP-003",
        "HTTP-004",
        "HTTP-005",
    ]
    assert len({f.fingerprint for f in findings}) == 5


def test_empty_header_value_counts_as_missing():
    headers = httpx.Headers({"X-Content-Type-Options": ""})

    ids = {f.id for f in evaluate_headers(headers, is_https=False)}

    assert "HTTP-003" in ids


def test_header_lookup_is_case_insensitive():
    headers = httpx.Headers({"content-SECURITY-policy": "default-src 'none'"})

    ids = {f.id for f in evaluate_headers(headers, is_https=True)}

    assert "HTTP-001" not in ids
