import json

import pytest

from sentrix.models import (
    SEVERITY_ORDER,
    Confidence,
    Evidence,
    Finding,
    Severity,
)


def make_finding(**overrides) -> Finding:
    base = {
        "id": "HTTP-001",
        "title": "CSP tidak ditemukan",
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "evidence": Evidence("missing_response_header", "content-security-policy"),
        "recommendation": "Evaluasi CSP.",
    }
    base.update(overrides)
    return Finding(**base)


def test_severity_order_matches_rank():
    assert SEVERITY_ORDER == ("HIGH", "MEDIUM", "LOW", "INFO")
    ranks = [Severity(name).rank for name in SEVERITY_ORDER]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)


def test_to_dict_keeps_report_shape_and_is_json_serializable():
    data = make_finding().to_dict()

    assert list(data) == [
        "id",
        "title",
        "severity",
        "confidence",
        "evidence",
        "recommendation",
        "status",
    ]
    assert data["severity"] == "MEDIUM"
    assert data["confidence"] == "HIGH"
    assert data["evidence"] == {
        "type": "missing_response_header",
        "header": "content-security-policy",
    }
    assert data["status"] == "observed"
    json.dumps(data)


def test_finding_is_immutable():
    finding = make_finding()

    with pytest.raises(AttributeError):
        finding.severity = Severity.HIGH  # type: ignore[misc]


def test_fingerprint_is_stable_and_ignores_wording_and_severity():
    original = make_finding()
    reworded = make_finding(
        title="Judul lain",
        recommendation="Saran lain.",
        severity=Severity.HIGH,
    )

    assert original.fingerprint == reworded.fingerprint
    assert len(original.fingerprint) == 16


def test_fingerprint_differs_when_evidence_differs():
    other = make_finding(
        evidence=Evidence("missing_response_header", "referrer-policy"),
    )

    assert make_finding().fingerprint != other.fingerprint
