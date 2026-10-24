"""Report exporters: JSON, SARIF 2.1.0, and standalone HTML."""

import copy
import json
from html.parser import HTMLParser

import httpx
import pytest

from sentrix import cli
from sentrix.reporting import (
    SARIF_FINGERPRINT_KEY,
    ReportFormat,
    build_sarif,
    render_html,
    render_json,
    render_report,
    render_sarif,
)

URL = "https://example.com/app"


def make_report(
    headers: dict[str, str] | None = None, url: str = URL
) -> dict:
    """A real report, built the same way ``sentrix check`` builds it."""
    response = httpx.Response(
        200, headers=headers or {}, request=httpx.Request("GET", url)
    )
    findings = cli.analyze_headers(
        response.headers, is_https=response.url.scheme == "https"
    )
    return cli.build_report(url, response, findings)


@pytest.fixture
def report() -> dict:
    return make_report()


@pytest.fixture
def clean_report() -> dict:
    return make_report(
        {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        }
    )


# --- JSON ------------------------------------------------------------------


def test_render_json_round_trips_and_ends_with_newline(report):
    text = render_json(report)

    assert text.endswith("\n")
    assert json.loads(text) == report


def test_render_json_keeps_non_ascii_readable(report):
    report["findings"][0]["title"] = "Tidak ditemukan — café"

    assert "café" in render_json(report)


# --- SARIF -----------------------------------------------------------------


def test_sarif_top_level_shape(report):
    log = build_sarif(report)

    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    assert len(log["runs"]) == 1
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "SENTRIX"
    assert driver["version"] == report["tool"]["version"]


def test_sarif_has_one_result_per_finding_in_report_order(report):
    run = build_sarif(report)["runs"][0]

    assert [r["ruleId"] for r in run["results"]] == [
        f["id"] for f in report["findings"]
    ]


def test_sarif_rule_index_points_at_matching_rule(report):
    run = build_sarif(report)["runs"][0]
    rules = run["tool"]["driver"]["rules"]

    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_sarif_lists_each_rule_once_even_with_repeated_findings(report):
    report["findings"].append(copy.deepcopy(report["findings"][0]))

    run = build_sarif(report)["runs"][0]
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]

    assert len(rule_ids) == len(set(rule_ids))
    assert len(run["results"]) == len(report["findings"])


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("INFO", "note"),
    ],
)
def test_sarif_level_follows_severity(report, severity, level):
    report["findings"] = [dict(report["findings"][0], severity=severity)]

    run = build_sarif(report)["runs"][0]

    assert run["results"][0]["level"] == level
    assert run["tool"]["driver"]["rules"][0]["defaultConfiguration"][
        "level"
    ] == level
    # The original label survives, and no CVSS-style score is invented.
    assert run["results"][0]["properties"]["severity"] == severity
    assert "security-severity" not in run["results"][0]["properties"]
    assert "security-severity" not in run["tool"]["driver"]["rules"][0].get(
        "properties", {}
    )


def test_sarif_fingerprint_matches_finding_fingerprint(report):
    response = httpx.Response(
        200, request=httpx.Request("GET", URL)
    )
    expected = {
        finding.fingerprint
        for finding in cli.evaluate_findings(response.headers, is_https=True)
    }

    run = build_sarif(report)["runs"][0]
    actual = {
        result["partialFingerprints"][SARIF_FINGERPRINT_KEY]
        for result in run["results"]
    }

    assert actual == expected


def test_sarif_fingerprint_ignores_wording_changes(report):
    before = build_sarif(report)["runs"][0]["results"][0]
    report["findings"][0]["title"] = "Judul diganti"
    report["findings"][0]["recommendation"] = "Rekomendasi diganti"
    after = build_sarif(report)["runs"][0]["results"][0]

    assert before["partialFingerprints"] == after["partialFingerprints"]


def test_sarif_location_is_the_final_url(report):
    report["target"]["final_url"] = "https://example.com/landing"

    run = build_sarif(report)["runs"][0]

    for result in run["results"]:
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == (
            "https://example.com/landing"
        )


def test_sarif_run_properties_carry_http_context(report):
    props = build_sarif(report)["runs"][0]["properties"]

    assert props["httpStatusCode"] == 200
    assert props["redirectCount"] == 0
    assert props["limitations"] == report["limitations"]


def test_sarif_strips_userinfo_query_and_fragment(report):
    report["target"]["requested_url"] = "https://bob:pw123@example.com/a?k=SECRET#f"
    report["target"]["final_url"] = "https://example.com/b?token=SECRET2#f2"

    text = render_sarif(report)

    for secret in ("pw123", "bob", "SECRET", "SECRET2", "#f"):
        assert secret not in text
    props = json.loads(text)["runs"][0]["properties"]
    assert props["requestedUrl"] == "https://example.com/a"
    assert props["finalUrl"] == "https://example.com/b"


def test_sarif_end_time_is_utc_z_form(report):
    report["timestamp"] = "2026-10-24T07:34:56.789123+07:00"

    invocation = build_sarif(report)["runs"][0]["invocations"][0]

    assert invocation["endTimeUtc"] == "2026-10-24T00:34:56Z"
    assert invocation["executionSuccessful"] is True


def test_sarif_naive_timestamp_is_treated_as_utc(report):
    report["timestamp"] = "2026-10-24T07:34:56"

    invocation = build_sarif(report)["runs"][0]["invocations"][0]

    assert invocation["endTimeUtc"] == "2026-10-24T07:34:56Z"


def test_sarif_omits_end_time_when_timestamp_is_unparseable(report):
    report["timestamp"] = "kemarin sore"

    invocation = build_sarif(report)["runs"][0]["invocations"][0]

    assert "endTimeUtc" not in invocation


def test_sarif_with_no_findings_is_still_a_valid_log(clean_report):
    log = build_sarif(clean_report)
    run = log["runs"][0]

    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
    assert log["version"] == "2.1.0"


def test_sarif_unknown_severity_fails_loudly(report):
    report["findings"][0]["severity"] = "CRITICAL"

    with pytest.raises(ValueError):
        build_sarif(report)


def test_sarif_does_not_mutate_the_report(report):
    snapshot = copy.deepcopy(report)

    build_sarif(report)

    assert report == snapshot


# --- HTML ------------------------------------------------------------------

VOID_TAGS = {"meta", "br", "hr", "img", "input", "link", "base"}
FORBIDDEN_TAGS = {
    "script", "link", "img", "iframe", "object", "embed", "form", "base",
    "a", "button", "input", "svg", "video", "audio", "source",
}


class TagAudit(HTMLParser):
    """Collects real start tags and checks that non-void tags are closed."""

    def __init__(self) -> None:
        super().__init__()
        self.seen: list[str] = []
        self.attrs: list[tuple[str, str | None]] = []
        self.stack: list[str] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.seen.append(tag)
        self.attrs.extend(attrs)
        if tag not in VOID_TAGS:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> with stack {self.stack}")
        else:
            self.stack.pop()


def audit(html: str) -> TagAudit:
    parser = TagAudit()
    parser.feed(html)
    parser.close()
    return parser


def test_html_is_well_formed_and_self_contained(report):
    parsed = audit(render_html(report))

    assert parsed.errors == []
    assert parsed.stack == []
    assert not FORBIDDEN_TAGS & set(parsed.seen)
    # Nothing fetches or links to another resource.
    assert not {"src", "href", "srcset", "action"} & {
        name for name, _ in parsed.attrs
    }
    assert not any(
        name.startswith("on") for name, _ in parsed.attrs
    )


def test_html_declares_doctype_charset_and_restrictive_csp(report):
    html = render_html(report)

    assert html.startswith("<!DOCTYPE html>")
    assert '<meta charset="utf-8">' in html
    assert "default-src 'none'" in html
    assert "style-src 'unsafe-inline'" in html
    assert '<html lang="id">' in html


def test_html_shows_target_status_and_every_finding(report):
    html = render_html(report)

    assert "https://example.com/app" in html
    for finding in report["findings"]:
        assert finding["id"] in html
        assert finding["title"] in html
    assert "Total <strong>5</strong>" in html


def test_html_escapes_every_dynamic_value(report):
    payload = "<script>alert(1)</script>"
    attr_payload = '"><img src=x onerror=alert(1)>'
    report["tool"]["name"] = payload
    report["tool"]["version"] = payload
    report["schema_version"] = payload
    report["timestamp"] = payload
    report["http"]["status_code"] = payload
    report["http"]["redirect_count"] = payload
    report["findings"][0].update(
        id=payload,
        title=payload,
        severity=payload,
        confidence=attr_payload,
        recommendation=attr_payload,
    )
    report["findings"][0]["evidence"]["header"] = payload
    report["limitations"] = [payload, attr_payload]

    html = render_html(report)
    parsed = audit(html)

    assert "<script" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html
    assert not {"script", "img"} & set(parsed.seen)
    assert not any(name.startswith("on") for name, _ in parsed.attrs)
    assert parsed.errors == []


def test_html_badge_class_comes_from_an_allowlist(report):
    report["findings"][0]["severity"] = 'x" onmouseover="alert(1)'

    html = render_html(report)
    parsed = audit(html)

    assert "sev-unknown" in html
    assert not any(name == "onmouseover" for name, _ in parsed.attrs)


def test_html_strips_userinfo_query_and_fragment(report):
    report["target"]["requested_url"] = "https://bob:pw123@example.com/a?k=SECRET#f"
    report["target"]["final_url"] = "https://example.com/b?token=SECRET2#f2"

    html = render_html(report)

    for secret in ("pw123", "bob", "SECRET", "SECRET2"):
        assert secret not in html
    assert "https://example.com/a" in html
    assert "https://example.com/b" in html


def test_html_empty_state_does_not_claim_the_target_is_safe(clean_report):
    html = render_html(clean_report)

    assert "Tidak ada temuan" in html
    assert "bukan bukti" in html
    assert "<table" not in html


def test_html_lists_limitations(report):
    html = render_html(report)

    for text in report["limitations"]:
        assert text in html


# --- cross-format ----------------------------------------------------------


@pytest.mark.parametrize("fmt", list(ReportFormat))
def test_no_format_leaks_response_header_values(fmt):
    report = make_report(
        {"Set-Cookie": "session=TOP-SECRET-VALUE", "X-Api-Key": "TOP-SECRET-VALUE"}
    )

    assert "TOP-SECRET-VALUE" not in render_report(report, fmt)


@pytest.mark.parametrize("fmt", list(ReportFormat))
def test_rendering_is_deterministic(report, fmt):
    assert render_report(report, fmt) == render_report(report, fmt)


@pytest.mark.parametrize(
    ("fmt", "renderer"),
    [
        (ReportFormat.JSON, render_json),
        (ReportFormat.SARIF, render_sarif),
        (ReportFormat.HTML, render_html),
    ],
)
def test_render_report_dispatches_to_the_matching_renderer(
    report, fmt, renderer
):
    assert render_report(report, fmt) == renderer(report)


def test_render_report_rejects_unknown_format(report):
    with pytest.raises(ValueError):
        render_report(report, "pdf")  # type: ignore[arg-type]


def test_report_format_values_are_the_cli_spellings():
    assert [fmt.value for fmt in ReportFormat] == ["json", "sarif", "html"]
