import json
from collections.abc import Callable

import httpx
import pytest
from typer.testing import CliRunner

from sentrix import cli
from sentrix.cli import app

runner = CliRunner()

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch):
    """Route every httpx.Client created by the CLI through a fake handler."""
    real_client = httpx.Client
    seen_requests: list[httpx.Request] = []

    def install(handler: Handler) -> list[httpx.Request]:
        def recording_handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(request)
            return handler(request)

        def factory(**kwargs):
            return real_client(
                transport=httpx.MockTransport(recording_handler),
                **kwargs,
            )

        monkeypatch.setattr(cli.httpx, "Client", factory)
        return seen_requests

    return install


def test_root_help_lists_check_command():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "check" in result.output


def test_check_requires_url_argument():
    result = runner.invoke(app, ["check"])

    assert result.exit_code == 2


def test_check_prints_findings_and_exits_zero(mock_http):
    mock_http(lambda request: httpx.Response(200, headers={}))

    result = runner.invoke(app, ["check", "https://example.com"])

    assert result.exit_code == 0
    assert "HTTP-001" in result.output
    assert "Findings: 5" in result.output


def test_check_with_all_headers_reports_zero_findings(mock_http):
    mock_http(
        lambda request: httpx.Response(
            200,
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            },
        )
    )

    result = runner.invoke(app, ["check", "https://example.com"])

    assert result.exit_code == 0
    assert "Findings: 0" in result.output


def test_json_report_structure(mock_http, tmp_path):
    mock_http(lambda request: httpx.Response(200, headers={}))
    report_path = tmp_path / "nested" / "report.json"

    result = runner.invoke(
        app,
        ["check", "https://example.com", "--output", str(report_path)],
    )

    assert result.exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert list(report) == [
        "schema_version",
        "tool",
        "timestamp",
        "target",
        "http",
        "summary",
        "findings",
        "limitations",
    ]
    assert report["schema_version"] == "1.0"
    assert report["tool"] == {"name": "SENTRIX", "version": "0.1.0"}
    assert report["target"]["requested_url"] == "https://example.com"
    assert report["http"]["status_code"] == 200
    assert report["http"]["final_scheme"] == "https"
    assert report["summary"]["findings"] == 5
    assert report["summary"]["by_severity"] == {
        "HIGH": 0,
        "MEDIUM": 2,
        "LOW": 2,
        "INFO": 1,
    }
    assert len(report["findings"]) == 5
    assert report["limitations"]


def test_report_does_not_include_response_header_values(mock_http, tmp_path):
    mock_http(
        lambda request: httpx.Response(
            200,
            headers={
                "Set-Cookie": "session=TOP-SECRET-VALUE",
                "Authorization": "Bearer TOP-SECRET-VALUE",
            },
        )
    )
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["check", "https://example.com", "-o", str(report_path)],
    )

    assert result.exit_code == 0
    assert "TOP-SECRET-VALUE" not in report_path.read_text(encoding="utf-8")
    assert "TOP-SECRET-VALUE" not in result.output


def test_plain_http_target_skips_hsts_in_report(mock_http, tmp_path):
    mock_http(lambda request: httpx.Response(200, headers={}))
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["check", "http://example.com", "-o", str(report_path)],
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    rule_ids = {finding["id"] for finding in report["findings"]}

    assert result.exit_code == 0
    assert report["http"]["final_scheme"] == "http"
    assert "HTTP-002" not in rule_ids


def test_redirect_is_followed_and_recorded(mock_http, tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(
                302,
                headers={"Location": "https://example.com/final"},
            )
        return httpx.Response(200, headers={})

    mock_http(handler)
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["check", "http://example.com/start", "-o", str(report_path)],
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert result.exit_code == 0
    assert report["http"]["redirect_count"] == 1
    assert report["target"]["requested_url"] == "http://example.com/start"
    assert report["target"]["final_url"] == "https://example.com/final"
    assert report["http"]["final_scheme"] == "https"


def test_redirect_loop_fails_cleanly(mock_http):
    mock_http(
        lambda request: httpx.Response(
            302,
            headers={"Location": str(request.url)},
        )
    )

    result = runner.invoke(app, ["check", "https://example.com"])

    assert result.exit_code == 1
    assert "Request gagal" in result.output


def test_network_failure_exits_with_error_and_writes_no_report(
    mock_http, tmp_path
):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    mock_http(handler)
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["check", "https://example.com", "-o", str(report_path)],
    )

    assert result.exit_code == 1
    assert "Request gagal" in result.output
    assert not report_path.exists()


def test_timeout_exits_with_error(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    mock_http(handler)

    result = runner.invoke(app, ["check", "https://example.com"])

    assert result.exit_code == 1
    assert "Request gagal" in result.output


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "not-a-url",
        "https://user:password@example.com",
    ],
)
def test_invalid_url_is_rejected_before_any_request(mock_http, url):
    seen = mock_http(lambda request: httpx.Response(200))

    result = runner.invoke(app, ["check", url])

    assert result.exit_code == 2
    assert seen == []


def test_credentials_in_url_are_not_echoed(mock_http):
    mock_http(lambda request: httpx.Response(200))

    result = runner.invoke(
        app,
        ["check", "https://user:hunter2@example.com"],
    )

    assert result.exit_code == 2
    assert "hunter2" not in result.output


def test_user_agent_identifies_the_tool(mock_http):
    seen = mock_http(lambda request: httpx.Response(200))

    runner.invoke(app, ["check", "https://example.com"])

    assert seen[0].headers["user-agent"] == "SENTRIX/0.1.0"
