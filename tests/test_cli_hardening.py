"""CLI behaviour for malformed input, request options, and value rules."""

import json
from collections.abc import Callable

import httpx
import pytest
from typer.testing import CliRunner

from sentrix import cli
from sentrix.cli import app

runner = CliRunner()

Handler = Callable[[httpx.Request], httpx.Response]

GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}


@pytest.fixture(autouse=True)
def no_ambient_config(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SENTRIX_CONFIG", raising=False)


@pytest.fixture
def mock_http(monkeypatch: pytest.MonkeyPatch):
    """Route every httpx.Client created by the CLI through a fake handler."""
    real_client = httpx.Client
    created: list[dict] = []

    def install(handler: Handler) -> list[dict]:
        def factory(**kwargs):
            created.append(kwargs)
            return real_client(
                transport=httpx.MockTransport(handler), **kwargs
            )

        monkeypatch.setattr(cli.httpx, "Client", factory)
        return created

    return install


# --- URL validation -------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1",                 # unclosed IPv6 bracket
        "http://example.com:99999",    # port out of range
        "http://example.com:abc",      # non-numeric port
        "https://example.com/\x00x",   # NUL
        "https://example.com/\x7f",    # DEL
        "https://example.com/\x1b[0m", # escape sequence
        "https://example.com/\n",
    ],
)
def test_malformed_url_is_a_usage_error_without_traceback(url, mock_http):
    created = mock_http(lambda request: httpx.Response(200))

    result = runner.invoke(app, ["check", url])

    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output
    assert created == []   # rejected before any HTTP client was created


@pytest.mark.parametrize(
    "url",
    ["https://[::1]:8443/path?q=1#frag", "http://127.0.0.1:8000"],
)
def test_valid_unusual_urls_are_still_accepted(url, mock_http):
    mock_http(lambda request: httpx.Response(200, headers=GOOD_HEADERS))

    assert runner.invoke(app, ["check", url]).exit_code == 0


# --- request failures -----------------------------------------------------


def test_invalid_url_from_httpx_exits_1_not_with_a_traceback(mock_http):
    def boom(request):
        raise httpx.InvalidURL("bad url")

    mock_http(boom)

    result = runner.invoke(app, ["check", "https://example.com"])

    assert result.exit_code == 1
    assert "Request gagal" in result.output
    assert isinstance(result.exception, SystemExit)


def test_error_text_that_looks_like_markup_does_not_crash(mock_http):
    def boom(request):
        raise httpx.ConnectError("refused [/bold] [red]", request=request)

    mock_http(boom)

    result = runner.invoke(app, ["check", "https://example.com"])

    assert result.exit_code == 1
    assert "Request gagal" in result.output


# --- body is never downloaded --------------------------------------------


def test_response_body_is_not_downloaded(mock_http):
    class Tripwire(httpx.SyncByteStream):
        read = False

        def __iter__(self):
            Tripwire.read = True
            yield b"x" * 1024

    mock_http(
        lambda request: httpx.Response(
            200, headers=GOOD_HEADERS, stream=Tripwire()
        )
    )

    result = runner.invoke(app, ["check", "https://example.com"])

    assert result.exit_code == 0
    assert Tripwire.read is False


# --- options --------------------------------------------------------------


def test_defaults_are_unchanged(mock_http):
    created = mock_http(lambda request: httpx.Response(200, headers=GOOD_HEADERS))

    runner.invoke(app, ["check", "https://example.com"])

    assert created[0]["timeout"] == cli.REQUEST_TIMEOUT_SECONDS == 8.0
    assert created[0]["max_redirects"] == cli.MAX_REDIRECTS == 5


def test_timeout_and_max_redirects_are_passed_to_the_client(mock_http):
    created = mock_http(lambda request: httpx.Response(200, headers=GOOD_HEADERS))

    result = runner.invoke(
        app,
        ["check", "https://example.com", "--timeout", "15", "--max-redirects", "2"],
    )

    assert result.exit_code == 0
    assert created[0]["timeout"] == 15.0
    assert created[0]["max_redirects"] == 2


def test_max_redirects_limit_is_enforced(mock_http):
    mock_http(lambda request: httpx.Response(301, headers={"Location": "/again"}))

    result = runner.invoke(
        app, ["check", "https://example.com/", "--max-redirects", "2"]
    )

    assert result.exit_code == 1
    assert "Request gagal" in result.output


@pytest.mark.parametrize(
    "args",
    [["--timeout", "0"], ["--timeout", "61"], ["--max-redirects", "-1"],
     ["--max-redirects", "21"]],
)
def test_out_of_range_options_exit_2(args, mock_http):
    mock_http(lambda request: httpx.Response(200))

    result = runner.invoke(app, ["check", "https://example.com", *args])

    assert result.exit_code == 2


@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_version_flag(flag):
    result = runner.invoke(app, [flag])

    assert result.exit_code == 0
    assert result.output.strip() == f"sentrix {cli.TOOL_VERSION}"


# --- value rules end to end -----------------------------------------------


def test_value_rules_show_up_in_the_report_without_leaking_values(mock_http, tmp_path):
    mock_http(
        lambda request: httpx.Response(
            200,
            headers={
                **GOOD_HEADERS,
                "Strict-Transport-Security": "max-age=0",
                "Content-Security-Policy": "script-src 'self' 'unsafe-inline'",
                "Server": "nginx/1.18.0-SECRET",
            },
        )
    )
    out = tmp_path / "report.json"

    result = runner.invoke(
        app, ["check", "https://example.com", "-o", str(out), "--fail-on", "MEDIUM"]
    )
    report = json.loads(out.read_text(encoding="utf-8"))

    assert result.exit_code == 3          # HTTP-102 is MEDIUM
    assert {f["id"] for f in report["findings"]} == {
        "HTTP-101", "HTTP-102", "HTTP-201",
    }
    assert "SECRET" not in out.read_text(encoding="utf-8")
    types = {f["evidence"]["type"] for f in report["findings"]}
    assert types == {"weak_header_value", "information_disclosure"}


def test_value_rules_appear_in_sarif_and_html(mock_http, tmp_path):
    mock_http(
        lambda request: httpx.Response(
            200, headers={**GOOD_HEADERS, "X-Powered-By": "Express"}
        )
    )

    sarif = tmp_path / "r.sarif"
    html = tmp_path / "r.html"
    runner.invoke(app, ["check", "https://example.com", "-o", str(sarif), "-f", "sarif"])
    runner.invoke(app, ["check", "https://example.com", "-o", str(html), "-f", "html"])

    log = json.loads(sarif.read_text(encoding="utf-8"))
    assert [r["ruleId"] for r in log["runs"][0]["results"]] == ["HTTP-202"]
    assert "HTTP-202" in html.read_text(encoding="utf-8")
    assert "Express" not in html.read_text(encoding="utf-8")


def test_rules_command_lists_the_new_rules():
    result = runner.invoke(app, ["rules"])

    assert result.exit_code == 0
    for rule_id in ("HTTP-101", "HTTP-102", "HTTP-103", "HTTP-104", "HTTP-201", "HTTP-202"):
        assert rule_id in result.output
