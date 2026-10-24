import json
import re
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


# --- scan history: --save, history, compare -------------------------------

ALL_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Isolated history database; never touches the real ~/.sentrix."""
    path = tmp_path / "history.db"
    monkeypatch.setenv("SENTRIX_DB", str(path))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return path


def test_check_without_save_does_not_create_database(mock_http, db):
    mock_http(lambda request: httpx.Response(200))

    result = runner.invoke(app, ["check", "https://example.com"])

    assert result.exit_code == 0
    assert not db.exists()
    assert "riwayat" not in result.output.lower()


def test_check_save_stores_scan_and_reports_id(mock_http, db):
    mock_http(lambda request: httpx.Response(200))

    result = runner.invoke(app, ["check", "https://example.com", "--save"])

    assert result.exit_code == 0
    assert "#1" in result.output
    assert db.exists()


def test_check_save_accepts_explicit_db_option(mock_http, tmp_path):
    mock_http(lambda request: httpx.Response(200))
    custom = tmp_path / "nested" / "custom.db"

    result = runner.invoke(
        app, ["check", "https://example.com", "--save", "--db", str(custom)]
    )

    assert result.exit_code == 0
    assert custom.exists()


def test_check_save_strips_query_and_never_stores_header_values(
    mock_http, db
):
    mock_http(
        lambda request: httpx.Response(
            200, headers={"Set-Cookie": "session=TOP-SECRET-VALUE"}
        )
    )

    result = runner.invoke(
        app, ["check", "https://example.com/p?token=SECRET", "--save"]
    )

    assert result.exit_code == 0
    raw = db.read_bytes()
    assert b"SECRET" not in raw
    assert b"TOP-SECRET-VALUE" not in raw


def test_check_save_failure_exits_one_with_clear_message(mock_http, tmp_path):
    mock_http(lambda request: httpx.Response(200))
    # a directory cannot be opened as a database file
    result = runner.invoke(
        app,
        ["check", "https://example.com", "--save", "--db", str(tmp_path)],
    )

    assert result.exit_code == 1
    assert "Riwayat gagal disimpan" in result.output


def test_failed_request_is_never_saved(mock_http, db):
    def boom(request):
        raise httpx.ConnectError("down", request=request)

    mock_http(boom)

    result = runner.invoke(app, ["check", "https://example.com", "--save"])

    assert result.exit_code == 1
    assert not db.exists()


def test_history_on_missing_database_prints_hint(db):
    result = runner.invoke(app, ["history"])

    assert result.exit_code == 0
    assert "Belum ada scan tersimpan" in result.output


def test_history_lists_saved_scans_newest_first(mock_http, db):
    mock_http(lambda request: httpx.Response(200))
    runner.invoke(app, ["check", "https://first.example", "--save"])
    runner.invoke(app, ["check", "https://second.example", "--save"])

    result = runner.invoke(app, ["history"])

    assert result.exit_code == 0
    assert result.output.index("second.example") < result.output.index(
        "first.example"
    )


def test_history_shows_untruncated_timestamp(mock_http, db):
    mock_http(lambda request: httpx.Response(200))
    runner.invoke(app, ["check", "https://example.com", "--save"])

    result = runner.invoke(app, ["history"])

    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ", result.output)
    assert "…" not in result.output.split("example.com")[0]


def test_history_limit_option_is_validated_and_applied(mock_http, db):
    mock_http(lambda request: httpx.Response(200))
    for host in ("a", "b", "c"):
        runner.invoke(app, ["check", f"https://{host}.example", "--save"])

    limited = runner.invoke(app, ["history", "--limit", "1"])
    invalid = runner.invoke(app, ["history", "--limit", "0"])

    assert "c.example" in limited.output
    assert "a.example" not in limited.output
    assert invalid.exit_code == 2


def test_history_renders_markup_like_targets_literally(mock_http, db):
    mock_http(lambda request: httpx.Response(200))
    runner.invoke(
        app, ["check", "https://e.co/[b]x[/b]", "--save"]
    )

    result = runner.invoke(app, ["history"])

    assert result.exit_code == 0
    assert "/[b]x[/b]" in result.output


def test_compare_shows_resolved_and_new_findings(mock_http, db):
    state = {"headers": {}}
    mock_http(lambda request: httpx.Response(200, headers=state["headers"]))

    runner.invoke(app, ["check", "https://example.com", "--save"])
    state["headers"] = {
        k: v for k, v in ALL_HEADERS.items() if k != "Referrer-Policy"
    }
    runner.invoke(app, ["check", "https://example.com", "--save"])

    result = runner.invoke(app, ["compare", "1", "2"])

    assert result.exit_code == 0
    assert "TERATASI" in result.output
    assert "Teratasi: 4" in result.output
    assert "Tetap: 1" in result.output
    assert "Baru: 0" in result.output
    assert "Peringatan" not in result.output


def test_compare_warns_when_targets_differ(mock_http, db):
    mock_http(lambda request: httpx.Response(200))
    runner.invoke(app, ["check", "https://a.example", "--save"])
    runner.invoke(app, ["check", "https://b.example", "--save"])

    result = runner.invoke(app, ["compare", "1", "2"])

    assert result.exit_code == 0
    assert "Peringatan" in result.output


def test_compare_unknown_scan_id_exits_one(mock_http, db):
    mock_http(lambda request: httpx.Response(200))
    runner.invoke(app, ["check", "https://example.com", "--save"])

    result = runner.invoke(app, ["compare", "1", "99"])

    assert result.exit_code == 1
    assert "99" in result.output


@pytest.mark.parametrize("args", [["compare", "0", "1"], ["compare", "1"]])
def test_compare_rejects_bad_arguments(db, args):
    result = runner.invoke(app, args)

    assert result.exit_code == 2


def test_root_help_lists_history_commands():
    result = runner.invoke(app, ["--help"])

    assert "history" in result.output
    assert "compare" in result.output


# --- report exports: --format sarif / html ---------------------------------


def test_format_sarif_writes_a_sarif_log(mock_http, tmp_path):
    mock_http(lambda request: httpx.Response(200, headers={}))
    path = tmp_path / "out" / "report.sarif"

    result = runner.invoke(
        app,
        ["check", "https://example.com", "-o", str(path), "--format", "sarif"],
    )

    assert result.exit_code == 0
    log = json.loads(path.read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0"
    assert len(log["runs"][0]["results"]) == 5
    assert "Laporan tersimpan" in result.output
    assert "sarif" in result.output


def test_format_html_writes_a_standalone_page(mock_http, tmp_path):
    mock_http(lambda request: httpx.Response(200, headers={}))
    path = tmp_path / "report.html"

    result = runner.invoke(
        app,
        ["check", "https://example.com", "-o", str(path), "-f", "html"],
    )

    assert result.exit_code == 0
    html = path.read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")
    assert "HTTP-001" in html
    assert "<script" not in html


def test_format_name_is_case_insensitive(mock_http, tmp_path):
    mock_http(lambda request: httpx.Response(200))
    path = tmp_path / "report.sarif"

    result = runner.invoke(
        app,
        ["check", "https://example.com", "-o", str(path), "--format", "SARIF"],
    )

    assert result.exit_code == 0
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_explicit_json_format_matches_the_default(mock_http, tmp_path):
    mock_http(lambda request: httpx.Response(200, headers={}))
    default_path = tmp_path / "default.json"
    explicit_path = tmp_path / "explicit.json"

    runner.invoke(app, ["check", "https://example.com", "-o", str(default_path)])
    runner.invoke(
        app,
        ["check", "https://example.com", "-o", str(explicit_path), "-f", "json"],
    )

    default = json.loads(default_path.read_text(encoding="utf-8"))
    explicit = json.loads(explicit_path.read_text(encoding="utf-8"))
    default.pop("timestamp")
    explicit.pop("timestamp")
    assert default == explicit


def test_format_without_output_is_rejected_before_any_request(mock_http):
    seen = mock_http(lambda request: httpx.Response(200))

    result = runner.invoke(
        app, ["check", "https://example.com", "--format", "sarif"]
    )

    assert result.exit_code == 2
    assert "--output" in result.output
    assert seen == []


def test_unknown_format_is_rejected_before_any_request(mock_http, tmp_path):
    seen = mock_http(lambda request: httpx.Response(200))
    path = tmp_path / "report.pdf"

    result = runner.invoke(
        app,
        ["check", "https://example.com", "-o", str(path), "--format", "pdf"],
    )

    assert result.exit_code == 2
    assert seen == []
    assert not path.exists()


@pytest.mark.parametrize("fmt", ["sarif", "html"])
def test_exports_do_not_contain_response_header_values(
    mock_http, tmp_path, fmt
):
    mock_http(
        lambda request: httpx.Response(
            200,
            headers={
                "Set-Cookie": "session=TOP-SECRET-VALUE",
                "Authorization": "Bearer TOP-SECRET-VALUE",
            },
        )
    )
    path = tmp_path / f"report.{fmt}"

    result = runner.invoke(
        app,
        ["check", "https://example.com", "-o", str(path), "-f", fmt],
    )

    assert result.exit_code == 0
    assert "TOP-SECRET-VALUE" not in path.read_text(encoding="utf-8")


def test_html_export_drops_query_string_from_the_target(mock_http, tmp_path):
    mock_http(lambda request: httpx.Response(200))
    path = tmp_path / "report.html"

    result = runner.invoke(
        app,
        [
            "check",
            "https://example.com/p?token=QUERY-SECRET",
            "-o",
            str(path),
            "-f",
            "html",
        ],
    )

    assert result.exit_code == 0
    assert "QUERY-SECRET" not in path.read_text(encoding="utf-8")


def test_export_can_be_combined_with_save(mock_http, db, tmp_path):
    mock_http(lambda request: httpx.Response(200))
    path = tmp_path / "report.sarif"

    result = runner.invoke(
        app,
        [
            "check",
            "https://example.com",
            "-o",
            str(path),
            "-f",
            "sarif",
            "--save",
        ],
    )

    assert result.exit_code == 0
    assert path.exists()
    assert db.exists()
    assert "#1" in result.output


def test_unwritable_output_exits_one_without_a_traceback(mock_http, tmp_path):
    mock_http(lambda request: httpx.Response(200))

    # A directory cannot be opened for writing as a file.
    result = runner.invoke(
        app, ["check", "https://example.com", "-o", str(tmp_path)]
    )

    assert result.exit_code == 1
    assert "Laporan gagal disimpan" in result.output
    assert "Traceback" not in result.output
    assert "Laporan tersimpan" not in result.output


def test_markup_like_text_in_url_does_not_crash(mock_http):
    mock_http(lambda request: httpx.Response(200))

    result = runner.invoke(app, ["check", "https://example.com/[/dim]"])

    assert result.exit_code == 0
    assert "[/dim]" in result.output


def test_markup_like_text_in_output_path_is_shown_literally(
    mock_http, tmp_path, monkeypatch
):
    mock_http(lambda request: httpx.Response(200))
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app, ["check", "https://example.com", "-o", "[bold]r.json"]
    )

    assert result.exit_code == 0
    assert "[bold]r.json" in result.output
    assert (tmp_path / "[bold]r.json").exists()


def test_check_help_lists_the_format_option():
    result = runner.invoke(app, ["check", "--help"])

    assert result.exit_code == 0
    assert "--format" in result.output
    assert "sarif" in result.output
    assert "html" in result.output
