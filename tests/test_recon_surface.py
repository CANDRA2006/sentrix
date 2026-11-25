"""Unit tests for expanded attack surface reconnaissance modules and CLI."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
from typer.testing import CliRunner

from sentrix.cli import app
from sentrix.recon.alive import (
    AliveResult,
    extract_html_title,
    probe_alive_subdomains,
    probe_subdomain,
)
from sentrix.recon.dirs import (
    CATEGORY_PATHS,
    DEFAULT_PATHS,
    DirResult,
    discover_directories,
    get_paths_for_categories,
)
from sentrix.recon.takeover import (
    TAKEOVER_SIGNATURES,
    TakeoverResult,
    check_subdomain_takeover,
    resolve_cname,
    scan_subdomain_takeovers,
)
from sentrix.recon.vhost import (
    DEFAULT_VHOST_WORDS,
    VHostResult,
    discover_vhosts,
)

runner = CliRunner()


# ===========================================================================
# 1. Directory Discovery & Categories
# ===========================================================================

def test_get_paths_for_categories_specific():
    paths = get_paths_for_categories("configs,api")
    assert "/.git/HEAD" in paths
    assert "/openapi.json" in paths
    assert "/admin" not in paths  # from admin category, not selected


def test_get_paths_for_categories_all():
    paths = get_paths_for_categories("all")
    for cat_paths in CATEGORY_PATHS.values():
        for p in cat_paths:
            assert p in paths


def test_get_paths_for_categories_unknown_fallback():
    paths = get_paths_for_categories("nonexistent_category")
    assert paths == DEFAULT_PATHS


def test_discover_directories_categorized():
    def handler(request: httpx.Request) -> httpx.Response:
        url_path = request.url.path
        if url_path == "/.env":
            return httpx.Response(200, content=b"SECRET=123", headers={"content-length": "10"})
        if url_path == "/openapi.json":
            return httpx.Response(200, content=b"{}", headers={"content-length": "2"})
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    results = discover_directories(
        "http://example.com",
        category="configs,api",
        client=client,
        rate_limit=0.0,
    )

    found_paths = {r.path: r for r in results}
    assert "/.env" in found_paths
    assert found_paths["/.env"].category == "configs"
    assert found_paths["/.env"].status_code == 200

    assert "/openapi.json" in found_paths
    assert found_paths["/.openapi.json" if "/.openapi.json" in found_paths else "/openapi.json"].category == "api"


# ===========================================================================
# 2. Subdomain Takeover Detector
# ===========================================================================

def test_takeover_vulnerable_github_pages():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            text="There isn't a GitHub Pages site here.",
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = check_subdomain_takeover(
        subdomain="blog.example.com",
        cname="example.github.io",
        client=client,
    )

    assert result is not None
    assert result.vulnerable is True
    assert result.service == "GitHub Pages"
    assert "GitHub Pages site here" in result.fingerprint_matched


def test_takeover_vulnerable_aws_s3():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            text="<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>",
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = check_subdomain_takeover(
        subdomain="assets.example.com",
        cname="assets.example.com.s3.amazonaws.com",
        client=client,
    )

    assert result is not None
    assert result.vulnerable is True
    assert result.service == "AWS S3"


def test_takeover_not_vulnerable_active_site():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="<html><body>Welcome to our active documentation site!</body></html>",
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    result = check_subdomain_takeover(
        subdomain="docs.example.com",
        cname="docs.github.io",
        client=client,
    )

    assert result is not None
    assert result.vulnerable is False
    assert result.service == "GitHub Pages"


def test_takeover_no_matching_cname():
    result = check_subdomain_takeover(
        subdomain="mail.example.com",
        cname="mail.protection.outlook.com",
    )
    assert result is None


def test_scan_subdomain_takeovers_collection():
    def handler(request: httpx.Request) -> httpx.Response:
        if "unclaimed" in str(request.url):
            return httpx.Response(404, text="There isn't a GitHub Pages site here")
        return httpx.Response(200, text="OK")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with patch("sentrix.recon.takeover.resolve_cname") as mock_resolve:
        mock_resolve.side_effect = lambda sub, **kw: "custom.github.io" if "github" in sub else ""

        results = scan_subdomain_takeovers(
            ["unclaimed.github.example.com", "other.example.com"],
            client=client,
            rate_limit=0.0,
        )

    assert len(results) == 1
    assert results[0].vulnerable is True
    assert results[0].service == "GitHub Pages"


# ===========================================================================
# 3. Live Subdomain Probing
# ===========================================================================

def test_extract_html_title():
    html = "<html><head><title>   Internal Portal :: Login   </title></head></html>"
    assert extract_html_title(html) == "Internal Portal :: Login"

    empty_html = "<html><body>No title here</body></html>"
    assert extract_html_title(empty_html) == ""


def test_probe_subdomain_alive():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><head><title>Dashboard</title></head></html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with patch("socket.gethostbyname", return_value="10.0.0.1"):
        res = probe_subdomain("dash.example.com", client=client)

    assert res.alive is True
    assert res.status_code == 200
    assert res.title == "Dashboard"
    assert res.ip == "10.0.0.1"


def test_probe_subdomain_dead():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    res = probe_subdomain("dead.example.com", client=client)

    assert res.alive is False
    assert res.status_code is None


def test_probe_alive_subdomains_list():
    def handler(request: httpx.Request) -> httpx.Response:
        if "online" in str(request.url):
            return httpx.Response(200, text="<title>Online</title>")
        raise httpx.ConnectError("Failed")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    results = probe_alive_subdomains(
        ["online.example.com", "offline.example.com"],
        client=client,
        rate_limit=0.0,
    )
    assert len(results) == 2
    assert results[0].alive is True
    assert results[0].title == "Online"
    assert results[1].alive is False


# ===========================================================================
# 4. Virtual Host (VHost) Discovery
# ===========================================================================

def test_discover_vhosts_detects_distinct():
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.headers.get("Host", "")
        # Baseline response
        if "invalid-baseline" in host:
            return httpx.Response(404, content=b"Default 404 page", headers={"Content-Length": "16"})
        # Target internal admin host returns custom 200
        if "admin.example.com" in host:
            return httpx.Response(200, content=b"<html><head><title>Admin Panel</title></head><body>Secret Admin</body></html>")
        # Regular vhost returns baseline 404
        return httpx.Response(404, content=b"Default 404 page", headers={"Content-Length": "16"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    results = discover_vhosts(
        target="http://93.184.216.34",
        domain="example.com",
        vhost_words=("admin", "dev", "test"),
        client=client,
        rate_limit=0.0,
    )

    assert len(results) == 1
    assert results[0].vhost == "admin.example.com"
    assert results[0].status_code == 200
    assert results[0].title == "Admin Panel"
    assert results[0].is_distinct is True


# ===========================================================================
# 5. CLI Integration for Extended Reconnaissance
# ===========================================================================

def test_recon_cli_extended_options(monkeypatch):
    from sentrix.recon import PortResult, ReconResult

    mock_res = ReconResult(
        target="example.com",
        subdomains=("api.example.com", "test.example.com"),
        open_ports=(PortResult(port=443, open=True, service="https", banner=""),),
        discovered_paths=(DirResult(path="/.env", status_code=200, content_length=50, category="configs"),),
        takeovers=(
            TakeoverResult(
                subdomain="test.example.com",
                service="GitHub Pages",
                cname="test.github.io",
                vulnerable=True,
                fingerprint_matched="There isn't a GitHub Pages site here",
                status_code=404,
            ),
        ),
        alive_subdomains=(
            AliveResult(
                subdomain="api.example.com",
                alive=True,
                status_code=200,
                title="API Gateway",
                ip="93.184.216.34",
            ),
        ),
        discovered_vhosts=(
            VHostResult(
                vhost="dev.example.com",
                status_code=200,
                content_length=1200,
                title="Development Portal",
            ),
        ),
    )

    monkeypatch.setattr("sentrix.cli.run_recon", lambda *a, **kw: mock_res)
    monkeypatch.setattr("sentrix.cli.validate_target_scope", lambda t, **kw: (t, "93.184.216.34"))

    result = runner.invoke(
        app,
        [
            "recon",
            "example.com",
            "--i-have-permission",
            "--check-takeover",
            "--alive-probe",
            "--vhost",
            "--category",
            "configs",
        ],
    )

    assert result.exit_code == 0
    assert "POTENSI SUBDOMAIN TAKEOVER TERDETEKSI" in result.output
    assert "RENTAN test.example.com -> GitHub Pages" in result.output
    assert "Subdomain aktif (Alive):" in result.output
    assert "API Gateway" in result.output
    assert "Virtual Host Terdeteksi (VHost):" in result.output
    assert "dev.example.com" in result.output
    assert "(configs)" in result.output
