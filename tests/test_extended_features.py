"""Comprehensive test suite for SENTRIX extended features:
- Cookie flag analysis (__Host-, __Secure-, HttpOnly, Secure, SameSite)
- Extended headers (X-Frame-Options, CSP frame-ancestors, COOP, COEP, CORP, Cache-Control)
- Information disclosure (Server version, X-AspNet-Version, X-AspNetMvc-Version)
- CORS wildcard + credentials detection
- TLS certificate and cipher inspection
- Redirect downgrade and cross-domain analysis
- HTTP methods inspection (OPTIONS / dangerous methods)
- Discovery (security.txt RFC 9116, robots.txt sensitive paths, exposed files)
- Subresource Integrity (SRI) parsing
- Technology fingerprinting (headers, cookies, meta tags)
- Markdown report rendering
- Security scoring & grading (A–F)
- Report diff / baseline
- Rule plugin system (YAML / TOML custom rules)
- Multi-target scan command
- Recon with authorization guardrails & SSRF protection
"""

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from sentrix import cli
from sentrix.audit import default_audit_log_path, log_audit_event
from sentrix.cli import app
from sentrix.cookies import _parse_cookie_flags, analyze_cookies
from sentrix.discovery import (
    check_exposed_file_status,
    parse_robots_txt,
    parse_security_txt,
)
from sentrix.fingerprint import (
    fingerprint_all,
    fingerprint_from_cookies,
    fingerprint_from_headers,
    fingerprint_from_html,
)
from sentrix.net import (
    ScopeError,
    analyze_redirects,
    find_dangerous_methods,
    inspect_tls,
    is_private_or_internal_ip,
    parse_allow_methods,
    validate_target_scope,
)
from sentrix.recon import discover_directories, run_recon, scan_ports
from sentrix.report.diff import diff_reports
from sentrix.report.markdown import render_markdown
from sentrix.reporting import ReportFormat, render_report
from sentrix.rules import (
    ALL_RULES,
    CORE_RULES,
    EXTENDED_RULES,
    cache_control_is_unprotected,
    coep_is_weak,
    coop_is_weak,
    corp_is_weak,
    cors_is_wildcard,
    csp_missing_frame_ancestors,
    load_rules_from_directory,
    load_rules_from_file,
    parse_plugin_rule,
    xfo_is_invalid,
)
from sentrix.scoring import compute_score
from sentrix.sri import check_sri

runner = CliRunner()


# --- 1. Cookie flag analysis ---

def test_cookie_flags_parsing():
    cookie = "id=123; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=example.com"
    analysis = _parse_cookie_flags(cookie)

    assert analysis.name == "id"
    assert analysis.secure is True
    assert analysis.httponly is True
    assert analysis.samesite == "strict"
    assert analysis.path == "/"
    assert analysis.has_domain is True


def test_cookie_host_prefix_validation():
    # Valid __Host- cookie: Secure, Path=/, NO Domain
    valid_host = "__Host-session=abc; Secure; Path=/; HttpOnly"
    valid_res = _parse_cookie_flags(valid_host)
    assert valid_res.has_host_prefix is True
    assert valid_res.host_prefix_valid is True

    # Invalid: missing Secure
    inv1 = "__Host-session=abc; Path=/; HttpOnly"
    assert _parse_cookie_flags(inv1).host_prefix_valid is False

    # Invalid: has Domain attribute
    inv2 = "__Host-session=abc; Secure; Path=/; Domain=example.com"
    assert _parse_cookie_flags(inv2).host_prefix_valid is False

    # Invalid: Path is not /
    inv3 = "__Host-session=abc; Secure; Path=/app"
    assert _parse_cookie_flags(inv3).host_prefix_valid is False


def test_cookie_secure_prefix_validation():
    # __Secure- requires Secure
    valid = "__Secure-token=123; Secure; Path=/app"
    assert _parse_cookie_flags(valid).secure_prefix_valid is True

    invalid = "__Secure-token=123; Path=/app"
    assert _parse_cookie_flags(invalid).secure_prefix_valid is False


def test_cookie_analysis_multiple_headers():
    cookies = [
        "auth=xyz; Secure; HttpOnly; SameSite=Lax",
        "tracker=1; Path=/",
    ]
    results = analyze_cookies(cookies, is_https=True)
    assert len(results) == 2
    assert results[0].secure is True
    assert results[1].secure is False


# --- 2. Extended header predicates ---

def test_xfo_predicates():
    assert xfo_is_invalid("DENY") is False
    assert xfo_is_invalid("SAMEORIGIN") is False
    assert xfo_is_invalid("deny") is False
    assert xfo_is_invalid("ALLOW-FROM https://evil.com") is True
    assert xfo_is_invalid("INVALID_VALUE") is True


def test_csp_frame_ancestors_predicate():
    assert csp_missing_frame_ancestors("default-src 'self'") is True
    assert csp_missing_frame_ancestors("default-src 'self'; frame-ancestors 'none'") is False
    assert csp_missing_frame_ancestors("frame-ancestors https://example.com") is False


def test_cors_wildcard_predicate():
    assert cors_is_wildcard("*") is True
    assert cors_is_wildcard("https://example.com") is False


def test_cache_control_predicate():
    assert cache_control_is_unprotected("public, max-age=3600") is True
    assert cache_control_is_unprotected("no-store, no-cache") is False
    assert cache_control_is_unprotected("private, max-age=0") is False


def test_isolation_headers_predicates():
    assert coop_is_weak("unsafe-none") is True
    assert coop_is_weak("same-origin") is False
    assert coop_is_weak("same-origin-allow-popups") is False

    assert coep_is_weak("unsafe-none") is True
    assert coep_is_weak("require-corp") is False

    assert corp_is_weak("cross-origin") is True
    assert corp_is_weak("same-origin") is False
    assert corp_is_weak("same-site") is False


# --- 3. CORS + credentials check ---

def test_cors_findings_creation():
    from sentrix.cli import _build_cors_findings

    headers = httpx.Headers({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    findings = _build_cors_findings(headers)
    assert len(findings) == 1
    assert findings[0].id == "CORS-001"


# --- 4. Redirect analysis ---

def test_redirect_analysis_downgrade_and_cross_domain():
    resp1 = httpx.Response(301, request=httpx.Request("GET", "https://example.com/"))
    resp2 = httpx.Response(302, request=httpx.Request("GET", "http://insecure.org/page"))
    history = [resp1, resp2]
    final_url = "http://insecure.org/page"

    analysis = analyze_redirects(history, final_url)
    assert analysis.has_downgrade is True
    assert analysis.has_cross_domain is True
    assert len(analysis.hops) == 2


def test_redirect_analysis_clean():
    resp1 = httpx.Response(301, request=httpx.Request("GET", "https://example.com/login"))
    history = [resp1]
    final_url = "https://example.com/dashboard"

    analysis = analyze_redirects(history, final_url)
    assert analysis.has_downgrade is False
    assert analysis.has_cross_domain is False


# --- 5. HTTP methods check ---

def test_http_methods_parser():
    allow = "GET, POST, OPTIONS, TRACE, PUT"
    methods = parse_allow_methods(allow)
    assert methods == ("GET", "POST", "OPTIONS", "TRACE", "PUT")

    dangerous = find_dangerous_methods(methods)
    assert set(dangerous) == {"TRACE", "PUT"}


# --- 6. Discovery: security.txt, robots.txt, exposed files ---

def test_parse_security_txt():
    sample = """Contact: mailto:security@example.com
Expires: 2027-12-31T23:59:59.000Z
Encryption: https://example.com/pgp-key.txt
"""
    res = parse_security_txt(sample)
    assert res.found is True
    assert res.has_contact is True
    assert res.has_expires is True
    assert res.has_encryption is True
    assert res.is_signed is False


def test_parse_robots_txt_sensitive_paths():
    sample = """User-agent: *
Disallow: /admin
Disallow: /api/private/
Disallow: /public/
Disallow: /.git
"""
    res = parse_robots_txt(sample)
    assert res.found is True
    assert "/admin" in res.sensitive_paths
    assert "/api/private/" in res.sensitive_paths
    assert "/.git" in res.sensitive_paths
    assert "/public/" not in res.sensitive_paths


def test_check_exposed_file_status():
    res200 = check_exposed_file_status("/.env", 200)
    assert res200.exists is True

    res403 = check_exposed_file_status("/.git/HEAD", 403)
    assert res403.exists is True

    res404 = check_exposed_file_status("/backup", 404)
    assert res404.exists is False


# --- 7. Subresource Integrity (SRI) ---

def test_sri_detects_external_scripts_without_integrity():
    html = """
    <html>
      <head>
        <script src="/local.js"></script>
        <script src="https://cdn.example.org/lib.js"></script>
        <script src="https://cdn.example.org/secure.js" integrity="sha384-xyz" crossorigin="anonymous"></script>
      </head>
    </html>
    """
    results = check_sri(html, "https://mywebsite.com")
    assert len(results) == 2
    # lib.js has no integrity
    lib_res = next(r for r in results if "lib.js" in r.src)
    assert lib_res.has_integrity is False

    # secure.js has integrity
    sec_res = next(r for r in results if "secure.js" in r.src)
    assert sec_res.has_integrity is True


# --- 8. Technology fingerprinting ---

def test_fingerprint_from_headers():
    headers = {
        "server": "nginx/1.24.0",
        "x-powered-by": "PHP/8.2.0",
        "x-aspnet-version": "4.0.30319",
    }
    techs = fingerprint_from_headers(headers)
    names = {t.name for t in techs}
    assert "Nginx" in names
    assert "PHP" in names
    assert "ASP.NET" in names


def test_fingerprint_from_cookies():
    cookie_names = ["PHPSESSID", "laravel_session", "other"]
    techs = fingerprint_from_cookies(cookie_names)
    names = {t.name for t in techs}
    assert "PHP" in names
    assert "Laravel" in names


def test_fingerprint_from_html():
    html = '<meta name="generator" content="WordPress 6.4.2" />'
    techs = fingerprint_from_html(html)
    assert len(techs) == 1
    assert techs[0].name == "WordPress"
    assert techs[0].version == "6.4.2"


# --- 9. Scoring & Grading ---

def test_compute_score():
    no_findings = []
    score_clean = compute_score(no_findings)
    assert score_clean.score == 100
    assert score_clean.grade == "A"

    findings = [
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
    ]
    # 100 - 25 - 15 = 60 (grade D: >= 50 and < 65)
    score_mid = compute_score(findings)
    assert score_mid.score == 60
    assert score_mid.grade == "D"


# --- 10. Markdown export ---

def test_render_markdown():
    report = {
        "tool": {"name": "SENTRIX", "version": "0.1.0"},
        "schema_version": "1.1",
        "timestamp": "2026-11-20T22:00:00Z",
        "target": {"requested_url": "https://example.com", "final_url": "https://example.com"},
        "http": {"status_code": 200, "redirect_count": 0},
        "summary": {"findings": 1, "by_severity": {"HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0}},
        "findings": [
            {
                "id": "HTTP-001",
                "title": "CSP missing",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "evidence": {"header": "content-security-policy"},
                "recommendation": "Add CSP.",
            }
        ],
        "limitations": ["Checks response headers only."],
    }
    md = render_markdown(report)
    assert "# SENTRIX - HTTP Security Posture Report" in md
    assert "| `HTTP-001` | MEDIUM |" in md
    assert "- Checks response headers only." in md


# --- 11. Diff / Baseline ---

def test_diff_reports():
    rep_a = {
        "target": {"requested_url": "https://example.com"},
        "timestamp": "2026-11-01T00:00:00Z",
        "findings": [
            {"id": "HTTP-001", "title": "CSP missing", "severity": "MEDIUM", "evidence": {"header": "csp"}},
            {"id": "HTTP-002", "title": "HSTS missing", "severity": "MEDIUM", "evidence": {"header": "hsts"}},
        ],
    }
    rep_b = {
        "target": {"requested_url": "https://example.com"},
        "timestamp": "2026-11-10T00:00:00Z",
        "findings": [
            {"id": "HTTP-001", "title": "CSP missing", "severity": "HIGH", "evidence": {"header": "csp"}},
            {"id": "HTTP-003", "title": "XCTO missing", "severity": "LOW", "evidence": {"header": "xcto"}},
        ],
    }

    diff = diff_reports(rep_a, rep_b)
    assert len(diff.appeared) == 1
    assert diff.appeared[0].rule_id == "HTTP-003"
    assert len(diff.resolved) == 1
    assert diff.resolved[0].rule_id == "HTTP-002"
    assert len(diff.severity_changed) == 1
    assert diff.severity_changed[0][0].severity == "MEDIUM"
    assert diff.severity_changed[0][1].severity == "HIGH"


# --- 12. Rule plugin system ---

def test_parse_plugin_rule_toml(tmp_path):
    plugin_file = tmp_path / "custom_rules.toml"
    plugin_file.write_text("""
[[rules]]
id = "PLUGIN-001"
header = "x-custom-firewall"
title = "Custom WAF header missing"
severity = "LOW"
recommendation = "Enable WAF."
https_only = false
""", encoding="utf-8")

    loaded = load_rules_from_file(plugin_file)
    assert len(loaded) == 1
    assert loaded[0].id == "PLUGIN-001"
    assert loaded[0].header == "x-custom-firewall"


def test_parse_plugin_rule_yaml(tmp_path):
    plugin_file = tmp_path / "custom_rules.yaml"
    plugin_file.write_text("""
- id: "PLUGIN-002"
  header: "x-api-key"
  title: "API key header missing"
  severity: "MEDIUM"
  recommendation: "Provide valid API key."
""", encoding="utf-8")

    loaded = load_rules_from_file(plugin_file)
    assert len(loaded) == 1
    assert loaded[0].id == "PLUGIN-002"


# --- 13. Scope & Guardrails (Private IP & Permissions) ---

def test_private_ip_detection():
    assert is_private_or_internal_ip("127.0.0.1") is True
    assert is_private_or_internal_ip("10.0.0.1") is True
    assert is_private_or_internal_ip("192.168.1.1") is True
    assert is_private_or_internal_ip("172.16.0.5") is True
    assert is_private_or_internal_ip("8.8.8.8") is False
    assert is_private_or_internal_ip("1.1.1.1") is False


def test_validate_target_scope_blocks_private():
    with pytest.raises(ScopeError):
        validate_target_scope("http://127.0.0.1:8000", allow_private=False)

    with pytest.raises(ScopeError):
        validate_target_scope("http://192.168.1.50", allow_private=False)

    # Allowed when allow_private=True
    host, ip = validate_target_scope("http://127.0.0.1:8000", allow_private=True)
    assert host == "127.0.0.1"


def test_recon_requires_permission_flag():
    result = runner.invoke(app, ["recon", "example.com"])
    assert result.exit_code == 2
    assert "Otorisasi Ditolak" in result.output
    assert "--i-have-permission" in result.output


def test_recon_runs_with_permission(monkeypatch):
    from sentrix.recon import ReconResult, PortResult
    # Mock run_recon directly so recon command tests cleanly without real network
    monkeypatch.setattr(
        "sentrix.cli.run_recon",
        lambda target, **kw: ReconResult(
            target=target,
            subdomains=("api.example.com", "dev.example.com"),
            open_ports=(PortResult(port=443, open=True, service="https", banner=""),),
            discovered_paths=(),
        ),
    )
    monkeypatch.setattr("sentrix.cli.validate_target_scope", lambda t, **kw: (t, "93.184.216.34"))

    result = runner.invoke(app, ["recon", "example.com", "--i-have-permission"])
    assert result.exit_code == 0
    assert "Subdomains ditemukan" in result.output
    assert "api.example.com" in result.output


# --- 14. Audit logging ---

def test_audit_logging(tmp_path):
    log_file = tmp_path / "test_audit.log"
    log_audit_event("scan", "https://example.com", {"findings": 5}, log_file)

    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    data = json.loads(content.strip())
    assert data["action"] == "scan"
    assert data["target"] == "https://example.com"
    assert data["details"]["findings"] == 5


# --- 15. CLI scan command ---

def test_cli_scan_targets(tmp_path, monkeypatch):
    targets = tmp_path / "targets.txt"
    targets.write_text("https://example1.com\nhttps://example2.com\n", encoding="utf-8")

    # Mock AsyncClient
    class MockAsyncResponse:
        def __init__(self, url):
            self.url = httpx.URL(url)
            self.status_code = 200
            self.headers = httpx.Headers({"Content-Security-Policy": "default-src 'self'"})
            self.history = []

    class MockAsyncClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url):
            return MockAsyncResponse(url)

    monkeypatch.setattr(cli.httpx, "AsyncClient", MockAsyncClient)

    result = runner.invoke(app, ["scan", str(targets), "--rate-limit", "0"])
    assert result.exit_code == 0
    assert "MULTI-TARGET SCAN" in result.output
    assert "example1.com" in result.output
    assert "example2.com" in result.output
