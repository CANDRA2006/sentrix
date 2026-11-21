"""SENTRIX: Local-first security posture analysis CLI."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from sentrix.audit import log_audit_event
from sentrix.cookies import analyze_cookies
from sentrix.discovery import (
    EXPOSED_FILE_PATHS,
    check_exposed_file_status,
    parse_robots_txt,
    parse_security_txt,
)
from sentrix.fingerprint import fingerprint_all
from sentrix.history import (
    DB_ENV_VAR,
    HistoryError,
    ScanDiff,
    StoredFinding,
    compare_scans,
    default_db_path,
    list_scans,
    open_history,
    save_scan,
)
from sentrix.models import SEVERITY_ORDER, Finding, Severity
from sentrix.net import (
    ScopeError,
    analyze_redirects,
    find_dangerous_methods,
    inspect_tls,
    parse_allow_methods,
    validate_target_scope,
)
from sentrix.normalize import normalize_findings
from sentrix.policy import (
    CONFIG_ENV_VAR,
    Policy,
    PolicyError,
    apply_policy,
    describe_rule_policy,
    gate_failed,
    load_policy,
)
from sentrix.recon import run_recon
from sentrix.report.diff import diff_reports
from sentrix.reporting import ReportFormat, render_report
from sentrix.rules import (
    ALL_RULES,
    CORE_RULES,
    EXTENDED_RULES,
    RULES,
    Rule,
    evaluate_headers,
    load_rules_from_directory,
)
from sentrix.scoring import compute_score
from sentrix.sri import check_sri

app = typer.Typer(
    name="sentrix",
    help="Local-first security posture analysis CLI.",
    no_args_is_help=True,
)
console = Console()

TOOL_NAME = "SENTRIX"
TOOL_VERSION = "0.1.0"
REPORT_SCHEMA_VERSION = "1.1"
REQUEST_TIMEOUT_SECONDS = 8.0
MAX_REDIRECTS = 5
EXIT_GATE_FAILED = 3

LIMITATIONS = [
    "Checks response headers only.",
    "Missing headers are observations, not proof of exploitation.",
    "Severity is a rule-based triage label, not a CVSS score.",
    "No vulnerability exploitation is performed.",
]

EXTENDED_LIMITATIONS = LIMITATIONS + [
    "Cookie analysis only inspects flag presence, not secret cookie values.",
    "TLS inspection uses the local system CA certificate store.",
    "Exposed-file checks only inspect HTTP status codes without reading response bodies.",
    "Technology fingerprinting is best-effort based on observable metadata.",
    "Subresource integrity inspection checks script tags in HTML bodies when requested.",
]


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"{TOOL_NAME.lower()} {TOOL_VERSION}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_show_version,
        is_eager=True,
        help="Tampilkan versi lalu keluar.",
    ),
) -> None:
    """Local-first security posture analysis CLI."""


def validate_url(url: str, allow_private: bool = True) -> str:
    """Accept only absolute HTTP or HTTPS URLs.

    Optionally validates target scope against private/internal IP ranges.
    """
    try:
        parsed = urlsplit(url)
        parsed.port
    except ValueError as exc:
        raise typer.BadParameter("URL tidak valid.") from exc

    if parsed.scheme not in {"http", "https"}:
        raise typer.BadParameter("URL harus menggunakan HTTP atau HTTPS.")

    if not parsed.hostname:
        raise typer.BadParameter("URL harus memiliki hostname yang valid.")

    if parsed.username or parsed.password:
        raise typer.BadParameter(
            "Jangan masukkan kredensial ke dalam URL."
        )

    if any(char.isspace() or not char.isprintable() for char in url):
        raise typer.BadParameter(
            "URL tidak boleh mengandung spasi atau karakter kontrol."
        )

    if not allow_private:
        try:
            validate_target_scope(url, allow_private=False)
        except ScopeError as exc:
            raise typer.BadParameter(str(exc)) from exc

    return url


def evaluate_findings(
    headers: httpx.Headers,
    is_https: bool,
    rules: tuple[Rule, ...] = RULES,
) -> list[Finding]:
    """Run the header rules and return normalized Finding objects."""
    return normalize_findings(evaluate_headers(headers, is_https, rules))


def analyze_headers(
    headers: httpx.Headers,
    is_https: bool,
    rules: tuple[Rule, ...] = RULES,
) -> list[dict]:
    """Generate normalized findings as report-ready dicts."""
    return [
        finding.to_dict()
        for finding in evaluate_findings(headers, is_https, rules)
    ]


DbOption = typer.Option(
    None,
    "--db",
    envvar=DB_ENV_VAR,
    help="Path database riwayat SQLite (default: ~/.sentrix/history.db).",
)

ConfigOption = typer.Option(
    None,
    "--config",
    "-c",
    envvar=CONFIG_ENV_VAR,
    help="File kebijakan TOML: nonaktifkan aturan, ubah severity, fail_on.",
)


def load_effective_policy(
    config: Path | None, fail_on: Severity | None, rules: tuple[Rule, ...] = RULES
) -> Policy:
    """Load the policy file (if any); ``--fail-on`` overrides the file."""
    policy = Policy()
    if config is not None:
        try:
            policy = load_policy(config, rules=rules)
        except PolicyError as exc:
            console.print(
                "[bold red]Konfigurasi tidak valid[/bold red] "
                f"({escape(str(config))}): {escape(str(exc))}"
            )
            raise typer.Exit(code=2) from exc

    if fail_on is not None:
        policy = replace(policy, fail_on=fail_on)
    return policy


def build_report(
    requested_url: str,
    response: httpx.Response,
    findings: list[dict],
    policy: Policy | None = None,
    *,
    score_data: dict | None = None,
    cookie_data: list[dict] | None = None,
    tls_data: dict | None = None,
    redirect_data: dict | None = None,
    methods_data: dict | None = None,
    discovery_data: dict | None = None,
    fingerprint_data: list[dict] | None = None,
    sri_data: list[dict] | None = None,
) -> dict:
    """Build the JSON-serializable report without leaking header values."""
    has_extended = any(
        x is not None
        for x in (
            score_data,
            cookie_data,
            tls_data,
            redirect_data,
            methods_data,
            discovery_data,
            fingerprint_data,
            sri_data,
        )
    )

    schema_version = "2.0" if has_extended else REPORT_SCHEMA_VERSION
    limits = list(EXTENDED_LIMITATIONS if has_extended else LIMITATIONS)

    rep: dict = {
        "schema_version": schema_version,
        "tool": {
            "name": TOOL_NAME,
            "version": TOOL_VERSION,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": {
            "requested_url": requested_url,
            "final_url": str(response.url),
        },
        "http": {
            "status_code": response.status_code,
            "final_scheme": response.url.scheme,
            "redirect_count": len(response.history),
        },
        "policy": (policy or Policy()).to_report_dict(),
        "summary": {
            "findings": len(findings),
            "by_severity": {
                severity: sum(
                    finding["severity"] == severity
                    for finding in findings
                )
                for severity in SEVERITY_ORDER
            },
        },
        "findings": findings,
        "limitations": limits,
    }

    if score_data is not None:
        rep["score"] = score_data
    if cookie_data is not None:
        rep["cookies"] = cookie_data
    if tls_data is not None:
        rep["tls"] = tls_data
    if redirect_data is not None:
        rep["redirect_analysis"] = redirect_data
    if methods_data is not None:
        rep["http_methods"] = methods_data
    if discovery_data is not None:
        rep["discovery"] = discovery_data
    if fingerprint_data is not None:
        rep["technologies"] = fingerprint_data
    if sri_data is not None:
        rep["sri"] = sri_data

    return rep


# --- Helpers for extended checks ---

def _build_cookie_findings(cookie_data: list[dict], is_https: bool) -> list[Finding]:
    findings: list[Finding] = []
    from sentrix.models import Confidence, Evidence

    for cookie in cookie_data:
        name = cookie.get("name", "unknown")
        if is_https and not cookie.get("secure"):
            findings.append(Finding(
                id="COOKIE-001",
                title=f"Cookie '{name}' tidak memiliki flag Secure",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                evidence=Evidence(type="cookie_flag_missing", header="set-cookie"),
                recommendation="Tambahkan flag Secure pada cookie agar hanya dikirim via HTTPS.",
            ))
        if not cookie.get("httponly"):
            findings.append(Finding(
                id="COOKIE-002",
                title=f"Cookie '{name}' tidak memiliki flag HttpOnly",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=Evidence(type="cookie_flag_missing", header="set-cookie"),
                recommendation="Tambahkan flag HttpOnly untuk mencegah akses script.",
            ))
        samesite = str(cookie.get("samesite", "")).lower()
        if not samesite or samesite == "none":
            findings.append(Finding(
                id="COOKIE-003",
                title=f"Cookie '{name}' tidak memiliki SameSite yang ketat",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=Evidence(type="cookie_flag_missing", header="set-cookie"),
                recommendation="Gunakan SameSite=Strict atau SameSite=Lax.",
            ))
        if cookie.get("has_host_prefix") and not cookie.get("host_prefix_valid"):
            findings.append(Finding(
                id="COOKIE-004",
                title=f"Cookie '{name}' tidak memenuhi syarat prefix __Host-",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                evidence=Evidence(type="cookie_prefix_invalid", header="set-cookie"),
                recommendation="__Host- membutuhkan Secure, Path=/, dan tanpa Domain.",
            ))
        if cookie.get("has_secure_prefix") and not cookie.get("secure_prefix_valid"):
            findings.append(Finding(
                id="COOKIE-005",
                title=f"Cookie '{name}' tidak memenuhi syarat prefix __Secure-",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                evidence=Evidence(type="cookie_prefix_invalid", header="set-cookie"),
                recommendation="__Secure- membutuhkan flag Secure.",
            ))
    return findings


def _build_tls_findings(tls_data: dict | None) -> list[Finding]:
    if not tls_data:
        return []
    findings: list[Finding] = []
    from sentrix.models import Confidence, Evidence

    if tls_data.get("expired"):
        findings.append(Finding(
            id="TLS-001",
            title="Sertifikat TLS sudah kedaluwarsa",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=Evidence(type="tls_certificate", header="tls"),
            recommendation="Perpanjang sertifikat TLS segera.",
        ))
    days = tls_data.get("days_until_expiry")
    if days is not None and 0 < days <= 30:
        findings.append(Finding(
            id="TLS-002",
            title=f"Sertifikat TLS akan kedaluwarsa dalam {days} hari",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence=Evidence(type="tls_certificate", header="tls"),
            recommendation="Perpanjang sertifikat TLS sebelum kedaluwarsa.",
        ))
    if tls_data.get("san_mismatch"):
        findings.append(Finding(
            id="TLS-003",
            title="SAN mismatch: hostname tidak tercantum di Subject Alternative Name",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            evidence=Evidence(type="tls_certificate", header="tls"),
            recommendation="Pastikan sertifikat mencakup hostname target.",
        ))
    proto = tls_data.get("protocol_version", "")
    if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(Finding(
            id="TLS-004",
            title=f"Protokol TLS usang digunakan: {proto}",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=Evidence(type="tls_protocol", header="tls"),
            recommendation="Gunakan TLS 1.2 atau TLS 1.3.",
        ))
    bits = tls_data.get("cipher_bits", 0)
    if bits and bits < 128:
        findings.append(Finding(
            id="TLS-005",
            title=f"Cipher lemah ({bits}-bit) digunakan",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=Evidence(type="tls_cipher", header="tls"),
            recommendation="Gunakan cipher modern dengan panjang kunci minimal 128-bit.",
        ))
    return findings


def _build_redirect_findings(redirect_data: dict) -> list[Finding]:
    findings: list[Finding] = []
    from sentrix.models import Confidence, Evidence

    if redirect_data.get("has_downgrade"):
        findings.append(Finding(
            id="REDIRECT-001",
            title="Redirect chain melakukan downgrade HTTPS → HTTP",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=Evidence(type="redirect_downgrade", header="location"),
            recommendation="Pastikan seluruh redirect chain tetap berada di HTTPS.",
        ))
    if redirect_data.get("has_cross_domain"):
        findings.append(Finding(
            id="REDIRECT-002",
            title="Redirect chain mengarah ke domain berbeda",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            evidence=Evidence(type="redirect_cross_domain", header="location"),
            recommendation="Verifikasi redirect cross-domain merupakan perilaku yang diharapkan.",
        ))
    return findings


def _build_methods_findings(methods_data: dict | None) -> list[Finding]:
    if not methods_data:
        return []
    findings: list[Finding] = []
    from sentrix.models import Confidence, Evidence

    dangerous = methods_data.get("dangerous_methods", [])
    if dangerous:
        methods_str = ", ".join(dangerous)
        findings.append(Finding(
            id="METHODS-001",
            title=f"HTTP method berisiko diizinkan: {methods_str}",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence=Evidence(type="dangerous_http_method", header="allow"),
            recommendation=f"Nonaktifkan method HTTP yang tidak diperlukan: {methods_str}.",
        ))
    return findings


def _build_discovery_findings(discovery_data: dict) -> list[Finding]:
    findings: list[Finding] = []
    from sentrix.models import Confidence, Evidence

    sec_txt = discovery_data.get("security_txt", {})
    if not sec_txt.get("found"):
        findings.append(Finding(
            id="DISC-001",
            title="security.txt tidak ditemukan",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            evidence=Evidence(type="missing_security_txt", header="security.txt"),
            recommendation="Publikasikan /.well-known/security.txt sesuai RFC 9116.",
        ))
    else:
        if not sec_txt.get("has_contact"):
            findings.append(Finding(
                id="DISC-002",
                title="security.txt tidak memiliki field Contact (wajib)",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=Evidence(type="incomplete_security_txt", header="security.txt"),
                recommendation="Tambahkan field Contact ke security.txt.",
            ))
        if not sec_txt.get("has_expires"):
            findings.append(Finding(
                id="DISC-003",
                title="security.txt tidak memiliki field Expires (wajib)",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=Evidence(type="incomplete_security_txt", header="security.txt"),
                recommendation="Tambahkan field Expires ke security.txt.",
            ))

    robots = discovery_data.get("robots_txt", {})
    sensitive = robots.get("sensitive_paths", [])
    if sensitive:
        paths_str = ", ".join(sensitive[:5])
        findings.append(Finding(
            id="DISC-004",
            title=f"robots.txt mengungkap path sensitif: {paths_str}",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            evidence=Evidence(type="sensitive_path_in_robots", header="robots.txt"),
            recommendation="Tinjau apakah path sensitif perlu dicantumkan di robots.txt.",
        ))

    exposed = discovery_data.get("exposed_files", [])
    for ef in exposed:
        path = ef.get("path", "")
        findings.append(Finding(
            id="DISC-005",
            title=f"File sensitif berpotensi terekspos: {path}",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            evidence=Evidence(type="exposed_file", header=path),
            recommendation=f"Blokir akses publik ke {path}.",
        ))
    return findings


def _build_sri_findings(sri_data: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    from sentrix.models import Confidence, Evidence

    for script in sri_data:
        src = script.get("src", "")
        display = src[:80] + "..." if len(src) > 80 else src
        findings.append(Finding(
            id="SRI-001",
            title=f"Script pihak ketiga tanpa Subresource Integrity: {display}",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            evidence=Evidence(type="missing_sri", header="script-src"),
            recommendation="Tambahkan atribut integrity dan crossorigin pada tag script.",
        ))
    return findings


def _build_cors_findings(headers: httpx.Headers) -> list[Finding]:
    findings: list[Finding] = []
    from sentrix.models import Confidence, Evidence

    allow_origin = headers.get("access-control-allow-origin", "")
    allow_creds = headers.get("access-control-allow-credentials", "").lower()
    if allow_origin == "*" and allow_creds == "true":
        findings.append(Finding(
            id="CORS-001",
            title="CORS: Allow-Origin: * dikombinasi dengan Allow-Credentials: true",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence=Evidence(type="cors_misconfiguration", header="access-control-allow-origin"),
            recommendation="Hindari wildcard origin bersama allow-credentials.",
        ))
    return findings


# --- Commands ---

@app.command()
def check(
    url: str = typer.Argument(
        ...,
        help="Satu URL yang kamu miliki atau diizinkan untuk diperiksa.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Simpan laporan ke file (format default: JSON).",
    ),
    report_format: ReportFormat | None = typer.Option(
        None,
        "--format",
        "-f",
        case_sensitive=False,
        help="Format file laporan: json, sarif, html, atau markdown. Perlu --output.",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Simpan hasil scan ke riwayat lokal (SQLite).",
    ),
    db: Path | None = DbOption,
    config: Path | None = ConfigOption,
    fail_on: Severity | None = typer.Option(
        None,
        "--fail-on",
        case_sensitive=False,
        help=(
            "Keluar dengan kode 3 jika ada temuan pada severity ini atau "
            "lebih tinggi. Menimpa fail_on di file konfigurasi."
        ),
    ),
    timeout: float = typer.Option(
        REQUEST_TIMEOUT_SECONDS,
        "--timeout",
        min=1.0,
        max=60.0,
        help="Batas waktu request dalam detik.",
    ),
    max_redirects: int = typer.Option(
        MAX_REDIRECTS,
        "--max-redirects",
        min=0,
        max=20,
        help="Jumlah maksimum redirect yang diikuti.",
    ),
    extended: bool = typer.Option(
        False,
        "--extended",
        help="Jalankan pemeriksaan lanjutan (cookies, TLS, discovery, SRI, info disclosure, scoring).",
    ),
    tls_check: bool = typer.Option(
        True,
        "--tls/--no-tls",
        help="Pemeriksaan TLS (hanya berlaku jika --extended aktif).",
    ),
    methods_check: bool = typer.Option(
        True,
        "--methods/--no-methods",
        help="Pemeriksaan HTTP OPTIONS methods (hanya berlaku jika --extended aktif).",
    ),
    discover_check: bool = typer.Option(
        True,
        "--discover/--no-discover",
        help="Pemeriksaan security.txt & robots.txt (hanya berlaku jika --extended aktif).",
    ),
    sri_check: bool = typer.Option(
        False,
        "--sri",
        help="Periksa Subresource Integrity pada script HTML eksternal.",
    ),
    rules_dir: Path | None = typer.Option(
        None,
        "--rules-dir",
        help="Direktori plugin rules TOML/YAML tambahan.",
    ),
    allow_private: bool = typer.Option(
        True,
        "--allow-private/--block-private",
        help="Izinkan atau blokir target di rentang IP internal/private.",
    ),
    audit_log: Path | None = typer.Option(
        None,
        "--audit-log",
        help="Path file audit log untuk mencatat tindakan.",
    ),
) -> None:
    """Inspect basic or extended HTTP security posture for one URL."""
    validate_url(url, allow_private=allow_private)

    if report_format is not None and output is None:
        raise typer.BadParameter(
            "--format hanya berlaku bersama --output.",
            param_hint="--format",
        )

    # Determine rule set
    current_rules = list(ALL_RULES if extended else CORE_RULES)
    if rules_dir is not None and rules_dir.is_dir():
        custom_rules = load_rules_from_directory(rules_dir)
        current_rules.extend(custom_rules)

    rules_tuple = tuple(current_rules)
    policy = load_effective_policy(config, fail_on, rules=rules_tuple)
    active_rules = apply_policy(rules_tuple, policy)

    console.print("\n[bold cyan]SENTRIX[/bold cyan] :: HTTP POSTURE CHECK")
    console.print(f"[dim]Target: {escape(url)}[/dim]")
    if not policy.is_default:
        console.print(f"[dim]Kebijakan: {escape(policy.summary())}[/dim]")
    if not active_rules:
        console.print(
            "[yellow]Peringatan:[/yellow] semua aturan dinonaktifkan, "
            "jadi tidak ada pemeriksaan yang dijalankan."
        )
    console.print()

    html_content: str | None = None
    cookie_data: list[dict] | None = None
    tls_data: dict | None = None
    redirect_data: dict | None = None
    methods_data: dict | None = None
    discovery_data: dict | None = None
    fingerprint_data: list[dict] | None = None
    sri_data: list[dict] | None = None

    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            max_redirects=max_redirects,
            headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"},
        ) as client:
            with client.stream("GET", url) as response:
                # In standard mode, the body is NEVER downloaded (stream untouched).
                # Only if explicitly requested via --sri do we read HTML body chunks.
                if sri_check:
                    ctype = response.headers.get("content-type", "").lower()
                    if "text/html" in ctype:
                        chunks: list[bytes] = []
                        total = 0
                        for chunk in response.iter_bytes(chunk_size=8192):
                            chunks.append(chunk)
                            total += len(chunk)
                            if total >= 512 * 1024:
                                break
                        html_content = b"".join(chunks).decode("utf-8", errors="replace")

            is_https = response.url.scheme == "https"

            if extended:
                raw_cookies = [v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"]
                if raw_cookies:
                    analyses = analyze_cookies(raw_cookies, is_https)
                    cookie_data = [a.to_dict() for a in analyses]

                redirect_data = analyze_redirects(list(response.history), str(response.url)).to_dict()

                if methods_check:
                    try:
                        opt_resp = client.request("OPTIONS", url)
                        allow_hdr = opt_resp.headers.get("allow", "")
                        if allow_hdr:
                            methods = parse_allow_methods(allow_hdr)
                            dang = find_dangerous_methods(methods)
                            methods_data = {
                                "allowed_methods": list(methods),
                                "dangerous_methods": list(dang),
                            }
                    except Exception:
                        pass

                c_names = [c["name"] for c in (cookie_data or [])]
                headers_dict = {k.lower(): v for k, v in response.headers.items()}
                techs = fingerprint_all(headers_dict, c_names, html_content)
                fingerprint_data = [t.to_dict() for t in techs]

                if sri_check and html_content:
                    sri_results = check_sri(html_content, str(response.url))
                    sri_data = [s.to_dict() for s in sri_results if not s.has_integrity]

                if tls_check and is_https:
                    parsed_u = urlsplit(url)
                    host = parsed_u.hostname
                    port = parsed_u.port or 443
                    if host:
                        t_info = inspect_tls(host, port, timeout)
                        if t_info:
                            tls_data = t_info.to_dict()

                if discover_check:
                    parsed_u = urlsplit(url)
                    origin = f"{parsed_u.scheme}://{parsed_u.hostname}"
                    if parsed_u.port and parsed_u.port not in (80, 443):
                        origin += f":{parsed_u.port}"

                    d_res: dict = {"security_txt": None, "robots_txt": None, "exposed_files": []}
                    for path in ("/.well-known/security.txt", "/security.txt"):
                        try:
                            s_resp = client.get(f"{origin}{path}")
                            if s_resp.status_code == 200:
                                d_res["security_txt"] = parse_security_txt(s_resp.text[:8192]).to_dict()
                                break
                            elif s_resp.status_code != 404:
                                d_res["security_txt"] = {"found": False, "status_code": s_resp.status_code}
                        except Exception:
                            pass
                    if d_res["security_txt"] is None:
                        d_res["security_txt"] = {"found": False, "status_code": None}

                    try:
                        r_resp = client.get(f"{origin}/robots.txt")
                        if r_resp.status_code == 200:
                            d_res["robots_txt"] = parse_robots_txt(r_resp.text[:16384]).to_dict()
                        else:
                            d_res["robots_txt"] = {"found": False, "status_code": r_resp.status_code}
                    except Exception:
                        d_res["robots_txt"] = {"found": False, "status_code": None}

                    exposed = []
                    for ef_path in EXPOSED_FILE_PATHS:
                        try:
                            h_resp = client.request("HEAD", f"{origin}{ef_path}")
                            stat = check_exposed_file_status(ef_path, h_resp.status_code)
                            if stat.exists:
                                exposed.append(stat.to_dict())
                        except Exception:
                            pass
                    d_res["exposed_files"] = exposed
                    discovery_data = d_res

    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        console.print(f"[bold red]Request gagal:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=1) from exc

    finding_objects = evaluate_findings(
        response.headers,
        is_https=response.url.scheme == "https",
        rules=active_rules,
    )

    extended_findings: list[Finding] = []
    if extended:
        if cookie_data:
            extended_findings.extend(_build_cookie_findings(cookie_data, response.url.scheme == "https"))
        if tls_data:
            extended_findings.extend(_build_tls_findings(tls_data))
        if redirect_data:
            extended_findings.extend(_build_redirect_findings(redirect_data))
        if methods_data:
            extended_findings.extend(_build_methods_findings(methods_data))
        if discovery_data:
            extended_findings.extend(_build_discovery_findings(discovery_data))
        if sri_data:
            extended_findings.extend(_build_sri_findings(sri_data))
        extended_findings.extend(_build_cors_findings(response.headers))

    all_finding_objects = normalize_findings(list(finding_objects) + extended_findings)
    findings = [f.to_dict() for f in all_finding_objects]

    score_data = None
    if extended:
        score_data = compute_score(findings).to_dict()

    report = build_report(
        url,
        response,
        findings,
        policy,
        score_data=score_data,
        cookie_data=cookie_data,
        tls_data=tls_data,
        redirect_data=redirect_data,
        methods_data=methods_data,
        discovery_data=discovery_data,
        fingerprint_data=fingerprint_data,
        sri_data=sri_data,
    )

    table = Table(title="HTTP Security Posture")
    table.add_column("Rule ID")
    table.add_column("Severity")
    table.add_column("Finding")

    for finding in findings:
        table.add_row(
            finding["id"],
            finding["severity"],
            finding["title"],
        )

    console.print(
        f"HTTP status: [bold]{response.status_code}[/bold] | "
        f"Redirects: {len(response.history)}"
    )
    console.print(table)
    console.print(f"\nFindings: {len(findings)}")

    if score_data:
        g = score_data.get("grade", "N/A")
        s = score_data.get("score", 0)
        color = "green" if g in ("A", "B") else ("yellow" if g in ("C", "D") else "red")
        console.print(f"Score: [bold {color}]{s}/100 ({g})[/bold {color}]")

    if output is not None:
        fmt = report_format or ReportFormat.JSON
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(render_report(report, fmt), encoding="utf-8")
        except OSError as exc:
            console.print(
                f"[bold red]Laporan gagal disimpan:[/bold red] {escape(str(exc))}"
            )
            raise typer.Exit(code=1) from exc
        console.print(
            f"[green]Laporan tersimpan:[/green] {escape(str(output))} [dim]({fmt.value})[/dim]"
        )

    if save:
        try:
            with open_history(db or default_db_path()) as conn:
                scan_id = save_scan(
                    conn,
                    target=url,
                    final_url=str(response.url),
                    scanned_at=report["timestamp"],
                    status_code=response.status_code,
                    tool_version=TOOL_VERSION,
                    findings=all_finding_objects,
                    policy=policy.rule_policy_json(),
                )
        except HistoryError as exc:
            console.print(f"[bold red]Riwayat gagal disimpan:[/bold red] {escape(str(exc))}")
            raise typer.Exit(code=1) from exc

        console.print(f"[green]Scan tersimpan di riwayat:[/green] #{scan_id}")

    # Audit log
    log_audit_event("check", url, {"status": response.status_code, "findings": len(findings)}, audit_log)

    if policy.fail_on is not None:
        threshold = policy.fail_on.value
        if gate_failed(all_finding_objects, policy.fail_on):
            console.print(
                f"[bold red]Gate gagal:[/bold red] ada temuan dengan "
                f"severity {threshold} atau lebih tinggi."
            )
            raise typer.Exit(code=EXIT_GATE_FAILED)
        note = "" if active_rules else " (tanpa pemeriksaan: semua aturan nonaktif)"
        console.print(
            f"[green]Gate lulus:[/green] tidak ada temuan dengan "
            f"severity {threshold} atau lebih tinggi.{note}"
        )


@app.command("scan")
def scan_command(
    targets_file: Path = typer.Argument(
        ...,
        help="File teks berisi daftar URL (satu per baris).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Direktori untuk menyimpan laporan per target.",
    ),
    report_format: ReportFormat | None = typer.Option(
        None,
        "--format",
        "-f",
        case_sensitive=False,
        help="Format file laporan: json, sarif, html, atau markdown.",
    ),
    config: Path | None = ConfigOption,
    fail_on: Severity | None = typer.Option(
        None,
        "--fail-on",
        case_sensitive=False,
        help="Keluar dengan kode 3 jika ada target dengan temuan pada severity ini atau lebih tinggi.",
    ),
    timeout: float = typer.Option(
        REQUEST_TIMEOUT_SECONDS,
        "--timeout",
        min=1.0,
        max=60.0,
        help="Batas waktu request per target.",
    ),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        min=1,
        max=50,
        help="Jumlah konkurensi request bersamaan.",
    ),
    rate_limit: float = typer.Option(
        2.0,
        "--rate-limit",
        min=0.0,
        max=60.0,
        help="Jeda minimum (detik) antar request ke target yang sama.",
    ),
    allow_private: bool = typer.Option(
        False,
        "--allow-private",
        help="Izinkan pemindaian alamat IP private/internal.",
    ),
    i_have_permission: bool = typer.Option(
        False,
        "--i-have-permission",
        help="Konfirmasi otorisasi untuk melakukan multi-target scan.",
    ),
    audit_log: Path | None = typer.Option(
        None,
        "--audit-log",
        help="Path file audit log.",
    ),
) -> None:
    """Scan multiple targets concurrently with rate limiting and safety guardrails."""
    if not targets_file.is_file():
        console.print(f"[bold red]File tidak ditemukan:[/bold red] {escape(str(targets_file))}")
        raise typer.Exit(code=2)

    lines = targets_file.read_text(encoding="utf-8").splitlines()
    raw_urls = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    if not raw_urls:
        console.print("[yellow]File target kosong.[/yellow]")
        raise typer.Exit(code=0)

    valid_urls: list[str] = []
    for u in raw_urls:
        try:
            valid_urls.append(validate_url(u, allow_private=allow_private))
        except typer.BadParameter as exc:
            console.print(f"[yellow]Target dilewati:[/yellow] {escape(u)} ({escape(str(exc))})")

    if not valid_urls:
        console.print("[bold red]Tidak ada URL valid yang dapat dipindai.[/bold red]")
        raise typer.Exit(code=2)

    policy = load_effective_policy(config, fail_on)
    active_rules = apply_policy(RULES, policy)

    console.print(f"\n[bold cyan]SENTRIX[/bold cyan] :: MULTI-TARGET SCAN")
    console.print(f"[dim]Targets: {len(valid_urls)} | Concurrency: {concurrency} | Rate limit: {rate_limit}s[/dim]\n")

    log_audit_event("scan", str(targets_file), {"targets_count": len(valid_urls)}, audit_log)

    async def _scan_target(
        aclient: httpx.AsyncClient,
        target_url: str,
        sem: asyncio.Semaphore,
    ) -> tuple[str, dict | None, str | None]:
        async with sem:
            try:
                resp = await aclient.get(target_url)
                is_https = resp.url.scheme == "https"
                f_objs = evaluate_findings(resp.headers, is_https, active_rules)
                f_dicts = [f.to_dict() for f in f_objs]
                sc = compute_score(f_dicts)
                rep = build_report(
                    target_url,
                    resp,
                    f_dicts,
                    policy,
                    score_data=sc.to_dict(),
                )
                if rate_limit > 0:
                    await asyncio.sleep(rate_limit)
                return (target_url, rep, None)
            except Exception as exc:
                return (target_url, None, str(exc))

    async def _run() -> list[tuple[str, dict | None, str | None]]:
        sem = asyncio.Semaphore(concurrency)
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"},
        ) as aclient:
            tasks = [_scan_target(aclient, u, sem) for u in valid_urls]
            return await asyncio.gather(*tasks)

    results = asyncio.run(_run())

    table = Table(title="Scan Results")
    table.add_column("Target")
    table.add_column("Status", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Score")
    table.add_column("Grade")

    gate_failed_detected = False

    for target_url, rep_dict, err in results:
        if err:
            table.add_row(escape(target_url), "[red]ERROR[/red]", "-", "-", "-")
            continue

        assert rep_dict is not None
        sc = rep_dict.get("score", {})
        table.add_row(
            escape(target_url),
            str(rep_dict["http"]["status_code"]),
            str(rep_dict["summary"]["findings"]),
            str(sc.get("score", "N/A")),
            str(sc.get("grade", "N/A")),
        )

        if output is not None:
            fmt = report_format or ReportFormat.JSON
            parsed = urlsplit(target_url)
            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", parsed.hostname or "scan")
            ext = {
                "json": ".json",
                "sarif": ".sarif",
                "html": ".html",
                "markdown": ".md",
            }.get(fmt.value, ".json")
            target_path = output / f"{safe_name}{ext}"
            output.mkdir(parents=True, exist_ok=True)
            target_path.write_text(render_report(rep_dict, fmt), encoding="utf-8")

        if policy.fail_on is not None:
            for f in rep_dict.get("findings", []):
                sev_str = f.get("severity", "")
                if sev_str in Severity.__members__:
                    if Severity(sev_str).rank <= policy.fail_on.rank:
                        gate_failed_detected = True

    console.print(table)

    success = sum(1 for _, r, _ in results if r is not None)
    failed = sum(1 for _, _, e in results if e is not None)
    console.print(f"\nSelesai: {success} berhasil, {failed} gagal dari {len(valid_urls)} target.")

    if gate_failed_detected:
        console.print(
            f"[bold red]Gate gagal:[/bold red] ada target dengan temuan "
            f"severity {policy.fail_on.value} atau lebih tinggi."
        )
        raise typer.Exit(code=EXIT_GATE_FAILED)


@app.command("diff")
def diff_command(
    report1: Path = typer.Argument(..., help="Path laporan lama (JSON)."),
    report2: Path = typer.Argument(..., help="Path laporan baru (JSON)."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Simpan hasil diff ke file."),
) -> None:
    """Compare two JSON report documents to see new, resolved, and changed findings."""
    for p in (report1, report2):
        if not p.is_file():
            console.print(f"[bold red]File tidak ditemukan:[/bold red] {escape(str(p))}")
            raise typer.Exit(code=2)

    try:
        rep_a = json.loads(report1.read_text(encoding="utf-8"))
        rep_b = json.loads(report2.read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[bold red]Gagal membaca JSON:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=1) from exc

    diff = diff_reports(rep_a, rep_b)

    console.print(f"\n[bold cyan]SENTRIX[/bold cyan] :: REPORT DIFF")
    console.print(f"[dim]Lama: {escape(str(report1))} ({escape(diff.timestamp_a)})[/dim]")
    console.print(f"[dim]Baru: {escape(str(report2))} ({escape(diff.timestamp_b)})[/dim]\n")

    for f in diff.appeared:
        console.print(f"[red]BARU     [/red] {f.rule_id} [{f.severity}] {escape(f.title)}")
    for f in diff.resolved:
        console.print(f"[green]TERATASI [/green] {f.rule_id} [{f.severity}] {escape(f.title)}")
    for a, b in diff.severity_changed:
        console.print(f"[yellow]BERUBAH  [/yellow] {b.rule_id} {a.severity} -> {b.severity} {escape(b.title)}")

    console.print(
        f"\nBaru: {len(diff.appeared)} | Teratasi: {len(diff.resolved)} | "
        f"Berubah: {len(diff.severity_changed)} | Tetap: {len(diff.unchanged)}"
    )

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(diff.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]Diff tersimpan:[/green] {escape(str(output))}")


@app.command("recon")
def recon_command(
    target: str = typer.Argument(..., help="Hostname atau domain target."),
    i_have_permission: bool = typer.Option(
        False,
        "--i-have-permission",
        help="Wajib: konfirmasi bahwa kamu memiliki otorisasi untuk melakukan pengujian.",
    ),
    allow_private: bool = typer.Option(
        False,
        "--allow-private",
        help="Izinkan recon pada alamat IP private/internal.",
    ),
    rate_limit: float = typer.Option(
        0.5,
        "--rate-limit",
        min=0.1,
        max=10.0,
        help="Jeda antar-permintaan (detik).",
    ),
    subdomains: bool = typer.Option(True, "--subdomains/--no-subdomains", help="Enumerasi subdomain pasif via crt.sh."),
    ports: bool = typer.Option(True, "--ports/--no-ports", help="Port check ringan pada web ports umum."),
    dirs: bool = typer.Option(True, "--dirs/--no-dirs", help="Pemeriksaan direktori sensitif berbasis wordlist kecil."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Simpan hasil recon ke file JSON."),
    audit_log: Path | None = typer.Option(None, "--audit-log", help="Path file audit log."),
) -> None:
    """Perform passive & gentle reconnaissance (subdomains, open web ports, sensitive paths)."""
    if not i_have_permission:
        console.print(
            "\n[bold red]Otorisasi Ditolak:[/bold red] Recon aktif memerlukan persetujuan eksplisit.\n"
            "Gunakan flag [bold cyan]--i-have-permission[/bold cyan] setelah memastikan "
            "kamu memiliki wewenang hukum / scope tertulis untuk memeriksa target ini.\n"
        )
        raise typer.Exit(code=2)

    try:
        validate_target_scope(target, allow_private=allow_private)
    except ScopeError as exc:
        console.print(f"[bold red]Scope Error:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc

    console.print(f"\n[bold cyan]SENTRIX[/bold cyan] :: RECONNAISSANCE")
    console.print(f"[dim]Target: {escape(target)} | Rate limit: {rate_limit}s[/dim]\n")

    log_audit_event("recon", target, {"subdomains": subdomains, "ports": ports, "dirs": dirs}, audit_log)

    recon_res = run_recon(
        target,
        ports_scan=ports,
        subdomains_scan=subdomains,
        dirs_scan=dirs,
        rate_limit=rate_limit,
    )

    if subdomains:
        console.print(f"[bold]Subdomains ditemukan (via crt.sh pasif):[/bold] {len(recon_res.subdomains)}")
        for sub in recon_res.subdomains[:20]:
            console.print(f"  - {escape(sub)}")
        if len(recon_res.subdomains) > 20:
            console.print(f"  [dim]... dan {len(recon_res.subdomains) - 20} lainnya[/dim]")
        console.print()

    if ports:
        console.print(f"[bold]Port terbuka:[/bold] {len(recon_res.open_ports)}")
        for p in recon_res.open_ports:
            banner_info = f" ({p.banner})" if p.banner else ""
            console.print(f"  - [green]{p.port}[/green]/{p.service}{banner_info}")
        console.print()

    if dirs:
        console.print(f"[bold]Path responsif:[/bold] {len(recon_res.discovered_paths)}")
        for d in recon_res.discovered_paths:
            console.print(f"  - [cyan]{d.path}[/cyan] (HTTP {d.status_code})")
        console.print()

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(recon_res.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]Hasil recon tersimpan:[/green] {escape(str(output))}")


@app.command("rules")
def rules_command(
    config: Path | None = ConfigOption,
    all_rules: bool = typer.Option(False, "--all", help="Tampilkan semua aturan termasuk extended."),
    rules_dir: Path | None = typer.Option(None, "--rules-dir", help="Direktori plugin rules TOML/YAML tambahan."),
) -> None:
    """List built-in rules, extended rules, and plugin rules."""
    current_rules = list(ALL_RULES if all_rules else CORE_RULES)
    if rules_dir is not None and rules_dir.is_dir():
        current_rules.extend(load_rules_from_directory(rules_dir))

    rules_tuple = tuple(current_rules)
    policy = load_effective_policy(config, None, rules=rules_tuple)
    if not policy.is_default:
        console.print(f"[dim]Kebijakan: {escape(policy.summary())}[/dim]")

    table = Table(title="Rules")
    table.add_column("Rule ID")
    table.add_column("Header")
    table.add_column("Severity")
    table.add_column("Status")

    for rule in current_rules:
        override = policy.severity_overrides.get(rule.id)
        severity = rule.severity.value
        if override is not None:
            severity = f"{override.value} (bawaan: {rule.severity.value})"

        if rule.id in policy.disabled_rules:
            status = "nonaktif"
        elif rule.https_only:
            status = "aktif (hanya HTTPS)"
        else:
            status = "aktif"

        table.add_row(rule.id, rule.header, severity, status)

    console.print(table)


@app.command("history")
def history_command(
    limit: int = typer.Option(
        20, "--limit", "-n", min=1, max=500, help="Jumlah scan terbaru."
    ),
    db: Path | None = DbOption,
) -> None:
    """List saved scans, newest first."""
    try:
        with open_history(db or default_db_path()) as conn:
            scans = list_scans(conn, limit)
    except HistoryError as exc:
        console.print(f"[bold red]Riwayat gagal dibaca:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=1) from exc

    if not scans:
        console.print("Belum ada scan tersimpan. Gunakan: sentrix check URL --save")
        return

    table = Table(title="Scan History")
    table.add_column("ID", justify="right")
    table.add_column("Waktu (UTC)")
    table.add_column("Target")
    table.add_column("HTTP", justify="right")
    table.add_column("Findings", justify="right")

    for scan in scans:
        table.add_row(
            str(scan.id),
            escape(_short_time(scan.scanned_at)),
            escape(scan.target),
            str(scan.status_code),
            str(scan.finding_count),
        )

    console.print(table)


def _short_time(iso_timestamp: str) -> str:
    return iso_timestamp[:19].replace("T", " ")


def _finding_lines(label: str, style: str, items: list[StoredFinding]) -> None:
    for item in items:
        console.print(
            f"[{style}]{label}[/{style}] {item.rule_id} "
            f"{escape(f'[{item.severity.value}]')} {escape(item.title)}"
        )


def _print_diff(diff: ScanDiff) -> None:
    console.print(
        f"\n[bold cyan]SENTRIX[/bold cyan] :: COMPARE "
        f"#{diff.old.id} -> #{diff.new.id}"
    )
    for label, scan in (("Lama", diff.old), ("Baru", diff.new)):
        console.print(f"[dim]{label}: {escape(scan.target)} ({escape(scan.scanned_at)})[/dim]")
    console.print()

    if not diff.same_target:
        console.print(
            "[yellow]Peringatan:[/yellow] kedua scan memiliki target yang "
            "berbeda; hasil perbandingan mungkin tidak bermakna.\n"
        )

    if not diff.same_policy:
        console.print(
            "[yellow]Peringatan:[/yellow] kedua scan memakai kebijakan "
            "aturan yang berbeda "
            f"(lama: {escape(describe_rule_policy(diff.old.policy))}; "
            f"baru: {escape(describe_rule_policy(diff.new.policy))}). "
            "Temuan BARU, TERATASI, atau BERUBAH bisa jadi hanya akibat "
            "aturan yang dinonaktifkan atau diubah severity-nya, bukan "
            "karena targetnya berubah.\n"
        )

    _finding_lines("BARU     ", "red", list(diff.appeared))
    _finding_lines("TERATASI ", "green", list(diff.resolved))
    for change in diff.severity_changed:
        console.print(
            f"[yellow]BERUBAH  [/yellow] {change.after.rule_id} "
            f"{change.before.severity.value} -> {change.after.severity.value} "
            f"{escape(change.after.title)}"
        )

    console.print(
        f"\nBaru: {len(diff.appeared)} | Teratasi: {len(diff.resolved)} | "
        f"Berubah severity: {len(diff.severity_changed)} | "
        f"Tetap: {len(diff.unchanged)}"
    )


@app.command("compare")
def compare_command(
    old_id: int = typer.Argument(..., min=1, help="ID scan lama."),
    new_id: int = typer.Argument(..., min=1, help="ID scan baru."),
    db: Path | None = DbOption,
) -> None:
    """Compare two saved scans by finding fingerprint."""
    try:
        with open_history(db or default_db_path()) as conn:
            diff = compare_scans(conn, old_id, new_id)
    except HistoryError as exc:
        console.print(f"[bold red]Perbandingan gagal:[/bold red] {escape(str(exc))}")
        raise typer.Exit(code=1) from exc

    _print_diff(diff)


if __name__ == "__main__":
    app()
