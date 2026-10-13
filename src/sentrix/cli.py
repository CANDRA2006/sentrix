
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="sentrix",
    help="Local-first security posture analysis CLI.",
    no_args_is_help=True,
)
console = Console()

RULES = [
    {
        "id": "HTTP-001",
        "header": "content-security-policy",
        "title": "Content Security Policy tidak ditemukan",
        "severity": "MEDIUM",
        "recommendation": (
            "Evaluasi Content-Security-Policy sesuai "
            "arsitektur aplikasi dan uji sebelum diterapkan."
        ),
        "https_only": False,
    },
    {
        "id": "HTTP-002",
        "header": "strict-transport-security",
        "title": "HSTS tidak ditemukan",
        "severity": "MEDIUM",
        "recommendation": (
            "Untuk situs HTTPS, evaluasi Strict-Transport-Security "
            "setelah memastikan seluruh alur mendukung HTTPS."
        ),
        "https_only": True,
    },
    {
        "id": "HTTP-003",
        "header": "x-content-type-options",
        "title": "X-Content-Type-Options tidak ditemukan",
        "severity": "LOW",
        "recommendation": (
            "Evaluasi penggunaan X-Content-Type-Options: nosniff."
        ),
        "https_only": False,
    },
    {
        "id": "HTTP-004",
        "header": "referrer-policy",
        "title": "Referrer-Policy tidak ditemukan",
        "severity": "LOW",
        "recommendation": (
            "Tentukan Referrer-Policy yang sesuai kebutuhan privasi."
        ),
        "https_only": False,
    },
    {
        "id": "HTTP-005",
        "header": "permissions-policy",
        "title": "Permissions-Policy tidak ditemukan",
        "severity": "INFO",
        "recommendation": (
            "Evaluasi pembatasan fitur browser yang tidak diperlukan."
        ),
        "https_only": False,
    },
]


def validate_url(url: str) -> str:
    """Accept only absolute HTTP or HTTPS URLs."""
    parsed = urlsplit(url)

    if parsed.scheme not in {"http", "https"}:
        raise typer.BadParameter("URL harus menggunakan HTTP atau HTTPS.")

    if not parsed.hostname:
        raise typer.BadParameter("URL harus memiliki hostname yang valid.")

    if parsed.username or parsed.password:
        raise typer.BadParameter(
            "Jangan masukkan kredensial ke dalam URL."
        )

    if any(char.isspace() for char in url):
        raise typer.BadParameter("URL tidak boleh mengandung spasi.")

    return url


def analyze_headers(headers: httpx.Headers, is_https: bool) -> list[dict]:
    """Generate findings using deterministic local rules."""
    findings = []

    for rule in RULES:
        if rule["https_only"] and not is_https:
            continue

        value = headers.get(rule["header"])

        if value:
            continue

        findings.append(
            {
                "id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "confidence": "HIGH",
                "evidence": {
                    "type": "missing_response_header",
                    "header": rule["header"],
                },
                "recommendation": rule["recommendation"],
                "status": "observed",
            }
        )

    return findings


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
        help="Simpan laporan ke file JSON.",
    ),
) -> None:
    """Inspect basic HTTP security headers for one URL."""
    validate_url(url)

    console.print("\n[bold cyan]SENTRIX[/bold cyan] :: HTTP POSTURE CHECK")
    console.print(f"[dim]Target: {url}[/dim]\n")

    try:
        with httpx.Client(
            timeout=8.0,
            follow_redirects=True,
            max_redirects=5,
            headers={"User-Agent": "SENTRIX/0.1.0"},
        ) as client:
            response = client.get(url)

    except httpx.HTTPError as exc:
        console.print(f"[bold red]Request gagal:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    findings = analyze_headers(
        response.headers,
        is_https=response.url.scheme == "https",
    )

    report = {
        "schema_version": "1.0",
        "tool": {
            "name": "SENTRIX",
            "version": "0.1.0",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": {
            "requested_url": url,
            "final_url": str(response.url),
        },
        "http": {
            "status_code": response.status_code,
            "final_scheme": response.url.scheme,
            "redirect_count": len(response.history),
        },
        "summary": {
            "findings": len(findings),
            "by_severity": {
                severity: sum(
                    finding["severity"] == severity
                    for finding in findings
                )
                for severity in ("HIGH", "MEDIUM", "LOW", "INFO")
            },
        },
        "findings": findings,
        "limitations": [
            "Checks response headers only.",
            "Missing headers are observations, not proof of exploitation.",
            "Severity is a rule-based triage label, not a CVSS score.",
            "No vulnerability exploitation is performed.",
        ],
    }

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

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        console.print(f"[green]Laporan tersimpan:[/green] {output}")


if __name__ == "__main__":
    app()
