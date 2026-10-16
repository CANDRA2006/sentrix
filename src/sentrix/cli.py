
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import typer
from rich.console import Console
from rich.table import Table

from sentrix.models import SEVERITY_ORDER
from sentrix.normalize import normalize_findings
from sentrix.rules import evaluate_headers

app = typer.Typer(
    name="sentrix",
    help="Local-first security posture analysis CLI.",
    no_args_is_help=True,
)
console = Console()

TOOL_NAME = "SENTRIX"
TOOL_VERSION = "0.1.0"
REPORT_SCHEMA_VERSION = "1.0"
REQUEST_TIMEOUT_SECONDS = 8.0
MAX_REDIRECTS = 5
LIMITATIONS = [
    "Checks response headers only.",
    "Missing headers are observations, not proof of exploitation.",
    "Severity is a rule-based triage label, not a CVSS score.",
    "No vulnerability exploitation is performed.",
]


@app.callback()
def main() -> None:
    """Local-first security posture analysis CLI."""


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
    """Generate normalized findings as report-ready dicts."""
    findings = normalize_findings(evaluate_headers(headers, is_https))
    return [finding.to_dict() for finding in findings]


def build_report(
    requested_url: str,
    response: httpx.Response,
    findings: list[dict],
) -> dict:
    """Build the JSON-serializable report without leaking header values."""
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
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
        "limitations": list(LIMITATIONS),
    }


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
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"},
        ) as client:
            response = client.get(url)

    except httpx.HTTPError as exc:
        console.print(f"[bold red]Request gagal:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    findings = analyze_headers(
        response.headers,
        is_https=response.url.scheme == "https",
    )

    report = build_report(url, response, findings)

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
