
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

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
from sentrix.models import SEVERITY_ORDER, Finding
from sentrix.normalize import normalize_findings
from sentrix.reporting import ReportFormat, render_report
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


def evaluate_findings(
    headers: httpx.Headers, is_https: bool
) -> list[Finding]:
    """Run the header rules and return normalized Finding objects."""
    return normalize_findings(evaluate_headers(headers, is_https))


def analyze_headers(headers: httpx.Headers, is_https: bool) -> list[dict]:
    """Generate normalized findings as report-ready dicts."""
    return [
        finding.to_dict() for finding in evaluate_findings(headers, is_https)
    ]


DbOption = typer.Option(
    None,
    "--db",
    envvar=DB_ENV_VAR,
    help="Path database riwayat SQLite (default: ~/.sentrix/history.db).",
)


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
        help="Simpan laporan ke file (format default: JSON).",
    ),
    report_format: ReportFormat | None = typer.Option(
        None,
        "--format",
        "-f",
        case_sensitive=False,
        help="Format file laporan: json, sarif, atau html. Perlu --output.",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Simpan hasil scan ke riwayat lokal (SQLite).",
    ),
    db: Path | None = DbOption,
) -> None:
    """Inspect basic HTTP security headers for one URL."""
    validate_url(url)

    # Fail before any network traffic rather than silently ignoring --format.
    if report_format is not None and output is None:
        raise typer.BadParameter(
            "--format hanya berlaku bersama --output.",
            param_hint="--format",
        )

    console.print("\n[bold cyan]SENTRIX[/bold cyan] :: HTTP POSTURE CHECK")
    console.print(f"[dim]Target: {escape(url)}[/dim]\n")

    try:
        with httpx.Client(
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            headers={"User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}"},
        ) as client:
            response = client.get(url)

    except httpx.HTTPError as exc:
        console.print(
            f"[bold red]Request gagal:[/bold red] {escape(str(exc))}"
        )
        raise typer.Exit(code=1) from exc

    finding_objects = evaluate_findings(
        response.headers,
        is_https=response.url.scheme == "https",
    )
    findings = [finding.to_dict() for finding in finding_objects]

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
        fmt = report_format or ReportFormat.JSON
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(render_report(report, fmt), encoding="utf-8")
        except OSError as exc:
            console.print(
                "[bold red]Laporan gagal disimpan:[/bold red] "
                f"{escape(str(exc))}"
            )
            raise typer.Exit(code=1) from exc
        console.print(
            f"[green]Laporan tersimpan:[/green] {escape(str(output))} "
            f"[dim]({fmt.value})[/dim]"
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
                    findings=finding_objects,
                )
        except HistoryError as exc:
            console.print(
                f"[bold red]Riwayat gagal disimpan:[/bold red] {escape(str(exc))}"
            )
            raise typer.Exit(code=1) from exc

        console.print(f"[green]Scan tersimpan di riwayat:[/green] #{scan_id}")


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
        console.print(
            f"[bold red]Riwayat gagal dibaca:[/bold red] {escape(str(exc))}"
        )
        raise typer.Exit(code=1) from exc

    if not scans:
        console.print(
            "Belum ada scan tersimpan. Gunakan: sentrix check URL --save"
        )
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
    """``2026-10-22T03:49:47.263+00:00`` -> ``2026-10-22 03:49:47``."""
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
        console.print(
            f"[dim]{label}: {escape(scan.target)} "
            f"({escape(scan.scanned_at)})[/dim]"
        )
    console.print()

    if not diff.same_target:
        console.print(
            "[yellow]Peringatan:[/yellow] kedua scan memiliki target yang "
            "berbeda; hasil perbandingan mungkin tidak bermakna.\n"
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
        console.print(
            f"[bold red]Perbandingan gagal:[/bold red] {escape(str(exc))}"
        )
        raise typer.Exit(code=1) from exc

    _print_diff(diff)


if __name__ == "__main__":
    app()
