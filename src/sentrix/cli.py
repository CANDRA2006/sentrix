
from __future__ import annotations

from dataclasses import replace
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
from sentrix.models import SEVERITY_ORDER, Finding, Severity
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
from sentrix.reporting import ReportFormat, render_report
from sentrix.rules import RULES, Rule, evaluate_headers

app = typer.Typer(
    name="sentrix",
    help="Local-first security posture analysis CLI.",
    no_args_is_help=True,
)
console = Console()

TOOL_NAME = "SENTRIX"
TOOL_VERSION = "0.1.0"
# 1.1 adds the "policy" block (additive; every 1.0 key is unchanged).
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
    config: Path | None, fail_on: Severity | None
) -> Policy:
    """Load the policy file (if any); ``--fail-on`` overrides the file.

    An invalid file ends the command with exit code 2, like other invalid
    input, before anything touches the network.
    """
    policy = Policy()
    if config is not None:
        try:
            policy = load_policy(config)
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
) -> None:
    """Inspect basic HTTP security headers for one URL."""
    validate_url(url)

    # Fail before any network traffic rather than silently ignoring --format.
    if report_format is not None and output is None:
        raise typer.BadParameter(
            "--format hanya berlaku bersama --output.",
            param_hint="--format",
        )

    policy = load_effective_policy(config, fail_on)
    active_rules = apply_policy(RULES, policy)

    console.print("\n[bold cyan]SENTRIX[/bold cyan] :: HTTP POSTURE CHECK")
    console.print(f"[dim]Target: {escape(url)}[/dim]")
    if not policy.is_default:
        # Switched-off rules are a suppression, so they are always shown.
        console.print(f"[dim]Kebijakan: {escape(policy.summary())}[/dim]")
    if not active_rules:
        console.print(
            "[yellow]Peringatan:[/yellow] semua aturan dinonaktifkan, "
            "jadi tidak ada pemeriksaan yang dijalankan."
        )
    console.print()

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
        rules=active_rules,
    )
    findings = [finding.to_dict() for finding in finding_objects]

    report = build_report(url, response, findings, policy)

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
                    policy=policy.rule_policy_json(),
                )
        except HistoryError as exc:
            console.print(
                f"[bold red]Riwayat gagal disimpan:[/bold red] {escape(str(exc))}"
            )
            raise typer.Exit(code=1) from exc

        console.print(f"[green]Scan tersimpan di riwayat:[/green] #{scan_id}")

    # Last on purpose: the report and the history entry are written even
    # when the gate fails, so a failed CI run still leaves its evidence.
    if policy.fail_on is not None:
        threshold = policy.fail_on.value
        if gate_failed(finding_objects, policy.fail_on):
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


@app.command("rules")
def rules_command(config: Path | None = ConfigOption) -> None:
    """List the built-in rules and what the policy does to each of them.

    Works offline, so it also checks a policy file without scanning anything.
    """
    policy = load_effective_policy(config, None)
    if not policy.is_default:
        console.print(f"[dim]Kebijakan: {escape(policy.summary())}[/dim]")

    table = Table(title="Rules")
    table.add_column("Rule ID")
    table.add_column("Header")
    table.add_column("Severity")
    table.add_column("Status")

    for rule in RULES:
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
        console.print(
            f"[bold red]Perbandingan gagal:[/bold red] {escape(str(exc))}"
        )
        raise typer.Exit(code=1) from exc

    _print_diff(diff)


if __name__ == "__main__":
    app()
