"""Report exporters: render the report document as JSON, SARIF, or HTML.

Every exporter is a pure function of the report dict produced by
``sentrix.cli.build_report``. None of them reads the clock, the network, or
the filesystem, so the same report always renders to the same output and a
saved JSON report could be converted later without rescanning.

Design notes:

* SARIF and HTML are the formats most likely to be attached to tickets or
  uploaded to CI, so URLs in them are passed through
  ``sentrix.history.sanitize_url`` (no userinfo, query string, or fragment).
  The JSON report is left exactly as before.
* The HTML report is a single file with inline CSS only: no scripts, no
  external resources. Every dynamic value is HTML-escaped, and a restrictive
  Content-Security-Policy ``<meta>`` is included as a second line of defence.
* SARIF ``level`` follows the triage label (HIGH -> error, MEDIUM ->
  warning, LOW/INFO -> note). The original label is kept in each result's
  ``properties``. ``security-severity`` is deliberately not set, because
  SENTRIX severities are not CVSS scores.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import StrEnum
from html import escape

from sentrix.history import sanitize_url
from sentrix.models import SEVERITY_ORDER, Severity, compute_fingerprint


class ReportFormat(StrEnum):
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"


# --- JSON ------------------------------------------------------------------


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


# --- SARIF -----------------------------------------------------------------

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_FINGERPRINT_KEY = "sentrix/v1"

_SARIF_LEVELS = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _sarif_time(iso_timestamp: str) -> str | None:
    """Normalize an ISO timestamp to the ``...Z`` form SARIF expects."""
    try:
        parsed = datetime.fromisoformat(iso_timestamp)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_sarif(report: dict) -> dict:
    """Return a SARIF 2.1.0 log (as a dict) for one report."""
    tool = report["tool"]
    final_url = sanitize_url(report["target"]["final_url"])

    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    results: list[dict] = []

    for finding in report["findings"]:
        level = _SARIF_LEVELS[Severity(finding["severity"])]
        rule_id = finding["id"]

        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": finding["title"]},
                    "help": {"text": finding["recommendation"]},
                    "defaultConfiguration": {"level": level},
                }
            )

        evidence = finding["evidence"]
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": level,
                "message": {"text": finding["title"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": final_url}
                        }
                    }
                ],
                "partialFingerprints": {
                    SARIF_FINGERPRINT_KEY: compute_fingerprint(
                        rule_id, evidence["type"], evidence["header"]
                    )
                },
                "properties": {
                    "severity": finding["severity"],
                    "confidence": finding["confidence"],
                    "status": finding["status"],
                    "evidence": dict(evidence),
                },
            }
        )

    invocation: dict = {"executionSuccessful": True}
    end_time = _sarif_time(report["timestamp"])
    if end_time is not None:
        invocation["endTimeUtc"] = end_time

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool["name"],
                        "version": tool["version"],
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "results": results,
                "properties": {
                    "requestedUrl": sanitize_url(
                        report["target"]["requested_url"]
                    ),
                    "finalUrl": final_url,
                    "httpStatusCode": report["http"]["status_code"],
                    "redirectCount": report["http"]["redirect_count"],
                    "limitations": list(report["limitations"]),
                },
            }
        ],
    }


def render_sarif(report: dict) -> str:
    return json.dumps(build_sarif(report), indent=2, ensure_ascii=False) + "\n"


# --- HTML ------------------------------------------------------------------

_HTML_CSS = """\
:root {
  --bg: #f6f7f9; --fg: #151a22; --muted: #55606f; --card: #ffffff;
  --line: #d6dbe2; --accent: #0b5cad;
  --high: #a4161a; --medium: #8a4b00; --low: #14597a; --info: #4b5563;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1217; --fg: #e5e8ed; --muted: #9ba6b5; --card: #161b22;
    --line: #2a323c; --accent: #6cb0f5;
    --high: #ff8d92; --medium: #ffc47d; --low: #7fc6ea; --info: #b6bdc9;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 64rem; margin: 0 auto; padding: 2rem 1rem 3rem; }
h1 { margin: 0 0 .25rem; font-size: 1.6rem; letter-spacing: .02em; }
h1 span { color: var(--muted); font-weight: 400; font-size: 1.1rem; }
h2 { margin: 2rem 0 .75rem; font-size: 1.15rem; }
.meta { margin: 0; color: var(--muted); font-size: .9rem; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9em; }
section { background: var(--card); border: 1px solid var(--line); border-radius: .5rem; padding: .25rem 1.25rem 1.25rem; margin-top: 1.25rem; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .4rem 1.25rem; margin: 0; }
dt { color: var(--muted); }
dd { margin: 0; overflow-wrap: anywhere; }
ul { margin: 0; padding-left: 1.25rem; }
ul.summary { display: flex; flex-wrap: wrap; gap: .75rem 1.5rem; list-style: none; padding: 0; }
.badge { display: inline-block; padding: 0 .5rem; border: 1px solid currentColor; border-radius: 999px; font-size: .78rem; font-weight: 600; letter-spacing: .03em; }
.sev-high { color: var(--high); }
.sev-medium { color: var(--medium); }
.sev-low { color: var(--low); }
.sev-info, .sev-unknown { color: var(--info); }
.scroll { overflow-x: auto; }
section > h2:first-child { margin-top: 1rem; }
table { width: 100%; min-width: 56rem; border-collapse: collapse; font-size: .92rem; }
td:first-child code { white-space: nowrap; }
th, td { text-align: left; vertical-align: top; padding: .55rem .6rem; border-bottom: 1px solid var(--line); }
th { color: var(--muted); font-weight: 600; white-space: nowrap; }
.empty { margin: .75rem 0 0; }
footer { margin-top: 2rem; color: var(--muted); font-size: .85rem; }
@media (max-width: 30rem) {
  dl { grid-template-columns: 1fr; gap: 0; }
  dd { margin-bottom: .6rem; }
}
@media print {
  body { background: #fff; color: #000; }
  section { break-inside: avoid; border-color: #999; }
}
"""


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _badge(severity: str) -> str:
    # The class name comes from an allowlist, never straight from the data.
    css = f"sev-{severity.lower()}" if severity in SEVERITY_ORDER else "sev-unknown"
    return f'<span class="badge {css}">{_e(severity)}</span>'


def _summary_items(summary: dict) -> str:
    by_severity = summary["by_severity"]
    items = [
        f"<li>{_badge(severity)} <strong>{_e(by_severity.get(severity, 0))}</strong></li>"
        for severity in SEVERITY_ORDER
    ]
    items.append(f"<li>Total <strong>{_e(summary['findings'])}</strong></li>")
    return "\n".join(items)


def _findings_section(findings: list[dict]) -> str:
    if not findings:
        return (
            '<p class="empty">Tidak ada temuan dari aturan yang dijalankan. '
            "Ini bukan bukti bahwa target aman: SENTRIX hanya memeriksa "
            "header respons tertentu.</p>"
        )

    rows = "\n".join(
        "<tr>"
        f"<td><code>{_e(item['id'])}</code></td>"
        f"<td>{_badge(item['severity'])}</td>"
        f"<td>{_e(item['confidence'])}</td>"
        f"<td>{_e(item['title'])}</td>"
        f"<td><code>{_e(item['evidence']['header'])}</code></td>"
        f"<td>{_e(item['recommendation'])}</td>"
        "</tr>"
        for item in findings
    )
    return (
        '<div class="scroll" role="region" aria-label="Tabel temuan" tabindex="0">\n'
        "<table>\n<thead><tr>"
        '<th scope="col">Rule</th>'
        '<th scope="col">Severity</th>'
        '<th scope="col">Confidence</th>'
        '<th scope="col">Temuan</th>'
        '<th scope="col">Header</th>'
        '<th scope="col">Rekomendasi</th>'
        "</tr></thead>\n"
        f"<tbody>\n{rows}\n</tbody>\n</table>\n</div>"
    )


def render_html(report: dict) -> str:
    """Return a self-contained HTML page for one report."""
    tool = report["tool"]
    target = report["target"]
    http = report["http"]

    limitations = "\n".join(
        f'<li lang="en">{_e(text)}</li>' for text in report["limitations"]
    )

    return f"""\
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<title>{_e(tool['name'])} - Laporan HTTP Posture</title>
<style>
{_HTML_CSS}</style>
</head>
<body>
<main>
<header>
<h1>{_e(tool['name'])} <span>Laporan HTTP Posture</span></h1>
<p class="meta">Dibuat {_e(report['timestamp'])} &middot; {_e(tool['name'])} {_e(tool['version'])} &middot; skema laporan {_e(report['schema_version'])}</p>
</header>
<section aria-labelledby="h-target">
<h2 id="h-target">Target</h2>
<dl>
<dt>URL diminta</dt><dd class="mono">{_e(sanitize_url(target['requested_url']))}</dd>
<dt>URL akhir</dt><dd class="mono">{_e(sanitize_url(target['final_url']))}</dd>
<dt>Status HTTP</dt><dd>{_e(http['status_code'])}</dd>
<dt>Redirect</dt><dd>{_e(http['redirect_count'])}</dd>
</dl>
</section>
<section aria-labelledby="h-summary">
<h2 id="h-summary">Ringkasan</h2>
<ul class="summary">
{_summary_items(report['summary'])}
</ul>
</section>
<section aria-labelledby="h-findings">
<h2 id="h-findings">Temuan</h2>
{_findings_section(report['findings'])}
</section>
<section aria-labelledby="h-limits">
<h2 id="h-limits">Batasan</h2>
<ul>
{limitations}
</ul>
</section>
<footer>URL pada laporan ini ditampilkan tanpa userinfo, query string, dan fragment. Nilai header respons tidak pernah disertakan.</footer>
</main>
</body>
</html>
"""


# --- dispatch --------------------------------------------------------------


def render_report(report: dict, fmt: ReportFormat) -> str:
    match fmt:
        case ReportFormat.JSON:
            return render_json(report)
        case ReportFormat.SARIF:
            return render_sarif(report)
        case ReportFormat.HTML:
            return render_html(report)
        case _:
            raise ValueError(f"Format laporan tidak dikenal: {fmt!r}")
