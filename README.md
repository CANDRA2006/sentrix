A Python-based CLI for inspecting HTTP security headers, identifying potential configuration issues, and generating structured security reports.

## Installation

Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Kali Linux / WSL:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Usage

```bash
sentrix --help
sentrix check https://example.com
sentrix check https://example.com --output reports/example.json
sentrix check https://example.com -o reports/example.sarif --format sarif
sentrix check https://example.com -o reports/example.html --format html
sentrix check https://example.com --save
sentrix history
sentrix compare 1 2
```

`check` is a required subcommand. Invalid input exits with code 2; network
failures, timeouts, and redirect loops exit with code 1.

## Report formats

`--output` writes the report to a file. `--format` picks the format
(`json`, `sarif`, or `html`; case-insensitive) and defaults to `json`, which
is the same report as before. `--format` without `--output` is rejected
before any request is made.

| Format | Use it for |
|---|---|
| `json` | The full machine-readable report. |
| `sarif` | SARIF 2.1.0, for SARIF viewers and tools that aggregate findings. |
| `html` | A single self-contained page to read, attach to a ticket, or print. |

All three are rendered from the same report, so they always agree.

- **SARIF** maps severity to `level` (`HIGH` is `error`, `MEDIUM` is
  `warning`, `LOW` and `INFO` are `note`); the original label stays in each
  result's `properties`. No `security-severity` score is set, because SENTRIX
  severities are not CVSS scores. Each result carries the same fingerprint
  that `compare` uses. A result's location is the scanned URL, not a file in a
  repository, so tools that map alerts onto source files (GitHub code
  scanning, for example) may not be able to place them.
- **HTML** has inline CSS only: no scripts, no external resources, and a
  restrictive Content-Security-Policy. Every value is HTML-escaped. It follows
  the system light/dark setting and prints cleanly.
- **URLs** in the SARIF and HTML reports have userinfo, query string, and
  fragment removed. The JSON report keeps the URL exactly as you typed it, as
  before, so avoid sharing it if the query string carries a token.
- None of the formats contain response header values.

## Scan history

`check --save` stores the result in a local SQLite database so scans can be
listed and compared over time. Nothing is saved unless `--save` is given.

```bash
sentrix check https://example.com --save   # prints "Scan tersimpan di riwayat: #1"
sentrix history                            # newest first; --limit/-n N (1-500)
sentrix compare 1 2                        # old id, then new id
```

`compare OLD NEW` matches findings by fingerprint (rule id + evidence, so
re-wording a title does not make a finding look new) and reports findings
that are new, resolved, unchanged, or changed severity. Comparing scans of
different targets prints a warning. `compare` is directional: swapping the
ids swaps "new" and "resolved".

The database defaults to `~/.sentrix/history.db`. Override it with
`--db PATH` or the `SENTRIX_DB` environment variable. A new database file is
created owner-only (`0600`) inside a `0700` directory on POSIX systems.

What is stored: target and final URL, timestamp, HTTP status, tool version,
and the findings (rule id, title, severity, confidence, header name). What is
**not** stored: response header values, and URL userinfo, query string, and
fragment. URL paths are stored as-is, so avoid scanning URLs whose path
itself carries a secret.

A database written by a newer SENTRIX schema is refused rather than
modified, and a SQLite file that is not a SENTRIX history is never adopted.

## Testing

```bash
python -m pytest -v
```

## Responsible use

Only assess systems you own or are explicitly authorized to test. A missing
header is an observation, not proof of an exploitable vulnerability, and
severity labels are rule-based triage labels, not CVSS scores.

## Known security limitations

These are not resolved yet:

- Redirects are followed without checking the destination. A public URL can
  redirect to `localhost`, a private network address, or a cloud metadata
  address.
- Hostnames are not resolved or checked against private/reserved address
  ranges, and URLs that already point at such addresses are accepted.
- The response body is fully read into memory; there is no response-size limit.
