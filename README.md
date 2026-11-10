# SENTRIX

**Security reconnaissance and exposure intelligence CLI.**
*Understand the surface. Verify the risk. Secure the system.*

**Language:** English | [Bahasa Indonesia](README.id.md)

`v0.1.0` | Python 3.13+ | MIT License | local-first, no API key

## Overview

SENTRIX is a command-line tool that inspects the HTTP security headers of a
URL and turns what it finds into structured, evidence-based findings. The
analysis is deterministic and runs on your machine: there is no AI service,
cloud platform, or API key involved. It is meant for repeatable checks during
development and for authorized security assessments.

A missing header is an observation, not proof of an exploitable
vulnerability. Whether a header matters depends on the application, its
deployment, and its threat model, and SENTRIX reports it that way.

## Features

- **HTTP security header checks.** Five rules cover Content-Security-Policy,
  Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, and
  Permissions-Policy. A header that is absent or empty is a finding.
- **Header value checks.** Six more rules judge headers that are present: a
  weak HSTS `max-age`, a CSP that allows inline/eval or any-origin scripts, a
  `nosniff` typo, a Referrer-Policy that leaks full URLs, and version or
  technology disclosure in `Server` and `X-Powered-By`. Header values are
  inspected but never stored in findings, reports, or history.
- **Evidence-based findings.** Each finding carries a rule id, the evidence
  behind it, a confidence label, a remediation suggestion, and a stable
  fingerprint. Findings are deduplicated and sorted deterministically.
- **Configurable rule policy.** Turn rules off, re-triage their severity, and
  fail a CI run above a threshold, all from a small TOML file.
- **Three report formats.** JSON, SARIF 2.1.0, and a self-contained HTML page,
  all rendered from the same report.
- **Scan history.** Save scans to a local SQLite database and compare any two
  of them.
- **Safe defaults.** URLs must be absolute `http`/`https`; requests have an
  8-second timeout and follow at most 5 redirects; response header values are
  never written to a report.

## Requirements

- Python 3.13 or newer, and pip
- Git (optional, recommended for development)
- Internet access for remote targets

SENTRIX is developed on Windows 11 and on Kali Linux under WSL.

## Installation

Windows PowerShell:

```powershell
git clone https://github.com/CANDRA2006/sentrix.git
cd sentrix
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Kali Linux / WSL:

```bash
git clone https://github.com/CANDRA2006/sentrix.git
cd sentrix
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Usage

```bash
sentrix --help
sentrix --version
sentrix check https://example.com
sentrix check https://example.com --timeout 15 --max-redirects 3
sentrix check https://example.com --output reports/example.json
sentrix check https://example.com -o reports/example.sarif --format sarif
sentrix check https://example.com -o reports/example.html --format html
sentrix check https://example.com --save
sentrix check https://example.com --config sentrix.toml --fail-on MEDIUM
sentrix rules --config sentrix.toml
sentrix history
sentrix compare 1 2
```

`check` is a required subcommand. Exit codes:

| Code | Meaning |
|---|---|
| `0` | The scan ran. Findings do not change this unless `--fail-on` is used. |
| `1` | The scan could not complete: network failure, timeout, redirect loop, or a report or history file that could not be written. |
| `2` | Invalid input: bad URL, unknown option value, or an invalid policy file. |
| `3` | The `--fail-on` gate failed: a finding is at or above the threshold. |

## Sample output

This is real output from a run against a local test server whose only
security header is `X-Content-Type-Options`. Findings for your own targets
depend on their response headers.

```text
SENTRIX :: HTTP POSTURE CHECK
Target: http://127.0.0.1:8793/

HTTP status: 200 | Redirects: 0
                      HTTP Security Posture                      
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Rule ID  ┃ Severity ┃ Finding                                 ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HTTP-001 │ MEDIUM   │ Content Security Policy tidak ditemukan │
│ HTTP-004 │ LOW      │ Referrer-Policy tidak ditemukan         │
│ HTTP-005 │ INFO     │ Permissions-Policy tidak ditemukan      │
└──────────┴──────────┴─────────────────────────────────────────┘

Findings: 3
```

Rule titles and recommendations, and many terminal messages, are currently
written in Indonesian; localization is not implemented yet. The structure of
the JSON report uses English keys.

## Security rules

| Rule ID | Header | Default severity | Notes |
|---|---|---|---|
| `HTTP-001` | `Content-Security-Policy` | MEDIUM | Controls which content sources a page may use. |
| `HTTP-002` | `Strict-Transport-Security` | MEDIUM | Only evaluated for HTTPS responses. |
| `HTTP-003` | `X-Content-Type-Options` | LOW | Helps prevent MIME-type sniffing. |
| `HTTP-004` | `Referrer-Policy` | LOW | Controls the referrer information browsers send. |
| `HTTP-005` | `Permissions-Policy` | INFO | Controls selected browser capabilities. |
| `HTTP-101` | `Strict-Transport-Security` | LOW | Present, but `max-age` is missing, zero, or under 180 days. Only evaluated for HTTPS responses. |
| `HTTP-102` | `Content-Security-Policy` | MEDIUM | The effective script policy (`script-src`, else `default-src`) allows `'unsafe-inline'` without a nonce or hash, `'unsafe-eval'`, `*`, `http:`, `https:`, or `data:`. A heuristic, so its confidence is MEDIUM. |
| `HTTP-103` | `X-Content-Type-Options` | LOW | Present, but the value is not `nosniff`. |
| `HTTP-104` | `Referrer-Policy` | LOW | The effective (last) policy is `unsafe-url` or `no-referrer-when-downgrade`. |
| `HTTP-201` | `Server` | LOW | The value includes a version number. |
| `HTTP-202` | `X-Powered-By` | LOW | The header is present. |

Rules `HTTP-001` to `HTTP-005` report a header that is missing. Rules
`HTTP-101` and up report a header that is present but weak or revealing. They
use the evidence types `weak_header_value` and `information_disclosure`, so
they never share a fingerprint with a missing-header finding. Every rule can be
switched off or re-triaged in the policy file.

Severity labels are rule-based triage labels, not CVSS scores. Run
`sentrix rules` to see the same list, including what a policy file changes.

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
- The rule policy a scan ran under (see below) is part of every report: the
  JSON `policy` block (report schema `1.1`), a "Kebijakan" section in the
  HTML page, and `policy` in the SARIF run properties.

## Rule policy

A policy file changes which built-in rules run, how severe they are, and when
`check` fails. It is a small TOML file, and it is only read when you ask for
it:

```toml
# sentrix.toml
[policy]
fail_on = "MEDIUM"   # exit code 3 if any finding is MEDIUM or higher

[rules.HTTP-001]
severity = "HIGH"    # re-triage a rule: HIGH, MEDIUM, LOW, or INFO

[rules.HTTP-005]
enabled = false      # do not evaluate this rule at all
```

```bash
sentrix rules                                  # list rule ids, headers, severities
sentrix rules --config sentrix.toml            # same, with the policy applied
sentrix check https://example.com --config sentrix.toml
sentrix check https://example.com --fail-on HIGH   # gate without a file
```

| Setting | Effect |
|---|---|
| `[policy] fail_on` | `check` exits with code `3` if any finding is at or above this severity. `--fail-on` on the command line overrides it. Without either, findings never change the exit code. |
| `[rules.ID] enabled = false` | The rule is not evaluated. |
| `[rules.ID] severity` | Replaces the rule's severity. The finding keeps its fingerprint, so `compare` shows a severity change, not a new finding. |

How it behaves:

- **Explicit only.** Pass `--config PATH` (or `-c`), or set `SENTRIX_CONFIG`;
  the flag wins. A `sentrix.toml` in the current directory is never picked up
  on its own, so a stray file cannot change a result.
- **Strict.** Unknown keys, unknown rule ids, wrong types, and invalid
  severities are errors (exit code `2`, before any request), because a typo
  that is silently ignored looks exactly like a policy that works.
  `sentrix rules --config FILE` checks a file without scanning anything. Use
  `sentrix rules` to see the valid rule ids.
- **Suppression is never silent.** `check` prints the active policy, and
  disabled rules and severity overrides are recorded in the report and in the
  history. Treat a disabled rule as "not evaluated", not as "passed". If a
  policy disables every rule, `check` warns that nothing was checked and the
  gate message says so instead of reporting a plain pass.
- **The gate runs last.** When `--fail-on` fails, the report and the history
  entry are still written first, so a failed CI run keeps its evidence.
- **Only the file name is recorded**, not its directory.
- **Limits.** UTF-8 only (a BOM is fine), at most 64 KiB, and no absurdly
  deep nesting (reported as an invalid file). Policies cannot add rules or run
  code. In Windows PowerShell 5, `>` writes UTF-16, which is
  rejected; create the file in an editor that saves UTF-8, or write it with
  `Set-Content -Encoding utf8`.

The same run as above, with the policy from the example (`HTTP-001` raised to
HIGH, `HTTP-005` switched off, gate at MEDIUM):

```text
SENTRIX :: HTTP POSTURE CHECK
Target: http://127.0.0.1:8793/
Kebijakan: sentrix.toml | nonaktif: HTTP-005 | severity: HTTP-001=HIGH | gagal 
jika >= MEDIUM

HTTP status: 200 | Redirects: 0
                      HTTP Security Posture                      
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Rule ID  ┃ Severity ┃ Finding                                 ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HTTP-001 │ HIGH     │ Content Security Policy tidak ditemukan │
│ HTTP-004 │ LOW      │ Referrer-Policy tidak ditemukan         │
└──────────┴──────────┴─────────────────────────────────────────┘

Findings: 2
Gate gagal: ada temuan dengan severity MEDIUM atau lebih tinggi.
```

The process exits with code `3`.

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
different targets prints a warning, and so does comparing scans that ran
under different rule policies, because a rule that was switched off looks
"resolved" without the target having changed. `--fail-on` is not part of that
comparison, since it cannot change what a scan finds. `compare` is
directional: swapping the ids swaps "new" and "resolved".

```text
SENTRIX :: COMPARE #1 -> #2
Lama: http://127.0.0.1:8793/ (2026-10-31T12:11:01.033209+00:00)
Baru: http://127.0.0.1:8793/ (2026-10-31T12:11:01.209701+00:00)

Peringatan: kedua scan memakai kebijakan aturan yang berbeda (lama: bawaan; 
baru: nonaktif: HTTP-005; severity: HTTP-001=HIGH). Temuan BARU, TERATASI, atau 
BERUBAH bisa jadi hanya akibat aturan yang dinonaktifkan atau diubah 
severity-nya, bukan karena targetnya berubah.

TERATASI  HTTP-005 [INFO] Permissions-Policy tidak ditemukan
BERUBAH   HTTP-001 MEDIUM -> HIGH Content Security Policy tidak ditemukan

Baru: 0 | Teratasi: 1 | Berubah severity: 1 | Tetap: 1
```

The database defaults to `~/.sentrix/history.db`. Override it with
`--db PATH` or the `SENTRIX_DB` environment variable. A new database file is
created owner-only (`0600`) inside a `0700` directory on POSIX systems.

What is stored: target and final URL, timestamp, HTTP status, tool version,
the rule policy the scan ran under (disabled rules and severity overrides,
not the file path), and the findings (rule id, title, severity, confidence,
header name). What is **not** stored: response header values, and URL
userinfo, query string, and fragment. URL paths are stored as-is, so avoid
scanning URLs whose path itself carries a secret.

The history schema is versioned. A database from an older SENTRIX is upgraded
in place the first time it is opened (schema 1 to 2 adds the policy column;
existing scans keep their data and count as "default rules"), inside a single
transaction, so a failed upgrade leaves the file as it was. That first open
needs write access even for read-only commands such as `history` and
`compare`, so an old database on a read-only mount must be made writable once.
After the upgrade, older SENTRIX versions refuse the file rather than modify
it, and so does any database written by a newer schema. A SQLite file that is
not a SENTRIX history is never adopted: its tables are checked before an
upgrade, and a file that does not match is left untouched. Back up
`~/.sentrix/history.db` first if you want to keep the option of going back to
an older version.

## How it works

```text
URL + options
     |
     v
Input validation (URL, --format, policy file)
     |
     v
HTTP request (httpx: timeout, redirect limit)
     |
     v
Header rules (policy applied) --> Normalization (dedupe, order, fingerprint)
     |
     v
One report document
     |
     +--> Terminal table
     +--> JSON / SARIF / HTML   (--output, --format)
     +--> SQLite history        (--save)  --> history, compare
```

| Module | Role |
|---|---|
| `cli.py` | Typer commands (`check`, `rules`, `history`, `compare`), report assembly, exit codes |
| `rules.py` | The built-in header rules |
| `policy.py` | TOML policy: loading, validation, applying it to the rules, the gate |
| `models.py` | The typed finding model and its fingerprint |
| `normalize.py` | Deduplication and deterministic ordering |
| `reporting.py` | JSON, SARIF, and HTML exporters |
| `history.py` | SQLite history and scan comparison |

## Testing

```bash
python -m pytest -v
```

## Responsible use

SENTRIX is intended for authorized security assessments, development
environments, and educational security research.

- Only assess systems you own or are explicitly authorized to test, and
  respect the scope and policies that apply to them.
- A missing header is an observation, not proof of an exploitable
  vulnerability. Verify before treating a result as a confirmed issue.
- Severity labels are rule-based triage labels, not CVSS scores.
- SENTRIX checks response headers only. It does not exploit anything and is
  not a comprehensive security assessment.

## Known security limitations

These are not resolved yet:

- Redirects are followed without checking the destination. A public URL can
  redirect to `localhost`, a private network address, or a cloud metadata
  address.
- Hostnames are not resolved or checked against private/reserved address
  ranges, and URLs that already point at such addresses are accepted.
- Only the status line and headers of the final response are read; its body is
  never downloaded. httpx does read the body of each intermediate redirect
  response before following it, and those are not size-limited.

## Planned

Not available in the current release:

- Network safety controls: target scope and private-address checks (see the
  limitations above)
- Importing results from other security tools
- Optional AI-assisted explanations of findings (the core analysis will stay
  deterministic and work without it)
- A CI workflow for this repository's own test suite

## Contributing

Contributions, bug reports, and suggestions are welcome.

1. Fork the repository and create a feature branch.
2. Add tests for new behavior.
3. Run `python -m pytest -v`.
4. Open a pull request that describes the change and its security
   implications.

## License

Released under the [MIT License](LICENSE).
