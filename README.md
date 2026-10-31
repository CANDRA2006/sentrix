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
