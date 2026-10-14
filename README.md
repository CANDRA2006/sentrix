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
```

`check` is a required subcommand. Invalid input exits with code 2; network
failures, timeouts, and redirect loops exit with code 1.

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
