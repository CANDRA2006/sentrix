"""Markdown report exporter: produces GitHub-Flavored Markdown reports."""

from __future__ import annotations

from sentrix.history import sanitize_url
from sentrix.models import SEVERITY_ORDER


def render_markdown(report: dict) -> str:
    """Render a report document as GitHub-Flavored Markdown."""
    tool = report["tool"]
    target = report["target"]
    http = report["http"]
    summary = report["summary"]
    findings = report.get("findings", [])
    limitations = report.get("limitations", [])

    lines: list[str] = []

    # Title & Header
    lines.append(f"# {tool['name']} - HTTP Security Posture Report\n")
    lines.append(f"> Generated at: `{report.get('timestamp', '')}` | Tool version: `{tool['name']} {tool['version']}` | Schema: `{report.get('schema_version', '')}`\n")

    # Score if available
    score_data = report.get("score")
    if score_data:
        grade = score_data.get("grade", "N/A")
        score = score_data.get("score", "N/A")
        lines.append(f"### Security Grade: **{grade}** ({score}/100)\n")

    # Target info
    lines.append("## Target Summary\n")
    lines.append(f"- **Requested URL:** `{sanitize_url(target['requested_url'])}`")
    lines.append(f"- **Final URL:** `{sanitize_url(target['final_url'])}`")
    lines.append(f"- **HTTP Status Code:** `{http['status_code']}`")
    lines.append(f"- **Redirect Count:** `{http['redirect_count']}`\n")

    # Policy section if present
    policy = report.get("policy")
    if policy:
        lines.append("### Policy")
        source = policy.get("source") or "Default"
        lines.append(f"- **Source:** `{source}`")
        if policy.get("disabled_rules"):
            lines.append(f"- **Disabled Rules:** {', '.join(f'`{r}`' for r in policy['disabled_rules'])}")
        if policy.get("severity_overrides"):
            lines.append(f"- **Overrides:** {', '.join(f'`{k}={v}`' for k, v in policy['severity_overrides'].items())}")
        if policy.get("fail_on"):
            lines.append(f"- **Gate (Fail on):** `>= {policy['fail_on']}`")
        lines.append("")

    # Summary table
    lines.append("## Findings Summary\n")
    lines.append("| Severity | Count |")
    lines.append("| :--- | :---: |")
    by_sev = summary.get("by_severity", {})
    for sev in SEVERITY_ORDER:
        lines.append(f"| **{sev}** | {by_sev.get(sev, 0)} |")
    lines.append(f"| **Total** | **{summary.get('findings', 0)}** |\n")

    # Findings details table
    lines.append("## Detailed Findings\n")
    if not findings:
        lines.append("*No findings observed for evaluated rules.*\n")
    else:
        lines.append("| Rule ID | Severity | Confidence | Finding | Header | Recommendation |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in findings:
            rule_id = f.get("id", "")
            sev = f.get("severity", "")
            conf = f.get("confidence", "")
            title = f.get("title", "").replace("|", "\\|")
            header = f.get("evidence", {}).get("header", "").replace("|", "\\|")
            rec = f.get("recommendation", "").replace("|", "\\|")
            lines.append(f"| `{rule_id}` | {sev} | {conf} | {title} | `{header}` | {rec} |")
        lines.append("")

    # Extended: TLS info
    tls = report.get("tls")
    if tls:
        lines.append("## TLS Inspection\n")
        lines.append(f"- **Protocol:** `{tls.get('protocol_version', 'N/A')}`")
        lines.append(f"- **Cipher:** `{tls.get('cipher_name', 'N/A')}` ({tls.get('cipher_bits', 'N/A')}-bit)")
        lines.append(f"- **Expiry in Days:** `{tls.get('days_until_expiry', 'N/A')}`")
        lines.append(f"- **SAN Mismatch:** `{tls.get('san_mismatch', False)}`")
        lines.append(f"- **Expired:** `{tls.get('expired', False)}`\n")

    # Extended: Technologies
    techs = report.get("technologies")
    if techs:
        lines.append("## Detected Technologies\n")
        lines.append("| Technology | Version | Source | Confidence |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for t in techs:
            lines.append(f"| **{t.get('name', '')}** | {t.get('version', '') or '-'} | {t.get('source', '')} | {t.get('confidence', '')} |")
        lines.append("")

    # Extended: Exposed files & discovery
    disc = report.get("discovery")
    if disc:
        lines.append("## Resource Discovery\n")
        sec_txt = disc.get("security_txt", {})
        lines.append(f"- **security.txt Found:** `{sec_txt.get('found', False)}`")
        robots = disc.get("robots_txt", {})
        lines.append(f"- **robots.txt Found:** `{robots.get('found', False)}`")
        if robots.get("sensitive_paths"):
            lines.append(f"  - Disallowed sensitive paths: {', '.join(f'`{p}`' for p in robots['sensitive_paths'])}")
        exposed_list = [f"`{e.get('path', '')}`" for e in exposed]
        if exposed_list:
            lines.append(f"- **Exposed Files:** {', '.join(exposed_list)}")
        lines.append("")

    # Limitations
    if limitations:
        lines.append("## Limitations\n")
        for limit in limitations:
            lines.append(f"- {limit}")
        lines.append("")

    lines.append("---\n*Report generated by SENTRIX.*")
    return "\n".join(lines) + "\n"
