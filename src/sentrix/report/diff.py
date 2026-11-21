"""Diff / baseline utility for comparing two JSON report documents."""

from __future__ import annotations

from dataclasses import dataclass

from sentrix.models import Severity


@dataclass(frozen=True, slots=True)
class DiffFinding:
    rule_id: str
    title: str
    severity: str
    header: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class DiffResult:
    target_a: str
    target_b: str
    timestamp_a: str
    timestamp_b: str
    appeared: tuple[DiffFinding, ...]
    resolved: tuple[DiffFinding, ...]
    severity_changed: tuple[tuple[DiffFinding, DiffFinding], ...]
    unchanged: tuple[DiffFinding, ...]

    def to_dict(self) -> dict:
        return {
            "target_a": self.target_a,
            "target_b": self.target_b,
            "timestamp_a": self.timestamp_a,
            "timestamp_b": self.timestamp_b,
            "appeared": [
                {"id": f.rule_id, "title": f.title, "severity": f.severity, "header": f.header}
                for f in self.appeared
            ],
            "resolved": [
                {"id": f.rule_id, "title": f.title, "severity": f.severity, "header": f.header}
                for f in self.resolved
            ],
            "severity_changed": [
                {
                    "id": b.rule_id,
                    "title": b.title,
                    "before_severity": a.severity,
                    "after_severity": b.severity,
                }
                for a, b in self.severity_changed
            ],
            "unchanged_count": len(self.unchanged),
        }


def diff_reports(report_a: dict, report_b: dict) -> DiffResult:
    """Compare two report dictionaries (older report_a -> newer report_b)."""
    target_a = report_a.get("target", {}).get("requested_url", "")
    target_b = report_b.get("target", {}).get("requested_url", "")
    time_a = report_a.get("timestamp", "")
    time_b = report_b.get("timestamp", "")

    def _make_findings_map(report: dict) -> dict[str, DiffFinding]:
        res = {}
        for f in report.get("findings", []):
            rule_id = f.get("id", "")
            title = f.get("title", "")
            sev = f.get("severity", "INFO")
            header = f.get("evidence", {}).get("header", "")
            fp = f.get("evidence", {}).get("fingerprint") or f"{rule_id}:{header}"
            res[fp] = DiffFinding(
                rule_id=rule_id,
                title=title,
                severity=sev,
                header=header,
                fingerprint=fp,
            )
        return res

    map_a = _make_findings_map(report_a)
    map_b = _make_findings_map(report_b)

    appeared: list[DiffFinding] = []
    for fp, finding in map_b.items():
        if fp not in map_a:
            appeared.append(finding)

    resolved: list[DiffFinding] = []
    for fp, finding in map_a.items():
        if fp not in map_b:
            resolved.append(finding)

    severity_changed: list[tuple[DiffFinding, DiffFinding]] = []
    unchanged: list[DiffFinding] = []

    for fp, finding_b in map_b.items():
        if fp in map_a:
            finding_a = map_a[fp]
            if finding_a.severity != finding_b.severity:
                severity_changed.append((finding_a, finding_b))
            else:
                unchanged.append(finding_b)

    return DiffResult(
        target_a=target_a,
        target_b=target_b,
        timestamp_a=time_a,
        timestamp_b=time_b,
        appeared=tuple(appeared),
        resolved=tuple(resolved),
        severity_changed=tuple(severity_changed),
        unchanged=tuple(unchanged),
    )
