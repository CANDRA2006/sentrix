"""Normalization: deduplicate findings and give them a deterministic order."""

from __future__ import annotations

from collections.abc import Iterable

from sentrix.models import Finding


def normalize_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Deduplicate by fingerprint and sort deterministically.

    When several findings share a fingerprint, the most severe one is kept;
    on a severity tie the first one seen wins. The result is sorted by
    severity (most severe first), then by rule id, so identical input always
    produces identical output regardless of input order.
    """
    best: dict[str, Finding] = {}

    for finding in findings:
        current = best.get(finding.fingerprint)
        if current is None or finding.severity.rank < current.severity.rank:
            best[finding.fingerprint] = finding

    return sorted(best.values(), key=lambda f: (f.severity.rank, f.id))
