"""Subresource Integrity (SRI) checking for third-party scripts.

Parses HTML to find <script src="..."> tags that load from external origins
and checks whether they have an ``integrity`` attribute.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class ScriptSRIResult:
    """Result for one external script tag."""
    src: str
    has_integrity: bool
    has_crossorigin: bool

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "has_integrity": self.has_integrity,
            "has_crossorigin": self.has_crossorigin,
        }


# Match <script ... src="..." ...> (not self-closing)
_SCRIPT_TAG = re.compile(
    r"<script\b([^>]*)>",
    re.I | re.DOTALL,
)

_SRC_ATTR = re.compile(
    r"""\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))""",
    re.I,
)

_INTEGRITY_ATTR = re.compile(r"\bintegrity\s*=", re.I)
_CROSSORIGIN_ATTR = re.compile(r"\bcrossorigin\b", re.I)


def _is_external(src: str, page_hostname: str) -> bool:
    """Check if a script src points to a third-party origin."""
    if not src:
        return False
    # Protocol-relative or absolute URL
    if src.startswith("//"):
        src = "https:" + src
    parsed = urlsplit(src)
    if not parsed.hostname:
        # Relative URL — same origin
        return False
    return parsed.hostname.lower() != page_hostname.lower()


def check_sri(html: str, page_url: str) -> list[ScriptSRIResult]:
    """Find external <script src=...> without integrity attributes.

    ``page_url`` is used to determine which scripts are third-party.
    Only returns results for external scripts (different hostname).
    """
    page_hostname = urlsplit(page_url).hostname or ""
    results: list[ScriptSRIResult] = []

    for tag_match in _SCRIPT_TAG.finditer(html):
        attrs = tag_match.group(1)
        src_match = _SRC_ATTR.search(attrs)
        if not src_match:
            continue

        src = src_match.group(1) or src_match.group(2) or src_match.group(3) or ""
        if not _is_external(src, page_hostname):
            continue

        has_integrity = bool(_INTEGRITY_ATTR.search(attrs))
        has_crossorigin = bool(_CROSSORIGIN_ATTR.search(attrs))

        results.append(ScriptSRIResult(
            src=src,
            has_integrity=has_integrity,
            has_crossorigin=has_crossorigin,
        ))

    return results
