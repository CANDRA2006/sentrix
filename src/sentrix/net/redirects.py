"""Redirect chain analysis."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class RedirectHop:
    url: str
    status_code: int
    scheme: str


@dataclass(frozen=True, slots=True)
class RedirectAnalysis:
    hops: tuple[RedirectHop, ...]
    has_downgrade: bool  # HTTPS -> HTTP
    has_cross_domain: bool
    final_scheme: str

    def to_dict(self) -> dict:
        return {
            "hops": [
                {"url": h.url, "status_code": h.status_code, "scheme": h.scheme}
                for h in self.hops
            ],
            "has_downgrade": self.has_downgrade,
            "has_cross_domain": self.has_cross_domain,
            "final_scheme": self.final_scheme,
        }


def analyze_redirects(history: list, final_url: str) -> RedirectAnalysis:
    """Analyze the redirect chain from httpx response.history."""
    hops: list[RedirectHop] = []
    has_downgrade = False
    has_cross_domain = False

    all_urls = [str(resp.url) for resp in history] + [final_url]

    for resp in history:
        url_str = str(resp.url)
        parsed = urlsplit(url_str)
        hops.append(RedirectHop(
            url=url_str,
            status_code=resp.status_code,
            scheme=parsed.scheme,
        ))

    for i in range(len(all_urls) - 1):
        from_parsed = urlsplit(all_urls[i])
        to_parsed = urlsplit(all_urls[i + 1])

        if from_parsed.scheme == "https" and to_parsed.scheme == "http":
            has_downgrade = True

        from_host = from_parsed.hostname or ""
        to_host = to_parsed.hostname or ""
        if from_host != to_host:
            has_cross_domain = True

    final_parsed = urlsplit(final_url)

    return RedirectAnalysis(
        hops=tuple(hops),
        has_downgrade=has_downgrade,
        has_cross_domain=has_cross_domain,
        final_scheme=final_parsed.scheme,
    )
