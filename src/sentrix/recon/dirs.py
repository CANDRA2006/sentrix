"""Lightweight directory discovery using a small, passive/gentle wordlist."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx


@dataclass(frozen=True, slots=True)
class DirResult:
    path: str
    status_code: int
    content_length: int = 0


# Small curated wordlist for common web entry points
DEFAULT_PATHS: tuple[str, ...] = (
    "/admin",
    "/administrator",
    "/api",
    "/login",
    "/signin",
    "/dashboard",
    "/config",
    "/backup",
    "/.git/HEAD",
    "/.env",
    "/server-status",
    "/robots.txt",
    "/.well-known/security.txt",
)


def discover_directories(
    base_url: str,
    paths: tuple[str, ...] = DEFAULT_PATHS,
    client: httpx.Client | None = None,
    timeout: float = 3.0,
    rate_limit: float = 0.5,
) -> list[DirResult]:
    """Check common paths using HEAD or lightweight GET requests."""
    parsed = urlsplit(base_url)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port not in (80, 443):
        origin += f":{parsed.port}"

    results: list[DirResult] = []

    def _do_check(c: httpx.Client):
        for p in paths:
            url = f"{origin}{p}"
            try:
                # Try HEAD first
                resp = c.head(url)
                if resp.status_code == 405:
                    # Fallback to stream GET to not read body
                    with c.stream("GET", url) as stream_resp:
                        code = stream_resp.status_code
                        cl = int(stream_resp.headers.get("content-length", 0))
                else:
                    code = resp.status_code
                    cl = int(resp.headers.get("content-length", 0))

                if code not in (404, 502, 503, 504):
                    results.append(DirResult(path=p, status_code=code, content_length=cl))
            except Exception:
                pass

            if rate_limit > 0:
                time.sleep(rate_limit)

    if client:
        _do_check(client)
    else:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": "SENTRIX-Recon/0.1"},
        ) as c:
            _do_check(c)

    return results
