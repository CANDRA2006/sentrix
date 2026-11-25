"""Live subdomain probing: verify active HTTP services, status code, and titles."""

from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass
from typing import Sequence

import httpx


@dataclass(frozen=True, slots=True)
class AliveResult:
    """Result of probing an active subdomain."""
    subdomain: str
    alive: bool
    status_code: int | None = None
    title: str = ""
    redirect_url: str = ""
    ip: str = ""

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "alive": self.alive,
            "status_code": self.status_code,
            "title": self.title,
            "redirect_url": self.redirect_url,
            "ip": self.ip,
        }


_TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_html_title(body: str) -> str:
    """Extract and sanitize HTML <title> tag text."""
    match = _TITLE_REGEX.search(body)
    if not match:
        return ""
    title = match.group(1).strip()
    # Normalize multiple whitespaces
    title = re.sub(r"\s+", " ", title)
    return title[:120]


def probe_subdomain(
    subdomain: str,
    client: httpx.Client | None = None,
    timeout: float = 3.0,
) -> AliveResult:
    """Probe a single subdomain via HTTPS then HTTP."""
    clean_host = subdomain.split(":")[0].strip()

    # Try DNS resolution to find IP
    ip_str = ""
    try:
        ip_str = socket.gethostbyname(clean_host)
    except OSError:
        pass

    def _do_probe(c: httpx.Client) -> AliveResult:
        # Check https first, then fallback to http
        schemes = ["https", "http"]
        last_error = None

        for scheme in schemes:
            url = f"{scheme}://{clean_host}"
            try:
                resp = c.get(url, timeout=timeout, follow_redirects=False)
                code = resp.status_code
                redirect = resp.headers.get("location", "")
                title = extract_html_title(resp.text) if resp.status_code == 200 else ""

                return AliveResult(
                    subdomain=clean_host,
                    alive=True,
                    status_code=code,
                    title=title,
                    redirect_url=redirect,
                    ip=ip_str,
                )
            except Exception as exc:
                last_error = exc
                continue

        return AliveResult(
            subdomain=clean_host,
            alive=False,
            status_code=None,
            title="",
            redirect_url="",
            ip=ip_str,
        )

    if client is not None:
        return _do_probe(client)

    try:
        with httpx.Client(
            timeout=timeout,
            headers={"User-Agent": "SENTRIX-Recon/0.1"},
            verify=False,
        ) as c:
            return _do_probe(c)
    except Exception:
        return AliveResult(subdomain=clean_host, alive=False, ip=ip_str)


def probe_alive_subdomains(
    subdomains: Sequence[str],
    client: httpx.Client | None = None,
    rate_limit: float = 0.1,
    timeout: float = 3.0,
) -> list[AliveResult]:
    """Probe a list of subdomains and return results."""
    results: list[AliveResult] = []

    for sub in subdomains:
        res = probe_subdomain(sub, client=client, timeout=timeout)
        results.append(res)
        if rate_limit > 0:
            time.sleep(rate_limit)

    return results
