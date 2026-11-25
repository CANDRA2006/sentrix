"""Subdomain takeover and dangling CNAME detector.

Analyzes subdomains for dangling DNS CNAME records that point to external
services (AWS S3, GitHub Pages, Heroku, Azure, etc.) where the resource
has been released but the DNS record remains active.
"""

from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urlsplit

import httpx


@dataclass(frozen=True, slots=True)
class TakeoverSignature:
    """Signature pattern for identifying unclaimed cloud services."""
    service: str
    cname_keywords: tuple[str, ...]
    fingerprints: tuple[str, ...]


# Known cloud/SaaS provider dangling CNAME patterns and fingerprints
TAKEOVER_SIGNATURES: tuple[TakeoverSignature, ...] = (
    TakeoverSignature(
        service="GitHub Pages",
        cname_keywords=("github.io",),
        fingerprints=(
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ),
    ),
    TakeoverSignature(
        service="AWS S3",
        cname_keywords=("s3.amazonaws.com", "s3-website"),
        fingerprints=(
            "NoSuchBucket",
            "The specified bucket does not exist",
        ),
    ),
    TakeoverSignature(
        service="Heroku",
        cname_keywords=("herokuapp.com", "herokudns.com"),
        fingerprints=(
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
        ),
    ),
    TakeoverSignature(
        service="Azure App Service",
        cname_keywords=("azurewebsites.net", "cloudapp.net", "trafficmanager.net"),
        fingerprints=(
            "404 Web Site not found",
            "The resource you are looking for has been removed",
        ),
    ),
    TakeoverSignature(
        service="Netlify",
        cname_keywords=("netlify.app", "netlify.com"),
        fingerprints=(
            "Not Found - Request ID",
        ),
    ),
    TakeoverSignature(
        service="Fastly",
        cname_keywords=("fastly.net",),
        fingerprints=(
            "Fastly error: unknown domain",
        ),
    ),
    TakeoverSignature(
        service="Ghost",
        cname_keywords=("ghost.io",),
        fingerprints=(
            "The thing you were looking for is no longer here",
        ),
    ),
    TakeoverSignature(
        service="Shopify",
        cname_keywords=("myshopify.com",),
        fingerprints=(
            "Sorry, this shop is currently unavailable",
        ),
    ),
    TakeoverSignature(
        service="Surge",
        cname_keywords=("surge.sh",),
        fingerprints=(
            "project not found",
        ),
    ),
    TakeoverSignature(
        service="Bitbucket",
        cname_keywords=("bitbucket.io",),
        fingerprints=(
            "Repository not found",
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class TakeoverResult:
    """Result of checking a subdomain for takeover vulnerability."""
    subdomain: str
    service: str
    cname: str = ""
    vulnerable: bool = False
    fingerprint_matched: str = ""
    status_code: int | None = None

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "service": self.service,
            "cname": self.cname,
            "vulnerable": self.vulnerable,
            "fingerprint_matched": self.fingerprint_matched,
            "status_code": self.status_code,
        }


def resolve_cname(subdomain: str, client: httpx.Client | None = None, timeout: float = 3.0) -> str:
    """Resolve CNAME for a subdomain using OS resolver or DNS-over-HTTPS.

    Returns the canonical name if available, or empty string.
    """
    clean_host = subdomain.split(":")[0].strip().lower()

    # 1. Try standard socket AI_CANONNAME
    try:
        addrinfo = socket.getaddrinfo(clean_host, None, flags=socket.AI_CANONNAME)
        if addrinfo and addrinfo[0][3] and addrinfo[0][3].lower() != clean_host:
            return addrinfo[0][3].lower()
    except OSError:
        pass

    # 2. Fallback to Cloudflare DNS-over-HTTPS query if available
    doh_url = f"https://cloudflare-dns.com/dns-query?name={clean_host}&type=CNAME"
    headers = {"accept": "application/dns-json", "User-Agent": "SENTRIX-Recon/0.1"}

    def _query(c: httpx.Client) -> str:
        try:
            resp = c.get(doh_url, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                for answer in data.get("Answer", []):
                    if answer.get("type") == 5:  # CNAME
                        return str(answer.get("data", "")).rstrip(".").lower()
        except Exception:
            pass
        return ""

    if client is not None:
        return _query(client)

    try:
        with httpx.Client(timeout=timeout) as c:
            return _query(c)
    except Exception:
        return ""


def check_subdomain_takeover(
    subdomain: str,
    cname: str | None = None,
    client: httpx.Client | None = None,
    timeout: float = 4.0,
) -> TakeoverResult | None:
    """Check a single subdomain for potential takeover.

    If cname is not provided, it is resolved automatically.
    """
    if cname is None:
        cname = resolve_cname(subdomain, client=client, timeout=timeout)

    # Check which provider matches the CNAME (or subdomain directly)
    matched_sig: TakeoverSignature | None = None
    target_to_match = (cname or subdomain).lower()

    for sig in TAKEOVER_SIGNATURES:
        if any(keyword in target_to_match for keyword in sig.cname_keywords):
            matched_sig = sig
            break

    if not matched_sig:
        return None

    # Probe HTTP/HTTPS to check for unclaimed error fingerprint
    def _probe(c: httpx.Client) -> TakeoverResult:
        urls = [f"https://{subdomain}", f"http://{subdomain}"]
        for url in urls:
            try:
                resp = c.get(url, timeout=timeout, follow_redirects=True)
                body = resp.text
                for fp in matched_sig.fingerprints:
                    if fp.lower() in body.lower():
                        return TakeoverResult(
                            subdomain=subdomain,
                            service=matched_sig.service,
                            cname=cname or "",
                            vulnerable=True,
                            fingerprint_matched=fp,
                            status_code=resp.status_code,
                        )
                # Found service CNAME, but fingerprint not matched (likely active/claimed)
                return TakeoverResult(
                    subdomain=subdomain,
                    service=matched_sig.service,
                    cname=cname or "",
                    vulnerable=False,
                    fingerprint_matched="",
                    status_code=resp.status_code,
                )
            except Exception:
                continue

        # If HTTP connection fails completely on dangling CNAME, flag as potential
        return TakeoverResult(
            subdomain=subdomain,
            service=matched_sig.service,
            cname=cname or "",
            vulnerable=False,
            fingerprint_matched="",
            status_code=None,
        )

    if client is not None:
        return _probe(client)

    try:
        with httpx.Client(
            timeout=timeout,
            headers={"User-Agent": "SENTRIX-Recon/0.1"},
            verify=False,
        ) as c:
            return _probe(c)
    except Exception:
        return None


def scan_subdomain_takeovers(
    subdomains: Sequence[str],
    client: httpx.Client | None = None,
    rate_limit: float = 0.2,
    timeout: float = 4.0,
) -> list[TakeoverResult]:
    """Check a collection of subdomains for takeover vulnerabilities."""
    results: list[TakeoverResult] = []

    for sub in subdomains:
        res = check_subdomain_takeover(sub, client=client, timeout=timeout)
        if res is not None:
            results.append(res)
        if rate_limit > 0:
            time.sleep(rate_limit)

    return results
