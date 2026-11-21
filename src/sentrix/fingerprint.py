"""Technology fingerprinting from headers, cookies, and HTML meta tags.

This is entirely passive — it only reads response headers and known
HTML patterns. No probing or active scanning is performed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Technology:
    """A detected technology with its source of detection."""
    name: str
    version: str
    source: str  # "header", "cookie", "meta", "html"
    confidence: str  # "HIGH", "MEDIUM", "LOW"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "confidence": self.confidence,
        }


# Header-based fingerprints: (header_name_lower, pattern, tech_name)
_HEADER_FINGERPRINTS: list[tuple[str, re.Pattern[str], str]] = [
    ("server", re.compile(r"nginx(?:/(\S+))?", re.I), "Nginx"),
    ("server", re.compile(r"Apache(?:/(\S+))?", re.I), "Apache"),
    ("server", re.compile(r"Microsoft-IIS(?:/(\S+))?", re.I), "Microsoft IIS"),
    ("server", re.compile(r"LiteSpeed(?:/(\S+))?", re.I), "LiteSpeed"),
    ("server", re.compile(r"openresty(?:/(\S+))?", re.I), "OpenResty"),
    ("server", re.compile(r"Caddy", re.I), "Caddy"),
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("x-powered-by", re.compile(r"PHP(?:/(\S+))?", re.I), "PHP"),
    ("x-powered-by", re.compile(r"ASP\.NET", re.I), "ASP.NET"),
    ("x-powered-by", re.compile(r"Express", re.I), "Express.js"),
    ("x-powered-by", re.compile(r"Next\.js(?:\s+(\S+))?", re.I), "Next.js"),
    ("x-powered-by", re.compile(r"Phusion Passenger", re.I), "Phusion Passenger"),
    ("x-aspnet-version", re.compile(r"(\S+)", re.I), "ASP.NET"),
    ("x-aspnetmvc-version", re.compile(r"(\S+)", re.I), "ASP.NET MVC"),
    ("x-drupal-cache", re.compile(r".*", re.I), "Drupal"),
    ("x-generator", re.compile(r"(.*)", re.I), "Generator"),
    ("x-varnish", re.compile(r".*", re.I), "Varnish"),
    ("via", re.compile(r"varnish", re.I), "Varnish"),
    ("cf-ray", re.compile(r".*", re.I), "Cloudflare"),
    ("x-amz-cf-id", re.compile(r".*", re.I), "Amazon CloudFront"),
    ("x-cache", re.compile(r"Hit from cloudfront", re.I), "Amazon CloudFront"),
    ("x-vercel-id", re.compile(r".*", re.I), "Vercel"),
    ("x-netlify-request-id", re.compile(r".*", re.I), "Netlify"),
]

# Cookie name patterns that reveal technology
_COOKIE_FINGERPRINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^PHPSESSID$", re.I), "PHP"),
    (re.compile(r"^ASP\.NET_SessionId$", re.I), "ASP.NET"),
    (re.compile(r"^JSESSIONID$", re.I), "Java/Servlet"),
    (re.compile(r"^CFID$|^CFTOKEN$", re.I), "ColdFusion"),
    (re.compile(r"^laravel_session$", re.I), "Laravel"),
    (re.compile(r"^_rails_session$|^_session_id$", re.I), "Ruby on Rails"),
    (re.compile(r"^connect\.sid$", re.I), "Express.js"),
    (re.compile(r"^wp-settings-", re.I), "WordPress"),
    (re.compile(r"^django", re.I), "Django"),
    (re.compile(r"^__cfduid$", re.I), "Cloudflare"),
]


def fingerprint_from_headers(headers: dict[str, str]) -> list[Technology]:
    """Detect technologies from HTTP response headers."""
    results: list[Technology] = []
    seen: set[str] = set()

    for header_lower, pattern, tech_name in _HEADER_FINGERPRINTS:
        value = headers.get(header_lower, "")
        if not value:
            continue
        match = pattern.search(value)
        if match:
            version = ""
            if match.lastindex and match.lastindex >= 1:
                version = match.group(1) or ""
            key = f"{tech_name}:{version}"
            if key not in seen:
                seen.add(key)
                results.append(Technology(
                    name=tech_name,
                    version=version,
                    source="header",
                    confidence="HIGH",
                ))

    return results


def fingerprint_from_cookies(cookie_names: list[str]) -> list[Technology]:
    """Detect technologies from cookie names (not values)."""
    results: list[Technology] = []
    seen: set[str] = set()

    for name in cookie_names:
        for pattern, tech_name in _COOKIE_FINGERPRINTS:
            if pattern.search(name) and tech_name not in seen:
                seen.add(tech_name)
                results.append(Technology(
                    name=tech_name,
                    version="",
                    source="cookie",
                    confidence="MEDIUM",
                ))

    return results


# HTML meta tag patterns
_META_GENERATOR = re.compile(
    r'<meta\s+[^>]*name\s*=\s*["\']?generator["\']?\s+[^>]*content\s*=\s*["\']([^"\']+)["\']',
    re.I,
)
_META_GENERATOR_ALT = re.compile(
    r'<meta\s+[^>]*content\s*=\s*["\']([^"\']+)["\'][^>]*name\s*=\s*["\']?generator["\']?',
    re.I,
)


def fingerprint_from_html(html: str) -> list[Technology]:
    """Detect technologies from HTML content (meta generator tag only)."""
    results: list[Technology] = []

    for pattern in (_META_GENERATOR, _META_GENERATOR_ALT):
        match = pattern.search(html)
        if match:
            generator = match.group(1).strip()
            # Try to separate name and version
            version_match = re.match(r"(.+?)\s+v?(\d[\d.]*)", generator)
            if version_match:
                results.append(Technology(
                    name=version_match.group(1),
                    version=version_match.group(2),
                    source="meta",
                    confidence="HIGH",
                ))
            else:
                results.append(Technology(
                    name=generator,
                    version="",
                    source="meta",
                    confidence="HIGH",
                ))
            break  # Only use the first match

    return results


def fingerprint_all(
    headers: dict[str, str],
    cookie_names: list[str] | None = None,
    html: str | None = None,
) -> list[Technology]:
    """Run all fingerprinting methods and return combined results."""
    results = fingerprint_from_headers(headers)
    if cookie_names:
        results.extend(fingerprint_from_cookies(cookie_names))
    if html:
        results.extend(fingerprint_from_html(html))
    return results
