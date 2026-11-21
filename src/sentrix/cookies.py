"""Cookie flag analysis: inspect Set-Cookie headers for security attributes.

This module checks cookie flags without storing or transmitting cookie values.
Only the flag names and their presence/absence are analyzed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CookieAnalysis:
    """Analysis result for one Set-Cookie header."""
    name: str
    secure: bool
    httponly: bool
    samesite: str  # "strict", "lax", "none", or "" (missing)
    has_host_prefix: bool
    has_secure_prefix: bool
    host_prefix_valid: bool  # __Host- requires Secure, Path=/, no Domain
    secure_prefix_valid: bool  # __Secure- requires Secure
    path: str
    has_domain: bool

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "secure": self.secure,
            "httponly": self.httponly,
            "samesite": self.samesite,
            "has_host_prefix": self.has_host_prefix,
            "has_secure_prefix": self.has_secure_prefix,
            "host_prefix_valid": self.host_prefix_valid,
            "secure_prefix_valid": self.secure_prefix_valid,
            "path": self.path,
            "has_domain": self.has_domain,
        }


def _parse_cookie_flags(set_cookie: str) -> CookieAnalysis:
    """Parse a single Set-Cookie header value and extract security flags.

    Only the flag names are extracted. Cookie values are never stored.
    """
    parts = [p.strip() for p in set_cookie.split(";")]
    if not parts:
        return CookieAnalysis(
            name="", secure=False, httponly=False, samesite="",
            has_host_prefix=False, has_secure_prefix=False,
            host_prefix_valid=True, secure_prefix_valid=True,
            path="", has_domain=False,
        )

    # First part is name=value; we only need the name
    name_value = parts[0]
    eq_pos = name_value.find("=")
    name = name_value[:eq_pos].strip() if eq_pos >= 0 else name_value.strip()

    secure = False
    httponly = False
    samesite = ""
    path = ""
    has_domain = False

    for part in parts[1:]:
        lower = part.strip().lower()
        if lower == "secure":
            secure = True
        elif lower == "httponly":
            httponly = True
        elif lower.startswith("samesite"):
            eq = lower.find("=")
            if eq >= 0:
                samesite = lower[eq + 1:].strip()
        elif lower.startswith("path"):
            eq = lower.find("=")
            if eq >= 0:
                path = part.strip()[eq + 1:].strip()
        elif lower.startswith("domain"):
            has_domain = True

    has_host_prefix = name.startswith("__Host-")
    has_secure_prefix = name.startswith("__Secure-")

    # __Host- requires: Secure flag, Path=/, no Domain attribute
    host_prefix_valid = True
    if has_host_prefix:
        host_prefix_valid = secure and path == "/" and not has_domain

    # __Secure- requires: Secure flag
    secure_prefix_valid = True
    if has_secure_prefix:
        secure_prefix_valid = secure

    return CookieAnalysis(
        name=name,
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        has_host_prefix=has_host_prefix,
        has_secure_prefix=has_secure_prefix,
        host_prefix_valid=host_prefix_valid,
        secure_prefix_valid=secure_prefix_valid,
        path=path,
        has_domain=has_domain,
    )


def analyze_cookies(set_cookie_headers: list[str], is_https: bool) -> list[CookieAnalysis]:
    """Analyze all Set-Cookie headers and return analysis results.

    Only analyses flag presence; never stores cookie values.
    """
    results: list[CookieAnalysis] = []
    for header_value in set_cookie_headers:
        analysis = _parse_cookie_flags(header_value)
        if analysis.name:
            results.append(analysis)
    return results
