"""Passive resource discovery: security.txt, robots.txt, exposed files.

All checks are strictly passive — only the HTTP status code is used to
determine whether a resource exists. Response bodies are never read except
for the well-defined security.txt and robots.txt formats.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit


# ---------------------------------------------------------------------------
# security.txt
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SecurityTxtResult:
    """Result of checking /.well-known/security.txt."""
    found: bool
    status_code: int | None = None
    has_contact: bool = False
    has_expires: bool = False
    has_encryption: bool = False
    is_signed: bool = False

    def to_dict(self) -> dict:
        return {
            "found": self.found,
            "status_code": self.status_code,
            "has_contact": self.has_contact,
            "has_expires": self.has_expires,
            "has_encryption": self.has_encryption,
            "is_signed": self.is_signed,
        }


def parse_security_txt(body: str) -> SecurityTxtResult:
    """Parse a security.txt body for required/recommended fields."""
    has_contact = bool(re.search(r"^Contact:", body, re.MULTILINE | re.IGNORECASE))
    has_expires = bool(re.search(r"^Expires:", body, re.MULTILINE | re.IGNORECASE))
    has_encryption = bool(re.search(r"^Encryption:", body, re.MULTILINE | re.IGNORECASE))
    is_signed = "-----BEGIN PGP SIGNED MESSAGE-----" in body

    return SecurityTxtResult(
        found=True,
        status_code=200,
        has_contact=has_contact,
        has_expires=has_expires,
        has_encryption=has_encryption,
        is_signed=is_signed,
    )


# ---------------------------------------------------------------------------
# robots.txt
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RobotsTxtResult:
    """Result of checking /robots.txt."""
    found: bool
    status_code: int | None = None
    sensitive_paths: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "found": self.found,
            "status_code": self.status_code,
            "sensitive_paths": list(self.sensitive_paths),
        }


# Paths that may indicate sensitive areas when disallowed
_SENSITIVE_PATTERNS = (
    "/admin", "/administrator", "/wp-admin", "/cpanel",
    "/phpmyadmin", "/server-status", "/server-info",
    "/.env", "/.git", "/.svn", "/.htaccess", "/.htpasswd",
    "/backup", "/db", "/database", "/dump",
    "/api/", "/internal/", "/private/", "/secret/",
    "/config", "/conf", "/credentials",
    "/debug", "/trace", "/test",
    "/wp-login", "/login", "/signin",
    "/cgi-bin",
)


def parse_robots_txt(body: str) -> RobotsTxtResult:
    """Parse robots.txt for Disallow entries pointing to sensitive paths."""
    sensitive: list[str] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Only look at Disallow directives
        match = re.match(r"Disallow:\s*(.*)", line, re.IGNORECASE)
        if not match:
            continue
        path = match.group(1).strip()
        if not path:
            continue
        path_lower = path.lower()
        for pattern in _SENSITIVE_PATTERNS:
            if path_lower.startswith(pattern) or pattern.startswith(path_lower):
                if path not in sensitive:
                    sensitive.append(path)
                break

    return RobotsTxtResult(
        found=True,
        status_code=200,
        sensitive_paths=tuple(sensitive),
    )


# ---------------------------------------------------------------------------
# Exposed files check
# ---------------------------------------------------------------------------

# Files that should not be publicly accessible
EXPOSED_FILE_PATHS = (
    "/.git/HEAD",
    "/.env",
    "/.htaccess",
    "/.htpasswd",
    "/server-status",
    "/server-info",
    "/.DS_Store",
    "/wp-config.php.bak",
    "/.svn/entries",
    "/web.config",
    "/crossdomain.xml",
    "/phpinfo.php",
)

# Status codes that indicate the file exists
_EXISTS_CODES = frozenset({200, 403})


@dataclass(frozen=True, slots=True)
class ExposedFileResult:
    path: str
    status_code: int
    exists: bool

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "status_code": self.status_code,
            "exists": self.exists,
        }


def check_exposed_file_status(path: str, status_code: int) -> ExposedFileResult:
    """Determine if a file is exposed based on status code only.

    Does NOT read the response body — this is a status-code-only check.
    """
    return ExposedFileResult(
        path=path,
        status_code=status_code,
        exists=status_code in _EXISTS_CODES,
    )
