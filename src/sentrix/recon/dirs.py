"""Lightweight directory discovery using categorized, passive/gentle wordlists."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urlsplit

import httpx


@dataclass(frozen=True, slots=True)
class DirResult:
    path: str
    status_code: int
    content_length: int = 0
    category: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "category": self.category,
        }


# Categorized wordlists for targeted attack surface reconnaissance
CATEGORY_PATHS: dict[str, tuple[str, ...]] = {
    "configs": (
        "/.git/HEAD",
        "/.git/config",
        "/.env",
        "/.env.local",
        "/.env.production",
        "/docker-compose.yml",
        "/Dockerfile",
        "/web.config",
        "/.htaccess",
    ),
    "api": (
        "/openapi.json",
        "/swagger.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger-ui.html",
        "/swagger/index.html",
        "/api/docs",
        "/api/v1",
        "/graphql",
    ),
    "metrics": (
        "/metrics",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/healthz",
        "/server-status",
        "/status",
    ),
    "backups": (
        "/backup.sql",
        "/db.sql",
        "/dump.sql",
        "/backup.zip",
        "/site.tar.gz",
        "/data.sqlite",
        "/backup.tar.gz",
    ),
    "admin": (
        "/admin",
        "/administrator",
        "/login",
        "/signin",
        "/dashboard",
        "/cpanel",
        "/phpmyadmin",
        "/wp-login.php",
        "/wp-admin",
    ),
}

# Small curated default wordlist for common web entry points
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


def get_paths_for_categories(categories: str | Sequence[str]) -> tuple[str, ...]:
    """Retrieve combined paths for given category name(s).

    Supports comma-separated string (e.g. 'configs,api') or list of names.
    Use 'all' to include all available categories.
    """
    if isinstance(categories, str):
        cat_list = [c.strip().lower() for c in categories.split(",") if c.strip()]
    else:
        cat_list = [c.strip().lower() for c in categories if c.strip()]

    if "all" in cat_list:
        combined: list[str] = []
        for paths in CATEGORY_PATHS.values():
            for p in paths:
                if p not in combined:
                    combined.append(p)
        return tuple(combined)

    selected: list[str] = []
    for cat in cat_list:
        if cat in CATEGORY_PATHS:
            for p in CATEGORY_PATHS[cat]:
                if p not in selected:
                    selected.append(p)

    return tuple(selected) if selected else DEFAULT_PATHS


def _infer_path_category(path: str) -> str:
    """Find category name for a given path."""
    for cat, paths in CATEGORY_PATHS.items():
        if path in paths:
            return cat
    return ""


def discover_directories(
    base_url: str,
    paths: tuple[str, ...] | None = None,
    category: str | Sequence[str] | None = None,
    client: httpx.Client | None = None,
    timeout: float = 3.0,
    rate_limit: float = 0.5,
) -> list[DirResult]:
    """Check common paths using HEAD or lightweight GET requests."""
    parsed = urlsplit(base_url)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port not in (80, 443):
        origin += f":{parsed.port}"

    if paths is not None:
        target_paths = paths
    elif category is not None:
        target_paths = get_paths_for_categories(category)
    else:
        target_paths = DEFAULT_PATHS

    results: list[DirResult] = []

    def _do_check(c: httpx.Client):
        for p in target_paths:
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
                    cat_name = _infer_path_category(p)
                    results.append(DirResult(
                        path=p,
                        status_code=code,
                        content_length=cl,
                        category=cat_name,
                    ))
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
