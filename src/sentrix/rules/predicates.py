"""Deterministic predicates for evaluating header values."""

from __future__ import annotations

import re

# Roughly 180 days, a common baseline for HSTS.
HSTS_MIN_MAX_AGE = 15_552_000
_CSP_BROAD_SOURCES = frozenset({"*", "http:", "https:", "data:"})
_CSP_NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
_WEAK_REFERRER_POLICIES = frozenset({"unsafe-url", "no-referrer-when-downgrade"})


def hsts_is_weak(value: str) -> bool:
    """No usable ``max-age`` directive, or one shorter than the baseline."""
    for part in value.split(";"):
        name, _, raw = part.strip().partition("=")
        if name.strip().lower() != "max-age":
            continue
        raw = raw.strip().strip('"')
        return not raw.isdecimal() or int(raw) < HSTS_MIN_MAX_AGE
    return True


def csp_script_is_loose(value: str) -> bool:
    """The effective script policy allows inline/eval code or any origin.

    Follows the spec: the first occurrence of a directive wins, and
    ``script-src`` falls back to ``default-src``. Browsers ignore
    ``'unsafe-inline'`` when a nonce or hash is present, so that case is not
    reported.
    """
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(
                tokens[0].lower(), [token.lower() for token in tokens[1:]]
            )

    sources = directives.get("script-src", directives.get("default-src"))
    if sources is None:
        return False

    has_nonce_or_hash = any(
        source.startswith(_CSP_NONCE_OR_HASH) or source == "'strict-dynamic'"
        for source in sources
    )
    if "'unsafe-eval'" in sources:
        return True
    if "'unsafe-inline'" in sources and not has_nonce_or_hash:
        return True
    return any(source in _CSP_BROAD_SOURCES for source in sources)


def nosniff_is_wrong(value: str) -> bool:
    """``nosniff`` is the only value browsers act on."""
    return value.split(",")[0].strip().lower() != "nosniff"


def referrer_policy_is_weak(value: str) -> bool:
    """The last listed policy is the one that applies."""
    tokens = [token.strip().lower() for token in value.split(",")]
    effective = next((token for token in reversed(tokens) if token), "")
    return effective in _WEAK_REFERRER_POLICIES


def server_reveals_version(value: str) -> bool:
    return re.search(r"\d+\.\d+", value) is not None


def reveals_technology(value: str) -> bool:
    return bool(value.strip())


def xfo_is_invalid(value: str) -> bool:
    """X-Frame-Options should be DENY or SAMEORIGIN."""
    v = value.strip().upper()
    if v in ("DENY", "SAMEORIGIN"):
        return False
    return True


def csp_missing_frame_ancestors(value: str) -> bool:
    """CSP without frame-ancestors directive."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1:])
    return "frame-ancestors" not in directives


def cors_is_wildcard(value: str) -> bool:
    """Access-Control-Allow-Origin: * indicator."""
    return value.strip() == "*"


def cache_control_is_unprotected(value: str) -> bool:
    """Cache-Control lacking no-store or private."""
    lower = value.lower()
    return not ("no-store" in lower or "private" in lower)


def coop_is_weak(value: str) -> bool:
    v = value.strip().lower()
    return v not in ("same-origin", "same-origin-allow-popups")


def coep_is_weak(value: str) -> bool:
    v = value.strip().lower()
    return v not in ("require-corp", "credentialless")


def corp_is_weak(value: str) -> bool:
    v = value.strip().lower()
    return v not in ("same-origin", "same-site")
