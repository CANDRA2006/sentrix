"""Compatibility facade for sentrix.net."""

from sentrix.net import (
    DANGEROUS_METHODS,
    RedirectAnalysis,
    RedirectHop,
    ScopeError,
    TLSInfo,
    analyze_redirects,
    find_dangerous_methods,
    inspect_tls,
    is_private_or_internal_ip,
    parse_allow_methods,
    validate_target_scope,
)

__all__ = [
    "DANGEROUS_METHODS",
    "RedirectAnalysis",
    "RedirectHop",
    "ScopeError",
    "TLSInfo",
    "analyze_redirects",
    "find_dangerous_methods",
    "inspect_tls",
    "is_private_or_internal_ip",
    "parse_allow_methods",
    "validate_target_scope",
]
