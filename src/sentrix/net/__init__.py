"""Network package."""

from __future__ import annotations

from sentrix.net.methods import (
    DANGEROUS_METHODS,
    find_dangerous_methods,
    parse_allow_methods,
)
from sentrix.net.redirects import (
    RedirectAnalysis,
    RedirectHop,
    analyze_redirects,
)
from sentrix.net.scope import (
    ScopeError,
    is_private_or_internal_ip,
    validate_target_scope,
)
from sentrix.net.tls import (
    TLSInfo,
    inspect_tls,
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
