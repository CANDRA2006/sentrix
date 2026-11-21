"""Target scope and network safety validation: guardrail against SSRF and internal scanning."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


class ScopeError(Exception):
    """Raised when target is outside authorized or safe scope."""


def is_private_or_internal_ip(ip_str: str) -> bool:
    """Check if an IP string belongs to a private, loopback, link-local, or reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        is_cgn = hasattr(ip, "is_carrier_grade_nat") and ip.is_carrier_grade_nat
        return bool(
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or is_cgn
        )
    except ValueError:
        return False


def validate_target_scope(url_or_host: str, allow_private: bool = False) -> tuple[str, str | None]:
    """Validate that the target does not resolve to a private/internal IP address.

    Returns (hostname, resolved_ip).
    Raises ScopeError if target resolves to private IP and allow_private is False.
    """
    if "://" in url_or_host:
        parsed = urlsplit(url_or_host)
        hostname = parsed.hostname or ""
    else:
        hostname = url_or_host.split(":")[0].strip()

    if not hostname:
        raise ScopeError("Target tidak memiliki hostname yang valid.")

    # Check if hostname itself is directly an IP literal
    if is_private_or_internal_ip(hostname):
        if not allow_private:
            raise ScopeError(
                f"Target '{hostname}' adalah alamat IP internal/private. "
                "Rentang internal/private diblokir demi keamanan kecuali menyertakan flag --allow-private."
            )
        return (hostname, hostname)

    # Resolve hostname
    try:
        ip_str = socket.gethostbyname(hostname)
    except socket.gaierror:
        # Cannot resolve hostname yet (offline or mock in tests)
        return (hostname, None)

    if is_private_or_internal_ip(ip_str) and not allow_private:
        raise ScopeError(
            f"Target '{hostname}' beralamat di IP internal/private ({ip_str}). "
            "Rentang internal/private diblokir demi keamanan kecuali menyertakan flag --allow-private."
        )

    return (hostname, ip_str)
