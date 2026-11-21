"""TLS inspection utilities using the standard library ssl module."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class TLSInfo:
    """TLS metadata for a single connection."""
    protocol_version: str
    cipher_name: str
    cipher_bits: int
    cert_subject: dict[str, str] = field(default_factory=dict)
    cert_issuer: dict[str, str] = field(default_factory=dict)
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_san: tuple[str, ...] = ()
    cert_serial: str = ""
    days_until_expiry: int | None = None
    chain_depth: int = 0
    san_mismatch: bool = False
    expired: bool = False

    def to_dict(self) -> dict:
        return {
            "protocol_version": self.protocol_version,
            "cipher_name": self.cipher_name,
            "cipher_bits": self.cipher_bits,
            "cert_subject": dict(self.cert_subject),
            "cert_issuer": dict(self.cert_issuer),
            "cert_not_before": self.cert_not_before,
            "cert_not_after": self.cert_not_after,
            "cert_san": list(self.cert_san),
            "cert_serial": self.cert_serial,
            "days_until_expiry": self.days_until_expiry,
            "chain_depth": self.chain_depth,
            "san_mismatch": self.san_mismatch,
            "expired": self.expired,
        }


def _parse_cert_field(entries: tuple[tuple[tuple[str, str], ...], ...] | None) -> dict[str, str]:
    if not entries:
        return {}
    result: dict[str, str] = {}
    for group in entries:
        for key, value in group:
            result[key] = value
    return result


def _parse_cert_date(date_str: str) -> datetime | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def inspect_tls(hostname: str, port: int = 443, timeout: float = 8.0) -> TLSInfo | None:
    """Connect to hostname:port and inspect the TLS certificate and cipher."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_OPTIONAL

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                protocol = ssock.version() or "unknown"
    except (OSError, ssl.SSLError):
        return None

    if cert is None or cipher_info is None:
        return None

    cipher_name = cipher_info[0]
    cipher_bits = cipher_info[2]

    subject = _parse_cert_field(cert.get("subject"))
    issuer = _parse_cert_field(cert.get("issuer"))
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    serial = cert.get("serialNumber", "")

    san_entries: list[str] = []
    for san_type, san_value in cert.get("subjectAltName", ()):
        san_entries.append(f"{san_type}:{san_value}")

    days_until_expiry: int | None = None
    expired = False
    if not_after:
        exp_date = _parse_cert_date(not_after)
        if exp_date:
            delta = exp_date - datetime.now(timezone.utc)
            days_until_expiry = delta.days
            expired = delta.total_seconds() < 0

    san_mismatch = True
    san_dns_values = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
    for san_dns in san_dns_values:
        if san_dns == hostname:
            san_mismatch = False
            break
        if san_dns.startswith("*."):
            suffix = san_dns[2:]
            if hostname.endswith(f".{suffix}") and "." not in hostname[: -(len(suffix) + 1)]:
                san_mismatch = False
                break
    if not san_dns_values:
        cn = subject.get("commonName", "")
        if cn == hostname:
            san_mismatch = False

    chain_depth = len(cert.get("caIssuers", ())) if "caIssuers" in cert else 0

    return TLSInfo(
        protocol_version=protocol,
        cipher_name=cipher_name,
        cipher_bits=cipher_bits,
        cert_subject=subject,
        cert_issuer=issuer,
        cert_not_before=not_before,
        cert_not_after=not_after,
        cert_san=tuple(san_entries),
        cert_serial=serial,
        days_until_expiry=days_until_expiry,
        chain_depth=chain_depth,
        san_mismatch=san_mismatch,
        expired=expired,
    )
