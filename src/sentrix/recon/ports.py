"""Lightweight port check and service detection on common web ports."""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PortResult:
    port: int
    open: bool
    service: str
    banner: str = ""


# Default common web/app ports
COMMON_PORTS: tuple[tuple[int, str], ...] = (
    (80, "http"),
    (443, "https"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (3000, "node/web"),
    (8000, "http-alt"),
    (8888, "http-alt"),
    (5000, "flask/web"),
    (9000, "http/mgmt"),
    (21, "ftp"),
    (22, "ssh"),
)


def scan_ports(
    hostname: str,
    ports: tuple[tuple[int, str], ...] = COMMON_PORTS,
    timeout: float = 0.5,
    rate_limit: float = 0.05,
) -> list[PortResult]:
    """Perform a gentle connect scan on selected ports with short timeout."""
    results: list[PortResult] = []

    for port, service in ports:
        is_open = False
        banner = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                res = sock.connect_ex((hostname, port))
                if res == 0:
                    is_open = True
                    # Optional short banner probe
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        raw = sock.recv(256)
                        if raw:
                            banner = raw.decode("utf-8", errors="replace").splitlines()[0]
                    except Exception:
                        pass
        except OSError:
            pass

        if is_open:
            results.append(PortResult(port=port, open=True, service=service, banner=banner))

        if rate_limit > 0:
            time.sleep(rate_limit)

    return results
