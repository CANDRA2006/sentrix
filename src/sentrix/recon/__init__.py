"""Active and passive reconnaissance package with strict guardrails."""

from __future__ import annotations

from dataclasses import dataclass

from sentrix.recon.dirs import DirResult, discover_directories
from sentrix.recon.ports import PortResult, scan_ports
from sentrix.recon.subdomains import enumerate_subdomains_crtsh


@dataclass(frozen=True, slots=True)
class ReconResult:
    target: str
    subdomains: tuple[str, ...]
    open_ports: tuple[PortResult, ...]
    discovered_paths: tuple[DirResult, ...]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "subdomains": list(self.subdomains),
            "open_ports": [
                {"port": p.port, "service": p.service, "banner": p.banner}
                for p in self.open_ports
            ],
            "discovered_paths": [
                {"path": d.path, "status_code": d.status_code}
                for d in self.discovered_paths
            ],
        }


def run_recon(
    target: str,
    ports_scan: bool = True,
    subdomains_scan: bool = True,
    dirs_scan: bool = True,
    rate_limit: float = 0.5,
) -> ReconResult:
    """Run passive/gentle recon on target."""
    subdomains: list[str] = []
    if subdomains_scan:
        subdomains = enumerate_subdomains_crtsh(target)

    open_ports: list[PortResult] = []
    if ports_scan:
        from urllib.parse import urlsplit
        host = urlsplit(target).hostname or target.split(":")[0]
        open_ports = scan_ports(host, rate_limit=rate_limit)

    discovered: list[DirResult] = []
    if dirs_scan:
        discovered = discover_directories(target, rate_limit=rate_limit)

    return ReconResult(
        target=target,
        subdomains=tuple(subdomains),
        open_ports=tuple(open_ports),
        discovered_paths=tuple(discovered),
    )


__all__ = [
    "DirResult",
    "PortResult",
    "ReconResult",
    "discover_directories",
    "enumerate_subdomains_crtsh",
    "run_recon",
    "scan_ports",
]
