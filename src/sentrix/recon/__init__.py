"""Active and passive reconnaissance package with strict guardrails."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urlsplit

from sentrix.recon.alive import AliveResult, probe_alive_subdomains, probe_subdomain
from sentrix.recon.dirs import (
    CATEGORY_PATHS,
    DEFAULT_PATHS,
    DirResult,
    discover_directories,
    get_paths_for_categories,
)
from sentrix.recon.ports import COMMON_PORTS, PortResult, scan_ports
from sentrix.recon.subdomains import enumerate_subdomains_crtsh
from sentrix.recon.takeover import (
    TAKEOVER_SIGNATURES,
    TakeoverResult,
    TakeoverSignature,
    check_subdomain_takeover,
    scan_subdomain_takeovers,
)
from sentrix.recon.vhost import (
    DEFAULT_VHOST_WORDS,
    VHostResult,
    discover_vhosts,
)


@dataclass(frozen=True, slots=True)
class ReconResult:
    target: str
    subdomains: tuple[str, ...]
    open_ports: tuple[PortResult, ...]
    discovered_paths: tuple[DirResult, ...]
    takeovers: tuple[TakeoverResult, ...] = ()
    alive_subdomains: tuple[AliveResult, ...] = ()
    discovered_vhosts: tuple[VHostResult, ...] = ()

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "subdomains": list(self.subdomains),
            "open_ports": [
                {"port": p.port, "service": p.service, "banner": p.banner}
                for p in self.open_ports
            ],
            "discovered_paths": [
                d.to_dict() for d in self.discovered_paths
            ],
            "takeovers": [t.to_dict() for t in self.takeovers],
            "alive_subdomains": [a.to_dict() for a in self.alive_subdomains],
            "discovered_vhosts": [v.to_dict() for v in self.discovered_vhosts],
        }


def run_recon(
    target: str,
    ports_scan: bool = True,
    subdomains_scan: bool = True,
    dirs_scan: bool = True,
    takeovers_scan: bool = False,
    alive_scan: bool = False,
    vhosts_scan: bool = False,
    dir_category: str | Sequence[str] | None = None,
    dir_paths: tuple[str, ...] | None = None,
    vhost_words: Sequence[str] | None = None,
    rate_limit: float = 0.5,
) -> ReconResult:
    """Run active and passive reconnaissance with configurable surface modules."""
    subdomains: list[str] = []
    if subdomains_scan or takeovers_scan or alive_scan:
        subdomains = enumerate_subdomains_crtsh(target)

    open_ports: list[PortResult] = []
    if ports_scan:
        host = urlsplit(target).hostname or target.split(":")[0]
        open_ports = scan_ports(host, rate_limit=rate_limit)

    discovered: list[DirResult] = []
    if dirs_scan:
        discovered = discover_directories(
            target,
            paths=dir_paths,
            category=dir_category,
            rate_limit=rate_limit,
        )

    takeovers: list[TakeoverResult] = []
    if takeovers_scan and subdomains:
        takeovers = scan_subdomain_takeovers(
            subdomains,
            rate_limit=rate_limit,
        )

    alive: list[AliveResult] = []
    if alive_scan and subdomains:
        alive = probe_alive_subdomains(
            subdomains,
            rate_limit=rate_limit,
        )

    vhosts: list[VHostResult] = []
    if vhosts_scan:
        host = urlsplit(target).hostname or target.split(":")[0]
        words = vhost_words or DEFAULT_VHOST_WORDS
        vhosts = discover_vhosts(
            target=target,
            domain=host,
            vhost_words=words,
            rate_limit=rate_limit,
        )

    return ReconResult(
        target=target,
        subdomains=tuple(subdomains),
        open_ports=tuple(open_ports),
        discovered_paths=tuple(discovered),
        takeovers=tuple(takeovers),
        alive_subdomains=tuple(alive),
        discovered_vhosts=tuple(vhosts),
    )


__all__ = [
    "AliveResult",
    "CATEGORY_PATHS",
    "COMMON_PORTS",
    "DEFAULT_PATHS",
    "DEFAULT_VHOST_WORDS",
    "DirResult",
    "PortResult",
    "ReconResult",
    "TAKEOVER_SIGNATURES",
    "TakeoverResult",
    "TakeoverSignature",
    "VHostResult",
    "check_subdomain_takeover",
    "discover_directories",
    "discover_vhosts",
    "enumerate_subdomains_crtsh",
    "get_paths_for_categories",
    "probe_alive_subdomains",
    "probe_subdomain",
    "run_recon",
    "scan_ports",
    "scan_subdomain_takeovers",
]
