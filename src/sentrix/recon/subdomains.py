"""Passive subdomain enumeration via crt.sh Certificate Transparency logs."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

import httpx


def enumerate_subdomains_crtsh(domain: str, timeout: float = 10.0) -> list[str]:
    """Query crt.sh for known subdomains in public certificate transparency logs.

    Completely passive: queries crt.sh, sends zero traffic to the target.
    """
    # Extract clean domain
    if "://" in domain:
        domain = urlsplit(domain).hostname or domain
    domain = domain.split(":")[0].strip()

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "SENTRIX-Recon/0.1"}

    subdomains: set[str] = set()

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.splitlines():
                        name = name.strip().lower()
                        if name.startswith("*."):
                            name = name[2:]
                        if name and name.endswith(domain):
                            subdomains.add(name)
    except Exception:
        pass

    return sorted(subdomains)
