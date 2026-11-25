"""Virtual Host (VHost) discovery via HTTP Host header permutation."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Sequence
from urllib.parse import urlsplit

import httpx

from sentrix.recon.alive import extract_html_title


@dataclass(frozen=True, slots=True)
class VHostResult:
    """Result of testing a virtual host candidate."""
    vhost: str
    status_code: int
    content_length: int
    title: str = ""
    is_distinct: bool = True

    def to_dict(self) -> dict:
        return {
            "vhost": self.vhost,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "title": self.title,
            "is_distinct": self.is_distinct,
        }


DEFAULT_VHOST_WORDS: tuple[str, ...] = (
    "admin",
    "dev",
    "staging",
    "test",
    "internal",
    "api",
    "corp",
    "portal",
    "vpn",
    "mail",
    "webmail",
    "beta",
    "demo",
    "m",
    "app",
    "auth",
    "sso",
)


def discover_vhosts(
    target: str,
    domain: str | None = None,
    vhost_words: Sequence[str] = DEFAULT_VHOST_WORDS,
    client: httpx.Client | None = None,
    rate_limit: float = 0.2,
    timeout: float = 3.0,
    size_threshold: int = 60,
) -> list[VHostResult]:
    """Test host header permutations against target IP/origin to detect distinct VHosts.

    A virtual host is deemed distinct if its HTTP status code or content length
    differs significantly from a randomized baseline request.
    """
    if "://" not in target:
        target = f"http://{target}"

    parsed = urlsplit(target)
    scheme = parsed.scheme or "http"
    base_host = parsed.hostname or target
    port = parsed.port
    origin = f"{scheme}://{base_host}"
    if port and port not in (80, 443):
        origin += f":{port}"

    root_domain = (domain or base_host).strip().lower()

    results: list[VHostResult] = []

    def _execute(c: httpx.Client):
        # 1. Establish baseline response using invalid host
        baseline_code = 0
        baseline_len = 0
        try:
            baseline_host = f"sentrix-vhost-invalid-baseline.{root_domain}"
            b_resp = c.get(
                origin,
                headers={"Host": baseline_host},
                timeout=timeout,
                follow_redirects=False,
            )
            baseline_code = b_resp.status_code
            baseline_len = len(b_resp.content)
        except Exception:
            pass

        # 2. Iterate vhost wordlist
        for word in vhost_words:
            candidate_vhost = f"{word}.{root_domain}"
            try:
                resp = c.get(
                    origin,
                    headers={"Host": candidate_vhost},
                    timeout=timeout,
                    follow_redirects=False,
                )
                code = resp.status_code
                length = len(resp.content)
                title = extract_html_title(resp.text) if code == 200 else ""

                # Check if distinct from baseline
                status_diff = code != baseline_code and baseline_code != 0
                size_diff = abs(length - baseline_len) > size_threshold
                is_distinct = (status_diff or size_diff) and code not in (400, 404, 500, 502)

                if is_distinct:
                    results.append(VHostResult(
                        vhost=candidate_vhost,
                        status_code=code,
                        content_length=length,
                        title=title,
                        is_distinct=True,
                    ))
            except Exception:
                pass

            if rate_limit > 0:
                time.sleep(rate_limit)

    if client is not None:
        _execute(client)
    else:
        with httpx.Client(
            timeout=timeout,
            headers={"User-Agent": "SENTRIX-Recon/0.1"},
            verify=False,
        ) as c:
            _execute(c)

    return results
