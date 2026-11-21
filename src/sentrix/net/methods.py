"""HTTP methods inspection."""

from __future__ import annotations

DANGEROUS_METHODS = frozenset({"TRACE", "PUT", "DELETE", "CONNECT", "PATCH"})


def parse_allow_methods(allow_header: str) -> tuple[str, ...]:
    """Parse the Allow header and return the list of methods."""
    if not allow_header.strip():
        return ()
    return tuple(m.strip().upper() for m in allow_header.split(",") if m.strip())


def find_dangerous_methods(methods: tuple[str, ...]) -> tuple[str, ...]:
    """Return the subset of methods that are considered risky to have enabled."""
    return tuple(m for m in methods if m in DANGEROUS_METHODS)
