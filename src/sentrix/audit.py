"""Audit logging for tracking scans, recon actions, and authorization flags."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> Path:
    return Path.home() / ".sentrix" / "audit.log"


def log_audit_event(
    action: str,
    target: str,
    details: dict,
    log_path: Path | None = None,
) -> None:
    """Append a structured audit entry to the audit log file."""
    path = log_path or default_audit_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "target": target,
            "details": details,
        }
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except OSError:
        pass
