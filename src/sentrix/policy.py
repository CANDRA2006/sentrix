"""Rule policy: which rules run, how severe they are, and when a scan fails.

A policy comes from an optional TOML file (``tomllib`` is in the standard
library, so there is no new dependency). It is plain data: it can switch
built-in rules off, re-triage their severity, and set the severity at which
``sentrix check`` should exit non-zero. It cannot run code and cannot add
rules.

Design notes:

* Strict on purpose. Unknown keys, unknown rule ids and wrongly typed values
  are errors, because a typo that is silently ignored looks exactly like a
  policy that works.
* Disabling a rule is a suppression, so it is never silent: the policy is
  copied into every report, printed by ``check``, and stored with each saved
  scan so ``compare`` can warn when two scans ran under different rules.
* A severity override does not change a finding's fingerprint, so ``compare``
  reports it as a severity change rather than as a new finding.
* ``fail_on`` only affects the exit code. It is left out of the stored rule
  policy because it cannot change what a scan finds.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from sentrix.models import SEVERITY_ORDER, Finding, Severity
from sentrix.rules import RULES, Rule

CONFIG_ENV_VAR = "SENTRIX_CONFIG"
MAX_CONFIG_BYTES = 64 * 1024

_TOP_LEVEL_KEYS = ("policy", "rules")
_POLICY_KEYS = ("fail_on",)
_RULE_KEYS = ("enabled", "severity")


class PolicyError(Exception):
    """A config file that cannot be read or is not a valid policy."""


@dataclass(frozen=True, slots=True)
class Policy:
    """The effective policy of one scan. The default policy changes nothing."""

    source: str | None = None
    fail_on: Severity | None = None
    disabled_rules: tuple[str, ...] = ()
    severity_overrides: Mapping[str, Severity] = field(default_factory=dict)

    @property
    def affects_findings(self) -> bool:
        """True if the policy can change which findings a scan produces."""
        return bool(self.disabled_rules or self.severity_overrides)

    @property
    def is_default(self) -> bool:
        return (
            self.source is None
            and self.fail_on is None
            and not self.affects_findings
        )

    def to_report_dict(self) -> dict:
        """JSON-serializable form that is copied into every report."""
        return {
            "source": self.source,
            "fail_on": self.fail_on.value if self.fail_on else None,
            "disabled_rules": list(self.disabled_rules),
            "severity_overrides": {
                rule_id: severity.value
                for rule_id, severity in sorted(
                    self.severity_overrides.items()
                )
            },
        }

    def rule_policy_json(self) -> str | None:
        """Canonical text stored with a scan, or ``None`` for the default.

        Only what can change the findings is included, so two scans compare
        as "same policy" exactly when they ran the same rules at the same
        severities. ``None`` also stands for scans stored before policies
        existed, which is correct: they ran with the default rules.
        """
        if not self.affects_findings:
            return None
        data = self.to_report_dict()
        return json.dumps(
            {
                "disabled_rules": data["disabled_rules"],
                "severity_overrides": data["severity_overrides"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def summary(self) -> str:
        """One terminal line describing a non-default policy."""
        parts = [self.source or "bawaan"]
        if self.disabled_rules:
            parts.append("nonaktif: " + ", ".join(self.disabled_rules))
        if self.severity_overrides:
            parts.append(
                "severity: "
                + ", ".join(
                    f"{rule_id}={severity.value}"
                    for rule_id, severity in sorted(
                        self.severity_overrides.items()
                    )
                )
            )
        if self.fail_on is not None:
            parts.append(f"gagal jika >= {self.fail_on.value}")
        return " | ".join(parts)


def describe_rule_policy(stored: str | None) -> str:
    """Human-readable form of ``Policy.rule_policy_json`` output.

    The text comes from a database file, so anything unexpected is reported
    as unrecognised instead of raising.
    """
    if stored is None:
        return "bawaan"
    try:
        data = json.loads(stored)
    except (ValueError, RecursionError):
        return "tidak dikenali"
    if not isinstance(data, dict):
        return "tidak dikenali"

    disabled = data.get("disabled_rules", [])
    overrides = data.get("severity_overrides", {})
    # Only plain identifiers are echoed back: the text is printed to a
    # terminal, so control characters and absurd lengths are "unrecognised".
    well_formed = (
        isinstance(disabled, list)
        and len(disabled) <= _MAX_STORED_ITEMS
        and all(_is_identifier(item) for item in disabled)
        and isinstance(overrides, dict)
        and len(overrides) <= _MAX_STORED_ITEMS
        and all(
            _is_identifier(key) and _is_identifier(value)
            for key, value in overrides.items()
        )
    )
    if not well_formed:
        return "tidak dikenali"

    parts = []
    if disabled:
        parts.append("nonaktif: " + ", ".join(disabled))
    if overrides:
        parts.append(
            "severity: "
            + ", ".join(f"{key}={value}" for key, value in sorted(overrides.items()))
        )
    return "; ".join(parts) or "bawaan"


# --- parsing ---------------------------------------------------------------


_IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_MAX_STORED_ITEMS = 50
_MAX_LISTED_KEYS = 10


def _is_identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _shorten(value: object, limit: int = 40) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _table(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PolicyError(f"{where} harus berupa tabel TOML.")
    return value


def _reject_unknown(
    table: Mapping[str, object], allowed: Sequence[str], where: str
) -> None:
    unknown = sorted(str(key) for key in table if key not in allowed)
    if unknown:
        # repr() keeps control characters from reaching the terminal, and the
        # cap keeps a pathological file from producing a wall of text.
        listed = ", ".join(_shorten(key) for key in unknown[:_MAX_LISTED_KEYS])
        extra = len(unknown) - _MAX_LISTED_KEYS
        if extra > 0:
            listed += f" (+{extra} lainnya)"
        raise PolicyError(
            f"Kunci tidak dikenal di {where}: {listed}. "
            f"Yang valid: {', '.join(allowed)}."
        )


def _severity(value: object, where: str) -> Severity:
    # ASCII only: str.upper() would otherwise turn a dotless "ı" into "I" and
    # accept spellings nobody meant.
    if isinstance(value, str) and value.isascii():
        candidate = value.strip().upper()
        if candidate in SEVERITY_ORDER:
            return Severity(candidate)
    raise PolicyError(
        f"{where}: severity tidak valid ({_shorten(value)}); "
        f"gunakan salah satu dari {', '.join(SEVERITY_ORDER)}."
    )


def parse_policy(
    data: Mapping[str, object],
    *,
    source: str | None = None,
    rules: Sequence[Rule] = RULES,
) -> Policy:
    """Validate parsed TOML and turn it into a ``Policy``."""
    _reject_unknown(data, _TOP_LEVEL_KEYS, "level atas")

    policy_table = _table(data.get("policy", {}), "[policy]")
    _reject_unknown(policy_table, _POLICY_KEYS, "[policy]")
    fail_on = None
    if "fail_on" in policy_table:
        fail_on = _severity(policy_table["fail_on"], "policy.fail_on")

    known = {rule.id: rule for rule in rules}
    rules_table = _table(data.get("rules", {}), "[rules]")
    disabled: list[str] = []
    overrides: dict[str, Severity] = {}

    for rule_id, raw in rules_table.items():
        if rule_id not in known:
            raise PolicyError(
                f"Aturan tidak dikenal: {_shorten(rule_id)}. "
                f"Aturan yang ada: {', '.join(known)}."
            )

        where = f"rules.{rule_id}"
        table = _table(raw, f"[{where}]")
        _reject_unknown(table, _RULE_KEYS, f"[{where}]")

        enabled = table.get("enabled", True)
        if not isinstance(enabled, bool):
            raise PolicyError(f"{where}.enabled harus true atau false.")

        if "severity" in table:
            severity = _severity(table["severity"], f"{where}.severity")
            if not enabled:
                raise PolicyError(
                    f"{where}: aturan dinonaktifkan sekaligus diberi "
                    "severity; pilih salah satu."
                )
            # An override equal to the built-in severity changes nothing, so
            # it is not recorded: otherwise it would make scans look as if
            # they ran under different policies.
            if severity is not known[rule_id].severity:
                overrides[rule_id] = severity

        if not enabled:
            disabled.append(rule_id)

    return Policy(
        source=source,
        fail_on=fail_on,
        disabled_rules=tuple(sorted(disabled)),
        severity_overrides=dict(sorted(overrides.items())),
    )


def load_policy(path: Path, *, rules: Sequence[Rule] = RULES) -> Policy:
    """Read and validate a policy file.

    Only the file *name* is kept as the policy's ``source``, so reports do
    not carry the directory layout of the machine that produced them.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise PolicyError(f"File tidak bisa dibaca: {exc}") from exc

    if len(raw) > MAX_CONFIG_BYTES:
        raise PolicyError(
            f"File terlalu besar (maksimum {MAX_CONFIG_BYTES // 1024} KiB)."
        )

    try:
        # utf-8-sig: Windows editors and PowerShell 5 often add a BOM.
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PolicyError("File harus berenkode UTF-8.") from exc

    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"TOML tidak valid: {exc}") from exc
    except RecursionError as exc:
        # The size limit does not stop absurdly deep nesting, and the parser
        # is recursive: report it as a bad file, not as a crash.
        raise PolicyError("TOML terlalu dalam bersarang.") from exc

    return parse_policy(data, source=path.name, rules=rules)


# --- applying --------------------------------------------------------------


def apply_policy(rules: Iterable[Rule], policy: Policy) -> tuple[Rule, ...]:
    """Rules that should actually run, with severity overrides applied.

    The input rules are never modified; overridden rules are copies.
    """
    effective: list[Rule] = []
    for rule in rules:
        if rule.id in policy.disabled_rules:
            continue
        override = policy.severity_overrides.get(rule.id)
        effective.append(
            replace(rule, severity=override) if override is not None else rule
        )
    return tuple(effective)


def gate_failed(findings: Iterable[Finding], fail_on: Severity | None) -> bool:
    """True if any finding is at least as severe as ``fail_on``."""
    if fail_on is None:
        return False
    return any(finding.severity.rank <= fail_on.rank for finding in findings)
