"""Rule plugin system: load custom security rules from TOML/YAML files."""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path

from sentrix.models import Confidence, Severity
from sentrix.rules.models import Rule


def _parse_yaml_simple(text: str) -> dict:
    """A lightweight, zero-dependency parser for simple rule YAML files.

    Handles basic key-value pairs and list of rule dictionaries.
    Falls back gracefully without requiring external PyYAML.
    """
    rules: list[dict] = []
    current_rule: dict | None = None

    for line in text.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue

        if trimmed.startswith("- ") or trimmed.startswith("-"):
            if current_rule:
                rules.append(current_rule)
            current_rule = {}
            line_content = trimmed[1:].strip()
            if line_content and ":" in line_content:
                k, _, v = line_content.partition(":")
                current_rule[k.strip()] = v.strip().strip("'\"")
            continue

        if ":" in trimmed and current_rule is not None:
            k, _, v = trimmed.partition(":")
            v_clean = v.strip().strip("'\"")
            if v_clean.lower() == "true":
                current_rule[k.strip()] = True
            elif v_clean.lower() == "false":
                current_rule[k.strip()] = False
            else:
                current_rule[k.strip()] = v_clean

    if current_rule:
        rules.append(current_rule)

    return {"rules": rules}


def parse_plugin_rule(data: dict) -> Rule:
    """Validate and build a Rule object from a plugin dictionary."""
    rule_id = str(data.get("id", "")).strip()
    if not rule_id:
        raise ValueError("Plugin rule must have an 'id'.")

    header = str(data.get("header", "")).strip().lower()
    if not header:
        raise ValueError(f"Plugin rule {rule_id} must have a 'header'.")

    title = str(data.get("title", f"Header {header} missing")).strip()
    rec = str(data.get("recommendation", f"Review {header}.")).strip()

    sev_str = str(data.get("severity", "MEDIUM")).strip().upper()
    severity = Severity(sev_str) if sev_str in Severity.__members__ else Severity.MEDIUM

    conf_str = str(data.get("confidence", "HIGH")).strip().upper()
    confidence = (
        Confidence(conf_str)
        if conf_str in Confidence.__members__
        else Confidence.HIGH
    )

    https_only = bool(data.get("https_only", False))
    evidence_type = str(data.get("evidence_type", "missing_response_header"))

    # Optional regex pattern for weak value matching
    pattern = data.get("pattern")
    is_weak = None
    if pattern:
        regex = re.compile(str(pattern), re.IGNORECASE)
        # Inverted flag: if match_inverted is True, rule fires if pattern does NOT match
        invert = bool(data.get("invert_match", False))
        if invert:
            is_weak = lambda val: bool(not regex.search(val))
        else:
            is_weak = lambda val: bool(regex.search(val))
        if evidence_type == "missing_response_header":
            evidence_type = "weak_header_value"

    return Rule(
        id=rule_id,
        header=header,
        title=title,
        severity=severity,
        recommendation=rec,
        https_only=https_only,
        is_weak=is_weak,
        evidence_type=evidence_type,
        confidence=confidence,
    )


def load_rules_from_file(path: Path) -> list[Rule]:
    """Load custom rules from a .toml or .yaml/.yml file."""
    if not path.is_file():
        return []

    text = path.read_text(encoding="utf-8-sig")
    rules_data: list[dict] = []

    if path.suffix.lower() in (".toml",):
        try:
            data = tomllib.loads(text)
            # Accept either [[rules]] or [[plugin_rules]] or top-level list
            rules_data = data.get("rules", data.get("plugin_rules", []))
            if isinstance(rules_data, dict):
                # [rules.RULE_ID] table format
                rules_data = [{"id": k, **v} for k, v in rules_data.items() if isinstance(v, dict)]
        except Exception:
            return []
    elif path.suffix.lower() in (".yaml", ".yml"):
        try:
            parsed = _parse_yaml_simple(text)
            rules_data = parsed.get("rules", [])
        except Exception:
            return []

    result: list[Rule] = []
    for item in rules_data:
        if isinstance(item, dict):
            try:
                result.append(parse_plugin_rule(item))
            except Exception:
                continue

    return result


def load_rules_from_directory(directory: Path) -> list[Rule]:
    """Scan directory for rule files (.toml, .yaml, .yml) and load rules."""
    if not directory.is_dir():
        return []

    rules: list[Rule] = []
    for ext in ("*.toml", "*.yaml", "*.yml"):
        for file_path in directory.glob(ext):
            rules.extend(load_rules_from_file(file_path))
    return rules
