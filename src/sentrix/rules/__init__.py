"""Deterministic response-header rules and plugin management."""

from __future__ import annotations

from sentrix.rules.builtin import (
    ALL_RULES,
    CORE_RULES,
    EXTENDED_RULES,
    RULES,
)
from sentrix.rules.engine import evaluate_headers
from sentrix.rules.models import Rule
from sentrix.rules.plugins import (
    load_rules_from_directory,
    load_rules_from_file,
    parse_plugin_rule,
)
from sentrix.rules.predicates import (
    HSTS_MIN_MAX_AGE,
    cache_control_is_unprotected,
    coep_is_weak,
    coop_is_weak,
    corp_is_weak,
    cors_is_wildcard,
    csp_missing_frame_ancestors,
    csp_script_is_loose,
    hsts_is_weak,
    nosniff_is_wrong,
    referrer_policy_is_weak,
    reveals_technology,
    server_reveals_version,
    xfo_is_invalid,
)

__all__ = [
    "ALL_RULES",
    "CORE_RULES",
    "EXTENDED_RULES",
    "HSTS_MIN_MAX_AGE",
    "RULES",
    "Rule",
    "cache_control_is_unprotected",
    "coep_is_weak",
    "coop_is_weak",
    "corp_is_weak",
    "cors_is_wildcard",
    "csp_missing_frame_ancestors",
    "csp_script_is_loose",
    "evaluate_headers",
    "hsts_is_weak",
    "load_rules_from_directory",
    "load_rules_from_file",
    "nosniff_is_wrong",
    "parse_plugin_rule",
    "referrer_policy_is_weak",
    "reveals_technology",
    "server_reveals_version",
    "xfo_is_invalid",
]
