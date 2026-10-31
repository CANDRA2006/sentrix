"""Rule policy: TOML loading, validation, and application."""

import json
import tomllib
from pathlib import Path

import httpx
import pytest

from sentrix import cli
from sentrix.models import Confidence, Evidence, Finding, Severity
from sentrix.policy import (
    MAX_CONFIG_BYTES,
    Policy,
    PolicyError,
    apply_policy,
    describe_rule_policy,
    gate_failed,
    load_policy,
    parse_policy,
)
from sentrix.rules import RULES


def parse(text: str, **kwargs) -> Policy:
    return parse_policy(tomllib.loads(text), **kwargs)


def write(tmp_path: Path, content: str | bytes, name: str = "sentrix.toml"):
    path = tmp_path / name
    if isinstance(content, str):
        content = content.encode("utf-8")
    path.write_bytes(content)
    return path


def finding(severity: Severity, rule_id: str = "HTTP-001") -> Finding:
    return Finding(
        id=rule_id,
        title="t",
        severity=severity,
        confidence=Confidence.HIGH,
        evidence=Evidence("missing_response_header", "x"),
        recommendation="r",
    )


FULL_CONFIG = """
[policy]
fail_on = "medium"

[rules.HTTP-001]
severity = "HIGH"

[rules.HTTP-005]
enabled = false

[rules.HTTP-004]
enabled = true
"""


# --- parsing: valid input --------------------------------------------------


def test_empty_config_is_the_default_policy():
    policy = parse("")

    assert policy == Policy()
    assert policy.is_default
    assert not policy.affects_findings


def test_full_config_is_parsed():
    policy = parse(FULL_CONFIG, source="sentrix.toml")

    assert policy.source == "sentrix.toml"
    assert policy.fail_on is Severity.MEDIUM
    assert policy.disabled_rules == ("HTTP-005",)
    assert dict(policy.severity_overrides) == {"HTTP-001": Severity.HIGH}
    assert policy.affects_findings
    assert not policy.is_default


@pytest.mark.parametrize("spelling", ["high", "High", "HIGH", "  hIgH "])
def test_severity_is_case_insensitive(spelling):
    policy = parse(f'[rules.HTTP-003]\nseverity = "{spelling}"')

    assert policy.severity_overrides == {"HTTP-003": Severity.HIGH}


def test_override_equal_to_the_builtin_severity_is_not_recorded():
    builtin = next(rule for rule in RULES if rule.id == "HTTP-001").severity

    policy = parse(f'[rules.HTTP-001]\nseverity = "{builtin.value}"')

    assert policy.severity_overrides == {}
    assert not policy.affects_findings
    assert policy.rule_policy_json() is None


def test_explicit_enabled_true_changes_nothing():
    policy = parse("[rules.HTTP-001]\nenabled = true")

    assert not policy.affects_findings


def test_empty_rule_table_is_allowed():
    assert not parse("[rules.HTTP-001]").affects_findings


def test_disabled_rules_and_overrides_are_sorted_regardless_of_file_order():
    policy = parse(
        """
        [rules.HTTP-005]
        enabled = false
        [rules.HTTP-002]
        enabled = false
        [rules.HTTP-004]
        severity = "HIGH"
        [rules.HTTP-003]
        severity = "HIGH"
        """
    )

    assert policy.disabled_rules == ("HTTP-002", "HTTP-005")
    assert list(policy.severity_overrides) == ["HTTP-003", "HTTP-004"]


# --- parsing: strictness ---------------------------------------------------


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        # typos must not be silently ignored
        ("[rule.HTTP-001]\nenabled = false", "rule"),
        ("[policy]\nfail-on = 'HIGH'", "fail-on"),
        ("[rules.HTTP-001]\nenabeld = false", "enabeld"),
        ("[rules.HTTP-001]\nseverty = 'HIGH'", "severty"),
        ("surprise = 1", "surprise"),
        # unknown rule ids, with the valid ones listed
        ("[rules.HTTP-999]\nenabled = false", "HTTP-999"),
        ("[rules.http-001]\nenabled = false", "http-001"),
        # wrong types
        ("[rules.HTTP-001]\nenabled = 'false'", "enabled"),
        ("[rules.HTTP-001]\nenabled = 0", "enabled"),
        ("[rules.HTTP-001]\nseverity = 3", "severity"),
        ("[rules.HTTP-001]\nseverity = ['HIGH']", "severity"),
        ("[policy]\nfail_on = true", "fail_on"),
        # invalid severity values
        ("[rules.HTTP-001]\nseverity = 'CRITICAL'", "CRITICAL"),
        ("[rules.HTTP-001]\nseverity = ''", "severity"),
        ("[policy]\nfail_on = 'none'", "none"),
        ("[policy]\nfail_on = 'ınfo'", "fail_on"),  # dotless i
        # not tables
        ("policy = 3", "[policy]"),
        ("rules = ['HTTP-001']", "[rules]"),
        ("[rules]\nHTTP-001 = false", "[rules.HTTP-001]"),
        # contradictory
        ("[rules.HTTP-001]\nenabled = false\nseverity = 'LOW'", "pilih salah satu"),
    ],
)
def test_invalid_policies_are_rejected_with_a_useful_message(text, fragment):
    with pytest.raises(PolicyError) as excinfo:
        parse(text)

    assert fragment in str(excinfo.value)


def test_unknown_rule_error_lists_the_valid_rule_ids():
    with pytest.raises(PolicyError) as excinfo:
        parse("[rules.HTTP-999]\nenabled = false")

    message = str(excinfo.value)
    for rule in RULES:
        assert rule.id in message


def test_unknown_key_error_lists_the_valid_keys():
    with pytest.raises(PolicyError) as excinfo:
        parse("[rules.HTTP-001]\nenabeld = false")

    assert "enabled" in str(excinfo.value)
    assert "severity" in str(excinfo.value)


def test_overlong_values_are_shortened_in_messages():
    with pytest.raises(PolicyError) as excinfo:
        parse("[rules.HTTP-001]\nseverity = '" + "x" * 500 + "'")

    assert len(str(excinfo.value)) < 250


def test_custom_rule_sets_are_validated_against_their_own_ids():
    only = (RULES[0],)

    assert parse(f"[rules.{only[0].id}]\nenabled = false", rules=only)
    with pytest.raises(PolicyError):
        parse("[rules.HTTP-002]\nenabled = false", rules=only)


# --- loading files ---------------------------------------------------------


def test_load_policy_reads_a_file_and_keeps_only_its_name(tmp_path):
    nested = tmp_path / "deep" / "dir"
    nested.mkdir(parents=True)
    path = write(nested, FULL_CONFIG)

    policy = load_policy(path)

    assert policy.source == "sentrix.toml"
    assert "deep" not in json.dumps(policy.to_report_dict())


def test_load_policy_accepts_a_utf8_bom(tmp_path):
    # Windows Notepad and PowerShell 5 write one.
    path = write(tmp_path, b"\xef\xbb\xbf" + FULL_CONFIG.encode("utf-8"))

    assert load_policy(path).fail_on is Severity.MEDIUM


def test_load_policy_rejects_utf16(tmp_path):
    # What `echo ... > sentrix.toml` produces in Windows PowerShell 5.
    path = write(tmp_path, FULL_CONFIG.encode("utf-16"))

    with pytest.raises(PolicyError, match="UTF-8"):
        load_policy(path)


def test_load_policy_missing_file(tmp_path):
    with pytest.raises(PolicyError, match="tidak bisa dibaca"):
        load_policy(tmp_path / "nope.toml")


def test_load_policy_on_a_directory(tmp_path):
    with pytest.raises(PolicyError, match="tidak bisa dibaca"):
        load_policy(tmp_path)


def test_load_policy_reports_toml_syntax_errors_with_a_location(tmp_path):
    path = write(tmp_path, "[policy\nfail_on = 'HIGH'")

    with pytest.raises(PolicyError, match="TOML tidak valid") as excinfo:
        load_policy(path)

    assert "line" in str(excinfo.value)


def test_load_policy_rejects_duplicate_keys(tmp_path):
    path = write(tmp_path, "[policy]\nfail_on = 'HIGH'\nfail_on = 'LOW'")

    with pytest.raises(PolicyError, match="TOML tidak valid"):
        load_policy(path)


def test_load_policy_size_limit_is_enforced_exactly(tmp_path):
    at_limit = write(tmp_path, b"#" * MAX_CONFIG_BYTES, "ok.toml")
    over_limit = write(tmp_path, b"#" * (MAX_CONFIG_BYTES + 1), "big.toml")

    assert load_policy(at_limit) == Policy(source="ok.toml")
    with pytest.raises(PolicyError, match="terlalu besar"):
        load_policy(over_limit)


# --- applying --------------------------------------------------------------


def test_apply_policy_with_default_policy_changes_nothing():
    assert apply_policy(RULES, Policy()) == RULES


def test_apply_policy_removes_disabled_rules_and_keeps_order():
    effective = apply_policy(RULES, parse("[rules.HTTP-002]\nenabled = false"))

    assert [rule.id for rule in effective] == [
        rule.id for rule in RULES if rule.id != "HTTP-002"
    ]


def test_apply_policy_overrides_severity_without_touching_the_originals():
    before = {rule.id: rule.severity for rule in RULES}

    effective = apply_policy(
        RULES, parse('[rules.HTTP-005]\nseverity = "HIGH"')
    )

    assert {rule.id: rule for rule in effective}["HTTP-005"].severity is (
        Severity.HIGH
    )
    assert {rule.id: rule.severity for rule in RULES} == before
    other = {rule.id: rule for rule in effective}["HTTP-001"]
    assert other is next(rule for rule in RULES if rule.id == "HTTP-001")


def test_apply_policy_keeps_every_other_rule_attribute():
    original = next(rule for rule in RULES if rule.id == "HTTP-002")

    changed = apply_policy(
        RULES, parse('[rules.HTTP-002]\nseverity = "LOW"')
    )[1]

    assert changed.id == original.id
    assert changed.header == original.header
    assert changed.title == original.title
    assert changed.recommendation == original.recommendation
    assert changed.https_only is original.https_only


def test_policy_changes_the_findings_a_scan_produces():
    headers = httpx.Headers({})
    policy = parse(
        """
        [rules.HTTP-005]
        enabled = false
        [rules.HTTP-001]
        severity = "HIGH"
        """
    )

    default = {
        f.id: f for f in cli.evaluate_findings(headers, is_https=True)
    }
    custom = {
        f.id: f
        for f in cli.evaluate_findings(
            headers, is_https=True, rules=apply_policy(RULES, policy)
        )
    }

    assert "HTTP-005" in default and "HTTP-005" not in custom
    assert default["HTTP-001"].severity is Severity.MEDIUM
    assert custom["HTTP-001"].severity is Severity.HIGH
    # Re-triage must not make the same observation look like a new one.
    assert custom["HTTP-001"].fingerprint == default["HTTP-001"].fingerprint


# --- gate ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [
        (Severity.HIGH, False),
        (Severity.MEDIUM, True),
        (Severity.LOW, True),
        (Severity.INFO, True),
        (None, False),
    ],
)
def test_gate_with_a_medium_finding(threshold, expected):
    assert gate_failed([finding(Severity.MEDIUM)], threshold) is expected


def test_gate_considers_every_finding_not_just_the_first():
    findings = [finding(Severity.INFO), finding(Severity.HIGH, "HTTP-002")]

    assert gate_failed(findings, Severity.HIGH) is True


def test_gate_with_no_findings_never_fails():
    for threshold in Severity:
        assert gate_failed([], threshold) is False


def test_gate_accepts_a_generator():
    assert gate_failed((f for f in [finding(Severity.LOW)]), Severity.LOW)


# --- reporting forms -------------------------------------------------------


def test_report_dict_shape_for_the_default_policy():
    assert Policy().to_report_dict() == {
        "source": None,
        "fail_on": None,
        "disabled_rules": [],
        "severity_overrides": {},
    }


def test_report_dict_shape_for_a_full_policy():
    assert parse(FULL_CONFIG, source="sentrix.toml").to_report_dict() == {
        "source": "sentrix.toml",
        "fail_on": "MEDIUM",
        "disabled_rules": ["HTTP-005"],
        "severity_overrides": {"HTTP-001": "HIGH"},
    }


def test_rule_policy_json_is_none_when_nothing_changes_findings():
    assert Policy().rule_policy_json() is None
    assert parse("[policy]\nfail_on = 'HIGH'").rule_policy_json() is None


def test_rule_policy_json_ignores_fail_on_and_source():
    a = parse(FULL_CONFIG, source="a.toml")
    b = parse(
        FULL_CONFIG.replace('"medium"', '"low"'), source="b.toml"
    )

    assert a.rule_policy_json() == b.rule_policy_json()


def test_rule_policy_json_is_canonical():
    a = parse(
        "[rules.HTTP-005]\nenabled = false\n[rules.HTTP-002]\nenabled = false"
    )
    b = parse(
        "[rules.HTTP-002]\nenabled = false\n[rules.HTTP-005]\nenabled = false"
    )

    assert a.rule_policy_json() == b.rule_policy_json()
    assert json.loads(a.rule_policy_json()) == {
        "disabled_rules": ["HTTP-002", "HTTP-005"],
        "severity_overrides": {},
    }


def test_summary_mentions_everything_that_is_configured():
    text = parse(FULL_CONFIG, source="sentrix.toml").summary()

    assert "sentrix.toml" in text
    assert "HTTP-005" in text
    assert "HTTP-001=HIGH" in text
    assert "MEDIUM" in text


def test_summary_without_a_config_file_says_default():
    assert Policy(fail_on=Severity.LOW).summary().startswith("bawaan")


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        (None, "bawaan"),
        ('{"disabled_rules":[],"severity_overrides":{}}', "bawaan"),
        (
            '{"disabled_rules":["HTTP-005"],"severity_overrides":{}}',
            "nonaktif: HTTP-005",
        ),
        (
            '{"disabled_rules":[],"severity_overrides":{"HTTP-001":"HIGH"}}',
            "severity: HTTP-001=HIGH",
        ),
        (
            (
                '{"disabled_rules":["HTTP-005"],'
                '"severity_overrides":{"HTTP-001":"HIGH"}}'
            ),
            "nonaktif: HTTP-005; severity: HTTP-001=HIGH",
        ),
        ("not json", "tidak dikenali"),
        ("[1, 2]", "tidak dikenali"),
        ('{"disabled_rules": "HTTP-005"}', "tidak dikenali"),
        ('{"disabled_rules": [1]}', "tidak dikenali"),
        ('{"severity_overrides": {"HTTP-001": 3}}', "tidak dikenali"),
        ('{"severity_overrides": []}', "tidak dikenali"),
        # A tampered database must not crash the parser or reach the terminal.
        ("[" * 100_000, "tidak dikenali"),
        ('{"disabled_rules": ["\\u001b[31mx"]}', "tidak dikenali"),
        ('{"disabled_rules": ["HTTP 005"]}', "tidak dikenali"),
        ('{"severity_overrides": {"HTTP-001": "HI\\nGH"}}', "tidak dikenali"),
        ('{"disabled_rules": ["A"' + ',"A"' * 60 + "]}", "tidak dikenali"),
        ('{"disabled_rules": ["' + "A" * 65 + '"]}', "tidak dikenali"),
        (
            '{"severity_overrides": {'
            + ",".join(f'"R{i}": "HIGH"' for i in range(51))
            + "}}",
            "tidak dikenali",
        ),
    ],
)
def test_describe_rule_policy(stored, expected):
    assert describe_rule_policy(stored) == expected


def test_describe_round_trips_what_rule_policy_json_writes():
    policy = parse(FULL_CONFIG)

    assert describe_rule_policy(policy.rule_policy_json()) == (
        "nonaktif: HTTP-005; severity: HTTP-001=HIGH"
    )


def test_deeply_nested_toml_is_a_policy_error_not_a_crash(tmp_path):
    # Far below the size limit, yet deep enough to overflow the parser stack.
    nested = "a = " + "[" * 20_000 + "]" * 20_000
    assert len(nested) < MAX_CONFIG_BYTES

    with pytest.raises(PolicyError, match="bersarang"):
        load_policy(write(tmp_path, nested))


def test_unknown_key_list_is_capped(tmp_path):
    keys = "\n".join(f"k{i} = 1" for i in range(3000))

    with pytest.raises(PolicyError) as caught:
        load_policy(write(tmp_path, "[policy]\n" + keys))

    message = str(caught.value)
    assert "(+2990 lainnya)" in message
    assert len(message) < 600


def test_control_characters_in_a_key_never_reach_the_message(tmp_path):
    config = '[policy]\n"\\u001b[31mred" = 1'

    with pytest.raises(PolicyError) as caught:
        load_policy(write(tmp_path, config))

    assert "\x1b" not in str(caught.value)
    assert "red" in str(caught.value)
