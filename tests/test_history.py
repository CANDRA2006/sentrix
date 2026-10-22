import os
import sqlite3
import sys
import threading
from pathlib import Path

import httpx
import pytest

from sentrix.history import (
    DB_ENV_VAR,
    SCHEMA_VERSION,
    HistoryError,
    compare_scans,
    default_db_path,
    get_findings,
    get_scan,
    list_scans,
    open_history,
    sanitize_url,
    save_scan,
)
from sentrix.models import Confidence, Evidence, Finding, Severity
from sentrix.normalize import normalize_findings
from sentrix.rules import evaluate_headers

ALL_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "history.db"


def findings_for(headers: dict[str, str]) -> list[Finding]:
    return normalize_findings(
        evaluate_headers(httpx.Headers(headers), is_https=True)
    )


def store(
    conn: sqlite3.Connection,
    findings: list[Finding],
    *,
    target: str = "https://example.com",
    scanned_at: str = "2026-10-21T00:00:00+00:00",
) -> int:
    return save_scan(
        conn,
        target=target,
        final_url=target,
        scanned_at=scanned_at,
        status_code=200,
        tool_version="0.1.0",
        findings=findings,
    )


# --- sanitize_url ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://example.com", "https://example.com"),
        ("https://example.com/a/b", "https://example.com/a/b"),
        ("https://example.com/a?token=SECRET#frag", "https://example.com/a"),
        ("https://user:pw@example.com/a", "https://example.com/a"),
        ("http://localhost:3000/x?y=1", "http://localhost:3000/x"),
        ("http://[::1]:8080/p?q=1", "http://[::1]:8080/p"),
    ],
)
def test_sanitize_url(raw, expected):
    assert sanitize_url(raw) == expected


# --- default_db_path ------------------------------------------------------


def test_default_db_path_uses_env_override(monkeypatch, tmp_path):
    target = tmp_path / "custom.db"
    monkeypatch.setenv(DB_ENV_VAR, str(target))

    assert default_db_path() == target


def test_default_db_path_falls_back_to_home(monkeypatch):
    monkeypatch.delenv(DB_ENV_VAR, raising=False)

    assert default_db_path() == Path.home() / ".sentrix" / "history.db"


# --- storage --------------------------------------------------------------


def test_save_and_read_back_scan(db_path):
    findings = findings_for({})

    with open_history(db_path) as conn:
        scan_id = store(conn, findings)

    with open_history(db_path) as conn:
        scan = get_scan(conn, scan_id)
        stored = get_findings(conn, scan_id)

    assert scan.target == "https://example.com"
    assert scan.status_code == 200
    assert scan.finding_count == 5
    assert {f.fingerprint for f in stored} == {f.fingerprint for f in findings}


def test_stored_findings_are_ordered_by_severity_then_rule(db_path):
    with open_history(db_path) as conn:
        scan_id = store(conn, findings_for({}))
        stored = get_findings(conn, scan_id)

    keys = [(f.severity.rank, f.rule_id) for f in stored]
    assert keys == sorted(keys)


def test_urls_are_sanitized_before_storage(db_path):
    with open_history(db_path) as conn:
        scan_id = save_scan(
            conn,
            target="https://example.com/p?token=SECRET",
            final_url="https://u:pw@example.com/q?x=SECRET#frag",
            scanned_at="2026-10-21T00:00:00+00:00",
            status_code=200,
            tool_version="0.1.0",
            findings=[],
        )

    raw = sqlite3.connect(db_path)
    try:
        dump = "\n".join(raw.iterdump())
    finally:
        raw.close()

    with open_history(db_path) as conn:
        scan = get_scan(conn, scan_id)

    assert scan.target == "https://example.com/p"
    assert scan.final_url == "https://example.com/q"
    assert "SECRET" not in dump
    assert "pw" not in scan.final_url


def test_header_values_are_never_stored(db_path):
    headers = {"Set-Cookie": "session=TOP-SECRET-VALUE"}

    with open_history(db_path) as conn:
        store(conn, findings_for(headers))

    assert b"TOP-SECRET-VALUE" not in db_path.read_bytes()


def test_duplicate_fingerprints_in_one_scan_are_stored_once(db_path):
    one = findings_for({})[0]

    with open_history(db_path) as conn:
        scan_id = store(conn, [one, one])
        assert get_scan(conn, scan_id).finding_count == 1


def test_list_scans_is_newest_first_and_respects_limit(db_path):
    with open_history(db_path) as conn:
        ids = [store(conn, [], scanned_at=f"2026-10-2{n}") for n in range(1, 4)]

    with open_history(db_path) as conn:
        assert [s.id for s in list_scans(conn)] == list(reversed(ids))
        assert [s.id for s in list_scans(conn, limit=2)] == ids[:0:-1]


def test_list_scans_on_empty_database(db_path):
    with open_history(db_path) as conn:
        assert list_scans(conn) == []


def test_scan_with_no_findings_has_zero_count(db_path):
    with open_history(db_path) as conn:
        scan_id = store(conn, [])

        assert get_scan(conn, scan_id).finding_count == 0
        assert get_findings(conn, scan_id) == []


def test_get_scan_unknown_id_raises(db_path):
    with open_history(db_path) as conn:
        with pytest.raises(HistoryError, match="999"):
            get_scan(conn, 999)


def test_open_history_creates_parent_directories(tmp_path):
    nested = tmp_path / "a" / "b" / "history.db"

    with open_history(nested):
        pass

    assert nested.exists()


def test_exception_inside_context_rolls_back(db_path):
    with pytest.raises(RuntimeError):
        with open_history(db_path) as conn:
            store(conn, findings_for({}))
            raise RuntimeError("boom")

    with open_history(db_path) as conn:
        assert list_scans(conn) == []


# --- schema handling ------------------------------------------------------


def test_new_database_gets_current_schema_version(db_path):
    with open_history(db_path):
        pass

    raw = sqlite3.connect(db_path)
    try:
        version = raw.execute("PRAGMA user_version").fetchone()[0]
    finally:
        raw.close()

    assert version == SCHEMA_VERSION


def test_reopening_existing_database_keeps_data(db_path):
    with open_history(db_path) as conn:
        store(conn, findings_for({}))

    with open_history(db_path) as conn:
        assert len(list_scans(conn)) == 1


def test_database_from_newer_schema_is_rejected(db_path):
    raw = sqlite3.connect(db_path)
    try:
        raw.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
        raw.commit()
    finally:
        raw.close()

    with pytest.raises(HistoryError, match="lebih baru"):
        with open_history(db_path):
            pass


def test_unrelated_sqlite_file_is_not_adopted(db_path):
    raw = sqlite3.connect(db_path)
    try:
        raw.execute("CREATE TABLE other (x INTEGER)")
        raw.commit()
    finally:
        raw.close()

    with pytest.raises(HistoryError, match="bukan riwayat"):
        with open_history(db_path):
            pass


def test_non_sqlite_file_raises_history_error(db_path):
    db_path.write_bytes(b"this is definitely not a sqlite database" * 20)

    with pytest.raises(HistoryError):
        with open_history(db_path):
            pass


# --- compare --------------------------------------------------------------


def test_compare_identical_scans_has_no_changes(db_path):
    with open_history(db_path) as conn:
        a = store(conn, findings_for({}))
        b = store(conn, findings_for({}))
        diff = compare_scans(conn, a, b)

    assert diff.appeared == ()
    assert diff.resolved == ()
    assert diff.severity_changed == ()
    assert len(diff.unchanged) == 5
    assert diff.same_target


def test_compare_reports_resolved_appeared_and_unchanged(db_path):
    # old scan is missing CSP (001) and HSTS (002)
    old_headers = {
        k: v for k, v in ALL_HEADERS.items()
        if k not in {"Content-Security-Policy", "Strict-Transport-Security"}
    }
    # new scan is missing HSTS (002) and Referrer-Policy (004)
    new_headers = {
        k: v for k, v in ALL_HEADERS.items()
        if k not in {"Strict-Transport-Security", "Referrer-Policy"}
    }

    with open_history(db_path) as conn:
        old_id = store(conn, findings_for(old_headers))
        new_id = store(conn, findings_for(new_headers))
        diff = compare_scans(conn, old_id, new_id)

    assert {f.rule_id for f in diff.appeared} == {"HTTP-004"}
    assert {f.rule_id for f in diff.resolved} == {"HTTP-001"}
    assert {f.rule_id for f in diff.unchanged} == {"HTTP-002"}
    assert diff.severity_changed == ()


def test_compare_is_directional(db_path):
    with open_history(db_path) as conn:
        bad = store(conn, findings_for({}))
        good = store(conn, findings_for(ALL_HEADERS))
        improved = compare_scans(conn, bad, good)
        regressed = compare_scans(conn, good, bad)

    assert len(improved.resolved) == 5 and improved.appeared == ()
    assert len(regressed.appeared) == 5 and regressed.resolved == ()


def test_compare_detects_severity_change_for_same_fingerprint(db_path):
    base = findings_for({})[0]
    escalated = Finding(
        id=base.id,
        title=base.title,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=Evidence(base.evidence.type, base.evidence.header),
        recommendation=base.recommendation,
    )
    assert escalated.fingerprint == base.fingerprint

    with open_history(db_path) as conn:
        old_id = store(conn, [base])
        new_id = store(conn, [escalated])
        diff = compare_scans(conn, old_id, new_id)

    assert diff.appeared == () and diff.resolved == () and diff.unchanged == ()
    assert len(diff.severity_changed) == 1
    change = diff.severity_changed[0]
    assert change.before.severity is base.severity
    assert change.after.severity is Severity.HIGH


def test_compare_flags_different_targets(db_path):
    with open_history(db_path) as conn:
        a = store(conn, [], target="https://a.example")
        b = store(conn, [], target="https://b.example")
        diff = compare_scans(conn, a, b)

    assert not diff.same_target


def test_compare_unknown_id_raises(db_path):
    with open_history(db_path) as conn:
        a = store(conn, [])

        with pytest.raises(HistoryError):
            compare_scans(conn, a, a + 100)
        with pytest.raises(HistoryError):
            compare_scans(conn, a + 100, a)


# --- file permissions and concurrent initialisation -----------------------


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX permission bits only"
)
def test_new_database_file_is_owner_only(db_path):
    with open_history(db_path):
        pass

    assert (db_path.stat().st_mode & 0o777) == 0o600


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX permission bits only"
)
def test_existing_database_permissions_are_not_changed(db_path):
    db_path.touch()
    os.chmod(db_path, 0o640)

    with open_history(db_path):
        pass

    assert (db_path.stat().st_mode & 0o777) == 0o640


def test_concurrent_first_open_does_not_race(db_path):
    workers = 6
    barrier = threading.Barrier(workers)
    errors: list[BaseException] = []

    def first_open() -> None:
        try:
            barrier.wait(timeout=5)
            with open_history(db_path) as conn:
                store(conn, [])
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=first_open) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)

    assert errors == []
    with open_history(db_path) as conn:
        assert len(list_scans(conn)) == workers


def test_failed_schema_init_leaves_database_untouched(db_path):
    raw = sqlite3.connect(db_path)
    try:
        raw.execute("CREATE TABLE other (x INTEGER)")
        raw.commit()
    finally:
        raw.close()

    with pytest.raises(HistoryError):
        with open_history(db_path):
            pass

    raw = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in raw.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        version = raw.execute("PRAGMA user_version").fetchone()[0]
    finally:
        raw.close()

    assert tables == {"other"}
    assert version == 0
