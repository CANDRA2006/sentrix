"""Local scan history backed by SQLite, plus comparison between two scans.

Design notes:

* Only data that is already in the JSON report is stored. Response header
  *values* are never stored, and URLs are stored without userinfo, query
  string, or fragment, since those parts commonly carry secrets.
* Findings are matched across scans by ``Finding.fingerprint``, which is
  independent of wording and severity.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from sentrix.models import Finding, Severity

SCHEMA_VERSION = 1
DB_ENV_VAR = "SENTRIX_DB"

_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE scans (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        target        TEXT    NOT NULL,
        final_url     TEXT    NOT NULL,
        scanned_at    TEXT    NOT NULL,
        status_code   INTEGER NOT NULL,
        tool_version  TEXT    NOT NULL
    )
    """,
    """
    CREATE TABLE scan_findings (
        scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        fingerprint  TEXT    NOT NULL,
        rule_id      TEXT    NOT NULL,
        title        TEXT    NOT NULL,
        severity     TEXT    NOT NULL,
        confidence   TEXT    NOT NULL,
        header       TEXT    NOT NULL,
        PRIMARY KEY (scan_id, fingerprint)
    )
    """,
    # PRAGMA does not accept bound parameters; SCHEMA_VERSION is a constant.
    f"PRAGMA user_version = {SCHEMA_VERSION}",
)


class HistoryError(Exception):
    """Raised for user-facing history problems (bad id, unusable database)."""


@dataclass(frozen=True, slots=True)
class ScanRecord:
    id: int
    target: str
    final_url: str
    scanned_at: str
    status_code: int
    tool_version: str
    finding_count: int


@dataclass(frozen=True, slots=True)
class StoredFinding:
    fingerprint: str
    rule_id: str
    title: str
    severity: Severity
    confidence: str
    header: str


@dataclass(frozen=True, slots=True)
class SeverityChange:
    before: StoredFinding
    after: StoredFinding


@dataclass(frozen=True, slots=True)
class ScanDiff:
    """Result of comparing an older scan against a newer one."""

    old: ScanRecord
    new: ScanRecord
    appeared: tuple[StoredFinding, ...]
    resolved: tuple[StoredFinding, ...]
    unchanged: tuple[StoredFinding, ...]
    severity_changed: tuple[SeverityChange, ...]

    @property
    def same_target(self) -> bool:
        return self.old.target == self.new.target


def default_db_path() -> Path:
    """``$SENTRIX_DB`` if set, otherwise ``~/.sentrix/history.db``."""
    override = os.environ.get(DB_ENV_VAR)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".sentrix" / "history.db"


def sanitize_url(url: str) -> str:
    """Drop userinfo, query string, and fragment before storing a URL."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:  # IPv6 literal; urlsplit strips the brackets
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _create_private_file(path: Path) -> None:
    """Create the database file owner-only (0600) if it does not exist yet.

    The history lists every target that was scanned, so it should not be
    world-readable. ``sqlite3.connect`` would otherwise create it with the
    process umask (typically 0644). Existing files are left untouched.
    """
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return
    os.close(fd)


@contextmanager
def open_history(path: Path) -> Iterator[sqlite3.Connection]:
    """Open (creating if needed) the history database.

    Commits on success, rolls back on error, and always closes the
    connection (``sqlite3.Connection`` as a context manager does not).
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _create_private_file(path)
        conn = sqlite3.connect(path)
    except (OSError, sqlite3.Error) as exc:
        raise HistoryError(f"Tidak bisa membuka database riwayat: {exc}") from exc

    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        _ensure_schema(conn)
        yield conn
        conn.commit()
    except sqlite3.Error as exc:
        conn.rollback()
        raise HistoryError(f"Database riwayat bermasalah: {exc}") from exc
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _user_version(conn: sqlite3.Connection) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def _ensure_schema(conn: sqlite3.Connection) -> None:
    version = _user_version(conn)

    if version == SCHEMA_VERSION:
        return

    if version > SCHEMA_VERSION:
        raise HistoryError(
            "Database riwayat dibuat oleh versi SENTRIX yang lebih baru "
            f"(schema {version}, didukung {SCHEMA_VERSION})."
        )

    # Fresh database. Take the write lock first and re-check, so two SENTRIX
    # processes starting at the same time cannot both try to create tables.
    conn.execute("BEGIN IMMEDIATE")
    try:
        version = _user_version(conn)
        if version == SCHEMA_VERSION:  # another process won the race
            conn.rollback()
            return

        existing = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' LIMIT 1"
        ).fetchone()
        if existing is not None:
            raise HistoryError(
                "File database sudah berisi tabel lain dan bukan riwayat "
                "SENTRIX; gunakan path lain."
            )

        for statement in _SCHEMA_STATEMENTS:
            conn.execute(statement)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def save_scan(
    conn: sqlite3.Connection,
    *,
    target: str,
    final_url: str,
    scanned_at: str,
    status_code: int,
    tool_version: str,
    findings: Sequence[Finding],
) -> int:
    """Store one scan and its findings; return the new scan id."""
    cursor = conn.execute(
        "INSERT INTO scans "
        "(target, final_url, scanned_at, status_code, tool_version) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            sanitize_url(target),
            sanitize_url(final_url),
            scanned_at,
            status_code,
            tool_version,
        ),
    )
    scan_id = cursor.lastrowid
    assert scan_id is not None

    conn.executemany(
        "INSERT OR IGNORE INTO scan_findings "
        "(scan_id, fingerprint, rule_id, title, severity, confidence, header) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (
                scan_id,
                finding.fingerprint,
                finding.id,
                finding.title,
                finding.severity.value,
                finding.confidence.value,
                finding.evidence.header,
            )
            for finding in findings
        ],
    )
    return scan_id


_SCAN_SELECT = """
SELECT s.id, s.target, s.final_url, s.scanned_at, s.status_code,
       s.tool_version, COUNT(f.fingerprint) AS finding_count
FROM scans AS s
LEFT JOIN scan_findings AS f ON f.scan_id = s.id
"""


def _record(row: sqlite3.Row) -> ScanRecord:
    return ScanRecord(
        id=row["id"],
        target=row["target"],
        final_url=row["final_url"],
        scanned_at=row["scanned_at"],
        status_code=row["status_code"],
        tool_version=row["tool_version"],
        finding_count=row["finding_count"],
    )


def list_scans(conn: sqlite3.Connection, limit: int = 20) -> list[ScanRecord]:
    """Most recent scans first."""
    rows = conn.execute(
        _SCAN_SELECT + "GROUP BY s.id ORDER BY s.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_record(row) for row in rows]


def get_scan(conn: sqlite3.Connection, scan_id: int) -> ScanRecord:
    row = conn.execute(
        _SCAN_SELECT + "WHERE s.id = ? GROUP BY s.id",
        (scan_id,),
    ).fetchone()
    if row is None:
        raise HistoryError(f"Scan dengan id {scan_id} tidak ditemukan.")
    return _record(row)


def get_findings(conn: sqlite3.Connection, scan_id: int) -> list[StoredFinding]:
    rows = conn.execute(
        "SELECT fingerprint, rule_id, title, severity, confidence, header "
        "FROM scan_findings WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
    return _sorted(
        StoredFinding(
            fingerprint=row["fingerprint"],
            rule_id=row["rule_id"],
            title=row["title"],
            severity=Severity(row["severity"]),
            confidence=row["confidence"],
            header=row["header"],
        )
        for row in rows
    )


def _sorted(findings: Iterable[StoredFinding]) -> list[StoredFinding]:
    return sorted(findings, key=lambda f: (f.severity.rank, f.rule_id))


def compare_scans(
    conn: sqlite3.Connection, old_id: int, new_id: int
) -> ScanDiff:
    """Compare two stored scans by finding fingerprint.

    ``appeared`` is present only in the new scan, ``resolved`` only in the
    old one. A fingerprint present in both lands in ``unchanged`` unless its
    severity differs, in which case it is reported in ``severity_changed``.
    """
    old = get_scan(conn, old_id)
    new = get_scan(conn, new_id)

    old_by_fp = {f.fingerprint: f for f in get_findings(conn, old_id)}
    new_by_fp = {f.fingerprint: f for f in get_findings(conn, new_id)}

    appeared = _sorted(
        f for fp, f in new_by_fp.items() if fp not in old_by_fp
    )
    resolved = _sorted(
        f for fp, f in old_by_fp.items() if fp not in new_by_fp
    )

    unchanged: list[StoredFinding] = []
    changed: list[SeverityChange] = []
    for fp, after in new_by_fp.items():
        before = old_by_fp.get(fp)
        if before is None:
            continue
        if before.severity is after.severity:
            unchanged.append(after)
        else:
            changed.append(SeverityChange(before=before, after=after))

    changed.sort(key=lambda c: (c.after.severity.rank, c.after.rule_id))

    return ScanDiff(
        old=old,
        new=new,
        appeared=tuple(appeared),
        resolved=tuple(resolved),
        unchanged=tuple(_sorted(unchanged)),
        severity_changed=tuple(changed),
    )
