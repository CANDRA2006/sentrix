"""Local scan history backed by SQLite, plus comparison between two scans.

Design notes:

* Only data that is already in the JSON report is stored. Response header
  *values* are never stored, and URLs are stored without userinfo, query
  string, or fragment, since those parts commonly carry secrets.
* Findings are matched across scans by ``Finding.fingerprint``, which is
  independent of wording and severity.
* Each scan also stores the rule policy it ran under (``None`` for the
  default rules). A rule that was switched off produces no finding, so
  without this ``compare`` would report it as "resolved".
* The schema is versioned with ``PRAGMA user_version``. Older databases are
  migrated in place, inside one transaction; newer ones are refused.
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

SCHEMA_VERSION = 2
DB_ENV_VAR = "SENTRIX_DB"

_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE scans (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        target        TEXT    NOT NULL,
        final_url     TEXT    NOT NULL,
        scanned_at    TEXT    NOT NULL,
        status_code   INTEGER NOT NULL,
        tool_version  TEXT    NOT NULL,
        policy        TEXT
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

# Statements that upgrade a database *from* the given version by one step.
# Version 1 -> 2: scans remember the rule policy they ran under. The new
# column is nullable, and NULL means "default rules", which is exactly what
# every scan stored before policies existed ran with.
_MIGRATIONS: dict[int, tuple[str, ...]] = {
    1: ("ALTER TABLE scans ADD COLUMN policy TEXT",),
}

# Columns each table must have before a migration *from* that version is
# allowed to touch the file. ``user_version`` alone is not proof that a file
# is a SENTRIX history: any SQLite database can carry the number 1.
_EXPECTED_COLUMNS: dict[int, dict[str, frozenset[str]]] = {
    1: {
        "scans": frozenset(
            {"id", "target", "final_url", "scanned_at", "status_code",
             "tool_version"}
        ),
        "scan_findings": frozenset(
            {"scan_id", "fingerprint", "rule_id", "title", "severity",
             "confidence", "header"}
        ),
    },
}


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
    policy: str | None = None


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

    @property
    def same_policy(self) -> bool:
        """False if the scans ran with different rules or severities."""
        return self.old.policy == self.new.policy


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


def _newer_schema_error(version: int) -> HistoryError:
    return HistoryError(
        "Database riwayat dibuat oleh versi SENTRIX yang lebih baru "
        f"(schema {version}, didukung {SCHEMA_VERSION})."
    )


def _ensure_schema(conn: sqlite3.Connection) -> None:
    version = _user_version(conn)

    if version == SCHEMA_VERSION:
        return

    if version > SCHEMA_VERSION:
        raise _newer_schema_error(version)

    # Fresh or older database. Take the write lock first and re-check, so two
    # SENTRIX processes starting at the same time cannot both create tables
    # or both try to migrate. DDL and ``user_version`` are transactional in
    # SQLite, so a failure anywhere below leaves the file exactly as it was.
    conn.execute("BEGIN IMMEDIATE")
    try:
        version = _user_version(conn)
        if version == SCHEMA_VERSION:  # another process won the race
            conn.rollback()
            return
        if version > SCHEMA_VERSION:
            raise _newer_schema_error(version)

        if version == 0:
            _create_schema(conn)
        else:
            _migrate(conn, version)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def _create_schema(conn: sqlite3.Connection) -> None:
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


def _check_shape(conn: sqlite3.Connection, version: int) -> None:
    """Refuse to migrate a file whose tables are not SENTRIX's."""
    expected = _EXPECTED_COLUMNS.get(version)
    if expected is None:
        return
    for table, columns in expected.items():
        # ``table`` comes from the constant above, never from user input.
        found = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if found != columns:
            raise HistoryError(
                f"File database bertanda schema {version} tetapi tabel "
                f"'{table}' bukan milik riwayat SENTRIX; file tidak diubah. "
                "Gunakan path lain."
            )


def _migrate(conn: sqlite3.Connection, version: int) -> None:
    _check_shape(conn, version)
    while version < SCHEMA_VERSION:
        statements = _MIGRATIONS.get(version)
        if statements is None:
            raise HistoryError(
                f"Versi schema database riwayat tidak dikenali ({version})."
            )
        for statement in statements:
            conn.execute(statement)
        version += 1
    # PRAGMA does not accept bound parameters; SCHEMA_VERSION is a constant.
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def save_scan(
    conn: sqlite3.Connection,
    *,
    target: str,
    final_url: str,
    scanned_at: str,
    status_code: int,
    tool_version: str,
    findings: Sequence[Finding],
    policy: str | None = None,
) -> int:
    """Store one scan and its findings; return the new scan id.

    ``policy`` is ``Policy.rule_policy_json()``: ``None`` means the scan ran
    with the default rules.
    """
    cursor = conn.execute(
        "INSERT INTO scans "
        "(target, final_url, scanned_at, status_code, tool_version, policy) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            sanitize_url(target),
            sanitize_url(final_url),
            scanned_at,
            status_code,
            tool_version,
            policy,
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
       s.tool_version, s.policy, COUNT(f.fingerprint) AS finding_count
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
        policy=row["policy"],
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
