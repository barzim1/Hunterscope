"""SQLite case store: what was triaged, what was decided, what is still open.

Single-writer, local file (stdlib sqlite3). Do not put it on a network share.
It holds real, un-redacted data: treat the file like the logs it came from.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hunterscope.models import Finding, host_key, user_key
from hunterscope.triage import Dossier

SCHEMA_VERSION = 1

STATUSES = {
    "new": "New",
    "in_progress": "In progress",
    "escalated_l2": "Escalated to L2",
    "escalated_l3": "Escalated to L3",
    "closed_fp": "Closed - False Positive",
    "closed_tp": "Closed - True Positive",
}
CLOSED = {"closed_fp", "closed_tp"}
ESCALATED = {"escalated_l2", "escalated_l3"}
NOTE_REQUIRED = CLOSED | ESCALATED  # a decision needs a reason the next shift can read

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL, target TEXT NOT NULL, target_key TEXT NOT NULL,
  status TEXT NOT NULL, score INTEGER NOT NULL, level TEXT NOT NULL,
  window_since TEXT, window_until TEXT,
  opened_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_target ON cases(kind, target_key, status);
CREATE TABLE IF NOT EXISTS case_findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
  mitre TEXT NOT NULL, description TEXT NOT NULL, first_seen TEXT NOT NULL, added_at TEXT NOT NULL,
  UNIQUE(case_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS case_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  ts TEXT NOT NULL, author TEXT NOT NULL, kind TEXT NOT NULL,
  from_status TEXT, to_status TEXT, text TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_log_case ON case_log(case_id, ts);
"""


def default_db_path() -> Path:
    env = os.environ.get("HUNTERSCOPE_DB")
    return Path(env) if env else Path.home() / ".hunterscope" / "cases.db"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """One canonical text format so string comparison in SQL equals time comparison."""
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def fingerprint(f: Finding) -> str:
    parts = sorted(f"{e.source}:{e.action}:{iso(e.ts)}:{e.ip}:{e.user}" for e in f.evidence)
    return hashlib.sha256("|".join([f.rule_id, *parts]).encode()).hexdigest()[:16]


def target_key(kind: str, target: str) -> str:
    return user_key(target) if kind == "user" else host_key(target)


@dataclass(frozen=True)
class Case:
    id: int
    kind: str
    target: str
    target_key: str
    status: str
    score: int
    level: str
    window_since: str | None
    window_until: str | None
    opened_at: datetime
    updated_at: datetime

    @property
    def status_label(self) -> str:
        return STATUSES[self.status]

    @property
    def is_closed(self) -> bool:
        return self.status in CLOSED


@dataclass(frozen=True)
class LogEntry:
    ts: datetime
    author: str
    kind: str
    from_status: str | None
    to_status: str | None
    text: str


@dataclass(frozen=True)
class TriageResult:
    case_id: int
    created: bool
    new_findings: int


def _case(row: sqlite3.Row) -> Case:
    return Case(
        id=row["id"], kind=row["kind"], target=row["target"], target_key=row["target_key"],
        status=row["status"], score=row["score"], level=row["level"],
        window_since=row["window_since"], window_until=row["window_until"],
        opened_at=parse_iso(row["opened_at"]), updated_at=parse_iso(row["updated_at"]),
    )


def _entry(row: sqlite3.Row) -> LogEntry:
    return LogEntry(parse_iso(row["ts"]), row["author"], row["kind"], row["from_status"],
                    row["to_status"], row["text"])


class CaseStore:
    def __init__(self, path: Path | str) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path))
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"case database is newer (v{version}) than this HunterScope (v{SCHEMA_VERSION})")
        with self._db:
            self._db.executescript(_SCHEMA)
            self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def __enter__(self) -> CaseStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._db.close()

    # ------------------------------------------------------------------ writes

    def _log(self, case_id: int, now: datetime, author: str, kind: str, text: str = "",
             from_status: str | None = None, to_status: str | None = None) -> None:
        self._db.execute(
            "INSERT INTO case_log(case_id, ts, author, kind, from_status, to_status, text) VALUES (?,?,?,?,?,?,?)",
            (case_id, iso(now), author, kind, from_status, to_status, text),
        )

    def upsert_from_dossier(self, d: Dossier, author: str, now: datetime | None = None) -> TriageResult:
        """Update the open case for this target, or open a new one. Closed cases are never reopened."""
        now = now or utcnow()
        key = target_key(d.kind, d.target)
        placeholders = ",".join("?" for _ in CLOSED)
        row = self._db.execute(
            f"SELECT * FROM cases WHERE kind=? AND target_key=? AND status NOT IN ({placeholders}) "
            "ORDER BY id DESC LIMIT 1",
            (d.kind, key, *sorted(CLOSED)),
        ).fetchone()
        with self._db:
            if row is None:
                case_id = self._db.execute(
                    "INSERT INTO cases(kind, target, target_key, status, score, level, window_since, window_until, "
                    "opened_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (d.kind, d.target, key, "new", d.score.total, d.score.level, iso(d.since), iso(d.until),
                     iso(now), iso(now)),
                ).lastrowid
                assert case_id is not None
            else:
                case_id = row["id"]
                self._db.execute(
                    "UPDATE cases SET score=?, level=?, window_since=?, window_until=?, updated_at=? WHERE id=?",
                    (d.score.total, d.score.level, iso(d.since), iso(d.until), iso(now), case_id),
                )
            added = 0
            for f in d.findings:
                cur = self._db.execute(
                    "INSERT OR IGNORE INTO case_findings(case_id, fingerprint, rule_id, title, severity, mitre, "
                    "description, first_seen, added_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (case_id, fingerprint(f), f.rule_id, f.title, f.severity, ",".join(f.mitre),
                     f.description, iso(f.ts), iso(now)),
                )
                added += cur.rowcount
            if row is None:
                text = f"Case opened from triage: score {d.score.total}/100 ({d.score.level}), {added} finding(s)"
            else:
                text = (f"Re-triaged: score {row['score']} -> {d.score.total}/100 ({d.score.level}), "
                        f"{added} new finding(s)")
            self._log(case_id, now, author, "triage", text)
        return TriageResult(case_id, row is None, added)

    def set_status(self, case_id: int, status: str, author: str, note: str = "",
                   now: datetime | None = None) -> None:
        now = now or utcnow()
        if status not in STATUSES:
            raise ValueError(f"unknown status '{status}' (use: {', '.join(STATUSES)})")
        case = self.get_case(case_id)
        if case.is_closed:
            raise ValueError(f"case {case_id} is {case.status_label}; closed cases are immutable "
                             "(a new triage with --save opens a fresh case)")
        if status == case.status:
            raise ValueError(f"case {case_id} is already {case.status_label}")
        if status in NOTE_REQUIRED and not note.strip():
            raise ValueError(f"--note is required for '{status}': the next shift needs the reason")
        with self._db:
            self._db.execute("UPDATE cases SET status=?, updated_at=? WHERE id=?", (status, iso(now), case_id))
            self._log(case_id, now, author, "status", note.strip(), case.status, status)

    def add_note(self, case_id: int, author: str, text: str, now: datetime | None = None) -> None:
        now = now or utcnow()
        if not text.strip():
            raise ValueError("empty note")
        self.get_case(case_id)  # existence check
        with self._db:
            self._db.execute("UPDATE cases SET updated_at=? WHERE id=?", (iso(now), case_id))
            self._log(case_id, now, author, "note", text.strip())

    # ------------------------------------------------------------------- reads

    def get_case(self, case_id: int) -> Case:
        row = self._db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise KeyError(f"no case #{case_id}")
        return _case(row)

    def list_cases(self, open_only: bool = False) -> list[Case]:
        sql = "SELECT * FROM cases"
        args: tuple[Any, ...] = ()
        if open_only:
            sql += f" WHERE status NOT IN ({','.join('?' for _ in CLOSED)})"
            args = tuple(sorted(CLOSED))
        return [_case(r) for r in self._db.execute(sql + " ORDER BY id", args)]

    def findings(self, case_id: int) -> list[dict[str, Any]]:
        rows = self._db.execute("SELECT * FROM case_findings WHERE case_id=? ORDER BY first_seen, id", (case_id,))
        return [dict(r) for r in rows]

    def log(self, case_id: int) -> list[LogEntry]:
        rows = self._db.execute("SELECT * FROM case_log WHERE case_id=? ORDER BY ts, id", (case_id,))
        return [_entry(r) for r in rows]

    def status_changes_between(self, since: datetime, until: datetime) -> list[tuple[int, LogEntry]]:
        rows = self._db.execute(
            "SELECT * FROM case_log WHERE kind='status' AND ts > ? AND ts <= ? ORDER BY ts, id",
            (iso(since), iso(until)),
        )
        return [(r["case_id"], _entry(r)) for r in rows]
