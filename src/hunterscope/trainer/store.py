"""Progress store (SQLite). Holds only the analyst's own attempts, never scenario content."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, token TEXT NOT NULL, template TEXT NOT NULL, category TEXT NOT NULL, difficulty INTEGER NOT NULL,
  truth TEXT NOT NULL, verdict TEXT NOT NULL, outcome TEXT NOT NULL, score INTEGER NOT NULL,
  actions TEXT NOT NULL, evidence TEXT NOT NULL, lookups TEXT NOT NULL, hints INTEGER NOT NULL, seconds INTEGER NOT NULL,
  justification TEXT NOT NULL, shift_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_attempts_template ON attempts(template, ts);
"""


def default_db_path() -> Path:
    env = os.environ.get("HUNTERSCOPE_TRAINER_DB")
    return Path(env) if env else Path.home() / ".hunterscope" / "trainer.db"


class TrainerStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._conn()) as c:
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        return c

    def record(self, *, token: str, template: str, category: str, difficulty: int, truth: str, sub: dict, result: dict,
               shift_id: str | None = None) -> None:
        with closing(self._conn()) as c, c:
            c.execute(
                "INSERT INTO attempts(ts,token,template,category,difficulty,truth,verdict,outcome,score,actions,evidence,lookups,hints,"
                "seconds,justification,shift_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"), token, template, category, difficulty, truth, sub["verdict"],
                 result["outcome"], result["score"], json.dumps(sub.get("actions", [])), json.dumps(sub.get("evidence", [])),
                 json.dumps(sub.get("lookups", [])), int(sub.get("hints", 0)), int(sub.get("seconds", 0)), sub.get("justification", ""),
                 shift_id))

    def attempted(self, token: str) -> bool:
        with closing(self._conn()) as c:
            return c.execute("SELECT 1 FROM attempts WHERE token=?", (token,)).fetchone() is not None

    def per_template(self) -> dict[str, dict]:
        with closing(self._conn()) as c:
            rows = c.execute(
                "SELECT template, COUNT(*) n, SUM(outcome='correct') ok, SUM(score) pts FROM attempts GROUP BY template").fetchall()
        return {r["template"]: {"n": r["n"], "correct": r["ok"], "points": r["pts"]} for r in rows}

    def stats(self, titles: dict[str, dict]) -> dict:
        with closing(self._conn()) as c:
            total = c.execute("SELECT COUNT(*) n, COALESCE(SUM(outcome='correct'),0) ok, COALESCE(AVG(score),0) avg, "
                              "COALESCE(AVG(seconds),0) sec FROM attempts").fetchone()
            conf = c.execute("SELECT truth, verdict, COUNT(*) n FROM attempts GROUP BY truth, verdict").fetchall()
            recent = c.execute("SELECT ts, token, template, difficulty, truth, verdict, outcome, score, seconds FROM attempts "
                               "ORDER BY id DESC LIMIT 15").fetchall()
        confusion: dict[str, dict[str, int]] = {t: {"tp": 0, "btp": 0, "fp": 0} for t in ("tp", "btp", "fp")}
        for r in conf:
            confusion[r["truth"]][r["verdict"]] = r["n"]
        missed = sum(confusion["tp"][v] for v in ("btp", "fp"))
        over = confusion["btp"]["tp"] + confusion["fp"]["tp"]
        n_tp = sum(confusion["tp"].values())
        n_benign = sum(sum(confusion[t].values()) for t in ("btp", "fp"))
        per = self.per_template()
        rows = []
        for tid, meta in titles.items():
            p = per.get(tid, {"n": 0, "correct": 0, "points": 0})
            rows.append({"id": tid, "title": meta["title"], "category": meta["category"], "n": p["n"], "correct": p["correct"],
                         "avg": round(p["points"] / p["n"]) if p["n"] else None})
        rows.sort(key=lambda r: (r["n"] == 0, r["avg"] if r["avg"] is not None else 101))
        return {
            "attempts": total["n"], "correct": total["ok"], "avg_score": round(total["avg"]), "avg_seconds": round(total["sec"]),
            "confusion": confusion,
            "bias": {"missed_tp": missed, "over_escalated": over, "tp_total": n_tp, "benign_total": n_benign},
            "templates": rows,
            "recent": [{**dict(r), "template": titles.get(r["template"], {}).get("title", r["template"])} for r in recent],
        }
