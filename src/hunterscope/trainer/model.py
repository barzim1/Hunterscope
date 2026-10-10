"""Data model of a training scenario.

A scenario is what an L1 analyst sees (an alert, log events, some context lookups) plus a `Truth` that never
leaves the server before a verdict is submitted. `Scenario.public()` is the only thing sent to the browser.
"""

from __future__ import annotations

import ntpath
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

TZ = timezone(timedelta(hours=1))  # CET. Scenarios are anchored in winter, so there is no DST shift to explain.
TZ_LABEL = "CET (UTC+1)"

VERDICTS = {
    "tp": "True Positive",
    "btp": "Benign True Positive",
    "fp": "False Positive",
}

ACTIONS = {
    "close": "Zamknij zgłoszenie (bez dalszych działań)",
    "close_tune": "Zamknij + wniosek o strojenie reguły / wyjątek",
    "notify_user": "Skontaktuj się z użytkownikiem / przełożonym",
    "escalate_l2": "Eskaluj do L2 (z notatką)",
    "isolate_host": "Izoluj host (ESET Protect / EDR)",
    "reset_creds": "Zresetuj hasło i unieważnij sesje / tokeny",
    "block_ioc": "Zablokuj IOC (IP, domena, hash) na proxy / FW / ESET",
    "hunt_org": "Sprawdź resztę środowiska pod kątem tych IOC",
    "eset_exception": "Przywróć z kwarantanny i dodaj wyjątek (ESET)",
}

LOOKUP_KINDS = ("asset", "user", "change", "ti")


@dataclass
class Event:
    ts: datetime
    source: str
    host: str = ""
    user: str = ""
    summary: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    raw: str = ""
    id: str = ""
    role: str = ""  # "key" supports the verdict, "herring" looks suspicious (or benign) but is not what decides it
    note: str = ""

    def key(self, note: str) -> Event:
        self.role, self.note = "key", note
        return self

    def herring(self, note: str) -> Event:
        self.role, self.note = "herring", note
        return self

    def public(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts.astimezone(TZ).isoformat(timespec="seconds"),
            "source": self.source,
            "host": self.host,
            "user": self.user,
            "summary": self.summary,
            "fields": self.fields,
            "raw": self.raw,
        }


@dataclass
class Alert:
    source: str  # which product raised it: "SIEM", "ESET PROTECT", "ESET Inspect", ...
    rule: str
    severity: str
    ts: datetime
    host: str
    user: str
    description: str
    trigger: Event  # the event the alert was raised on; its fields are shown on the alert card

    def public(self) -> dict:
        return {
            "source": self.source,
            "rule": self.rule,
            "severity": self.severity,
            "ts": self.ts.astimezone(TZ).isoformat(timespec="seconds"),
            "host": self.host,
            "user": self.user,
            "description": self.description,
            "trigger_event": self.trigger.id,
        }


@dataclass
class Context:
    """What the analyst can look up. Absence of a record is itself information, so lookups can return nothing."""

    assets: dict[str, dict[str, str]] = field(default_factory=dict)
    users: dict[str, dict[str, str]] = field(default_factory=dict)
    changes: list[dict[str, str]] = field(default_factory=list)  # {"scope", "start", "end", "title", "ticket"}
    ti: dict[str, dict[str, str]] = field(default_factory=dict)


@dataclass
class Lessons:
    """Static, per-template teaching material shown in the debrief."""

    title: str
    category: str
    tp_signs: list[str]
    fp_signs: list[str]
    checklist: list[str]
    pitfalls: list[str]
    attack: list[str]
    tips: list[str]
    hints: list[str]


@dataclass
class Truth:
    verdict: str
    severity: str
    summary: str
    model_note: str  # what a good ticket note looks like for this exact case
    required_actions: list[str]
    harmful_actions: list[str]
    expected_lookups: list[str]  # "kind:value" the analyst should have checked before deciding


@dataclass
class Scenario:
    token: str
    template: str
    difficulty: int
    alert: Alert
    events: list[Event]
    context: Context
    truth: Truth
    lessons: Lessons
    file: dict | None = None

    def event(self, event_id: str) -> Event | None:
        return next((e for e in self.events if e.id == event_id), None)

    def process_tree(self) -> list[dict]:
        """Flat list of process-creation events; the browser nests them by (host, parent pid)."""
        nodes = []
        for e in self.events:
            if e.source == "sysmon" and e.fields.get("EventID") == "1":
                f = e.fields
                nodes.append(
                    {
                        "id": e.id,
                        "ts": e.ts.astimezone(TZ).isoformat(timespec="seconds"),
                        "host": e.host,
                        "user": f.get("User", ""),
                        "pid": f.get("ProcessId", ""),
                        "ppid": f.get("ParentProcessId", ""),
                        "image": f.get("Image", ""),
                        "cmd": f.get("CommandLine", ""),
                        "signed": f.get("Signed", ""),
                        "integrity": f.get("IntegrityLevel", ""),
                    }
                )
        return nodes

    def public(self) -> dict:
        return {
            "token": self.token,
            "difficulty": self.difficulty,
            "tz": TZ_LABEL,
            "alert": self.alert.public(),
            "events": [e.public() for e in self.events],
            "tree": self.process_tree(),
            "file": self.file,
        }


def basename(path: str) -> str:
    return ntpath.basename(path) or path
