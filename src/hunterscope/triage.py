"""Build a Dossier for one user or host from a pool of normalized events."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from hunterscope.detect import run_detections
from hunterscope.models import Event, Finding, host_key, user_key
from hunterscope.netutil import is_internal
from hunterscope.score import Score, compute_score
from hunterscope.sigma import RuleSet

_RANGE_RE = re.compile(r"^(\d+)([mhdw])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_timerange(value: str) -> timedelta:
    m = _RANGE_RE.match(value.strip().lower())
    if not m:
        raise ValueError(f"invalid timerange '{value}' (use e.g. 90m, 24h, 7d, 2w)")
    return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})


@dataclass
class RelatedAccount:
    """Another account seen authenticating from an IP the target used (or, in IP mode, every account from it)."""

    user: str
    ip: str
    failures: int
    successes: int
    first: datetime
    last: datetime


def related_accounts(pool: list[Event], skip_user: str | None = None) -> list[RelatedAccount]:
    rows: dict[tuple[str, str], RelatedAccount] = {}
    for e in pool:
        if e.source not in {"entra", "windows"} or e.action not in {"signin", "logon"} or not e.ip or not e.user:
            continue
        if skip_user is not None and user_key(e.user) == skip_user:
            continue
        key = (user_key(e.user), e.ip)
        row = rows.get(key)
        if row is None:
            row = rows[key] = RelatedAccount(e.user, e.ip, 0, 0, e.ts, e.ts)
        row.failures += e.outcome == "failure"
        row.successes += e.outcome == "success"
        row.first, row.last = min(row.first, e.ts), max(row.last, e.ts)
    return sorted(rows.values(), key=lambda r: (-r.failures, -r.successes, r.user))


@dataclass
class Dossier:
    kind: str
    target: str
    since: datetime
    until: datetime
    events: list[Event]
    findings: list[Finding]
    score: Score
    sources: Counter[str]
    skipped: int = 0
    related: list[RelatedAccount] = field(default_factory=list)
    generated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def flagged_ids(self) -> set[int]:
        return {id(e) for f in self.findings for e in f.evidence}

    def iocs(self) -> dict[str, list[str]]:
        out: dict[str, set[str]] = {}
        for f in self.findings:
            for kind, value in f.iocs:
                if kind == "ip" and is_internal(value):
                    continue
                out.setdefault(kind, set()).add(value)
        return {k: sorted(v) for k, v in sorted(out.items())}

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "since": self.since.isoformat(),
            "until": self.until.isoformat(),
            "generated": self.generated.isoformat(),
            "events_analysed": len(self.events),
            "sources": dict(self.sources),
            "score": {
                "total": self.score.total,
                "level": self.score.level,
                "bonus": self.score.bonus,
                "bonus_reason": self.score.bonus_reason,
                "contributions": [vars(c) for c in self.score.contributions],
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "tactic": f.tactic,
                    "mitre": f.mitre,
                    "time": f.ts.isoformat(),
                    "description": f.description,
                    "evidence_events": len(f.evidence),
                }
                for f in self.findings
            ],
            "iocs": self.iocs(),
            "related_accounts": [
                {"user": r.user, "ip": r.ip, "failures": r.failures, "successes": r.successes,
                 "first": r.first.isoformat(), "last": r.last.isoformat()}
                for r in self.related
            ],
        }


def select_events(events: list[Event], kind: str, target: str) -> list[Event]:
    if kind == "user":
        key = user_key(target)
        return [e for e in events if user_key(e.user) == key]
    if kind == "ip":
        wanted = target.strip()
        return [e for e in events if e.ip == wanted]
    key = host_key(target)
    return [e for e in events if host_key(e.host) == key]


def build_dossier(
    events: list[Event],
    kind: str,
    target: str,
    timerange: timedelta,
    cfg: dict[str, Any],
    anchor: datetime | None = None,
    skipped: int = 0,
    sigma: RuleSet | None = None,
) -> Dossier:
    """`anchor` is the window end; default = latest event for the target (offline data)."""
    mine = select_events(events, kind, target)
    if not mine:
        raise LookupError(f"no events found for {kind} '{target}'")
    until = anchor or max(e.ts for e in mine)
    since = until - timerange
    windowed = sorted((e for e in mine if since <= e.ts <= until), key=lambda e: e.ts)

    # Other accounts that touched the same IPs in the window: needed to see a spray, which no single account shows.
    own = {id(e) for e in windowed}
    ips = {e.ip for e in windowed if e.ip}
    context = [e for e in events if e.ip in ips and since <= e.ts <= until and id(e) not in own]
    skip = user_key(target) if kind == "user" else None
    related = related_accounts([*windowed, *context], skip_user=skip)

    findings = run_detections(windowed, cfg, context=context, sigma=sigma)
    return Dossier(
        kind=kind,
        target=target,
        since=since,
        until=until,
        events=windowed,
        findings=findings,
        score=compute_score(findings, cfg),
        sources=Counter(e.source for e in windowed),
        skipped=skipped,
        related=related,
    )
