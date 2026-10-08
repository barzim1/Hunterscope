"""Shift handover: what the next analyst must know, built from the case store."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from hunterscope.casestore import CLOSED, ESCALATED, Case, CaseStore, LogEntry
from hunterscope.report import make_env

_SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class CaseView:
    case: Case
    findings: list[dict[str, Any]]
    top_findings: list[str]
    more_findings: int
    last_note: LogEntry | None
    decision_note: str  # why it was closed / escalated
    age_hours: float
    idle_hours: float
    stale: bool
    new_this_shift: bool  # opened (open/unresolved) or escalated/closed inside the window


@dataclass
class Handover:
    since: datetime
    until: datetime
    analyst: str
    opened: int = 0
    closed_fp: list[CaseView] = field(default_factory=list)
    closed_tp: list[CaseView] = field(default_factory=list)
    escalated: list[CaseView] = field(default_factory=list)
    unresolved: list[CaseView] = field(default_factory=list)

    @property
    def targets(self) -> list[tuple[str, str]]:
        views = [*self.closed_fp, *self.closed_tp, *self.escalated, *self.unresolved]
        return sorted({(v.case.kind, v.case.target) for v in views})


def _view(store: CaseStore, case: Case, until: datetime, window_start: datetime, cfg: dict[str, Any],
          change: LogEntry | None) -> CaseView:
    findings = store.findings(case.id)
    ranked = sorted(findings, key=lambda f: (_SEVERITY.get(f["severity"], 9), f["first_seen"]))
    top_n = cfg["handover"]["top_findings"]
    log = store.log(case.id)
    noted = [e for e in log if e.kind in {"note", "status"} and e.text]
    decision = change.text if change else next((e.text for e in reversed(log) if e.kind == "status" and e.text), "")
    idle = (until - case.updated_at).total_seconds() / 3600
    return CaseView(
        case=case,
        findings=findings,
        top_findings=[f["title"] for f in ranked[:top_n]],
        more_findings=max(0, len(ranked) - top_n),
        last_note=noted[-1] if noted else None,
        decision_note=decision,
        age_hours=(until - case.opened_at).total_seconds() / 3600,
        idle_hours=idle,
        stale=not case.is_closed and idle >= cfg["handover"]["stale_hours"],
        new_this_shift=bool(change) or case.opened_at > window_start,
    )


def build_handover(store: CaseStore, until: datetime, hours: float, cfg: dict[str, Any],
                   analyst: str) -> Handover:
    since = until - timedelta(hours=hours)
    ho = Handover(since=since, until=until, analyst=analyst)

    changes: dict[int, LogEntry] = {}  # latest status change inside the window, per case
    for case_id, entry in store.status_changes_between(since, until):
        changes[case_id] = entry

    for case in store.list_cases():
        if case.opened_at > until:
            continue  # created after the window being summarized
        if case.opened_at > since:
            ho.opened += 1
        change = changes.get(case.id)
        if case.status in CLOSED:
            if change and change.to_status == case.status:
                target = ho.closed_fp if case.status == "closed_fp" else ho.closed_tp
                target.append(_view(store, case, until, since, cfg, change))
        elif case.status in ESCALATED:
            escalated_now = change if change and change.to_status in ESCALATED else None
            ho.escalated.append(_view(store, case, until, since, cfg, escalated_now))
        else:
            ho.unresolved.append(_view(store, case, until, since, cfg, None))

    for bucket in (ho.escalated, ho.unresolved):
        bucket.sort(key=lambda v: (-v.case.score, v.case.id))
    for bucket in (ho.closed_fp, ho.closed_tp):
        bucket.sort(key=lambda v: v.case.id)
    return ho


def render_markdown(ho: Handover) -> str:
    return make_env().get_template("handover.md.j2").render(h=ho)


def render_html(ho: Handover) -> str:
    from hunterscope import __version__
    from hunterscope.report import _stamp

    return make_env().get_template("handover.html.j2").render(h=ho, version=__version__, generated=_stamp())
