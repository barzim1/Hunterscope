"""Plain-language explanations: what an event, code, process, rule or ATT&CK technique means.

Offline lookup in a curated knowledge base (`config/knowledge.yaml`). Nothing is generated, so nothing is
invented: a term the base does not know is reported as unknown, never guessed. The text is context for a
decision, not a verdict; whether *this* occurrence is malicious depends on who, from where, and what came
before and after.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from hunterscope.models import Event, Finding
from hunterscope.triage import Dossier

TABLES = {
    "windows_events": "Zdarzenie Windows",
    "sysmon_events": "Zdarzenie Sysmon",
    "entra_errors": "Kod Entra ID",
    "ual_operations": "Operacja M365",
    "processes": "Proces / plik",
    "techniques": "Technika MITRE ATT&CK",
    "rules": "Reguła HunterScope",
}
# Sysmon event ids are 1-30; Windows Security/System ids that matter here are all above that.
SYSMON_MAX_ID = 30

_REQUIRED = ("title", "what", "risk", "normal", "check", "source")
_TECHNIQUE_ID = re.compile(r"^t\d{4}(\.\d{3})?$")
_PREFIXES = {
    "event": ("windows_events", "sysmon_events"),
    "eventid": ("windows_events", "sysmon_events"),
    "sysmon": ("sysmon_events",),
    "entra": ("entra_errors",),
    "aadsts": ("entra_errors",),
    "ual": ("ual_operations",),
    "proc": ("processes",),
    "process": ("processes",),
    "tech": ("techniques",),
    "mitre": ("techniques",),
    "rule": ("rules",),
}


@dataclass(frozen=True)
class Explanation:
    table: str
    key: str
    title: str
    what: str
    risk: str
    normal: str
    check: tuple[str, ...]
    source: str
    quiet: bool = False

    @property
    def kind(self) -> str:
        return TABLES[self.table]

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "table": self.table, "key": self.key, "title": self.title, "what": self.what,
                "risk": self.risk, "normal": self.normal, "check": list(self.check), "source": self.source}


class KnowledgeBase:
    """Case-insensitive view over the YAML tables; YAML may give numeric keys as ints, so keys are stringified."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self._index: dict[str, dict[str, tuple[str, dict[str, Any]]]] = {}
        for table in TABLES:
            self._index[table] = {str(k).lower(): (str(k), v) for k, v in (raw.get(table) or {}).items()}

    def get(self, table: str, key: str) -> Explanation | None:
        found = self._index.get(table, {}).get(key.lower())
        if found is None:
            return None
        original, entry = found
        missing = [f for f in _REQUIRED if not entry.get(f)]
        if missing:
            raise ValueError(f"knowledge base entry {table}/{original} lacks: {', '.join(missing)}")
        return Explanation(
            table=table, key=original, title=str(entry["title"]).strip(), what=str(entry["what"]).strip(),
            risk=str(entry["risk"]).strip(), normal=str(entry["normal"]).strip(),
            check=tuple(str(c).strip() for c in entry["check"]), source=str(entry["source"]).strip(),
            quiet=bool(entry.get("quiet", False)),
        )

    def keys(self, table: str) -> list[str]:
        return [original for original, _ in self._index.get(table, {}).values()]


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip())[-1].lower()


def lookup(term: str, kb: KnowledgeBase) -> list[Explanation]:
    """Resolve a free-form term to every matching entry. A bare number can be a Windows event id, a Sysmon
    event id and an Entra error code at once; all matches are returned so the analyst sees the ambiguity."""
    raw = term.strip()
    tables: tuple[str, ...] | None = None
    if ":" in raw:
        prefix, _, rest = raw.partition(":")
        if prefix.lower() in _PREFIXES:
            tables, raw = _PREFIXES[prefix.lower()], rest.strip()
    norm = re.sub(r"^aadsts", "", raw.lower())
    if tables is None:
        if _TECHNIQUE_ID.match(norm):
            tables = ("techniques",)
        elif norm.isdigit():
            tables = ("windows_events", "sysmon_events", "entra_errors")
        else:
            tables = ("rules", "processes", "ual_operations")

    out: list[Explanation] = []
    for table in tables:
        candidates = [norm]
        if table == "processes":
            base = _basename(norm)
            candidates = [norm, base, base + ".exe"]
        elif table == "ual_operations":
            candidates = [norm.rstrip(".")]
        for cand in dict.fromkeys(candidates):
            hit = kb.get(table, cand)
            if hit is not None and hit not in out:
                out.append(hit)
                break
    return out


def event_keys(e: Event) -> list[tuple[str, str]]:
    """Knowledge-base entries an event can be explained with: (table, key)."""
    keys: list[tuple[str, str]] = []
    if e.source == "windows":
        event_id = e.detail.get("event_id")
        if isinstance(event_id, int):
            keys.append(("sysmon_events" if event_id <= SYSMON_MAX_ID else "windows_events", str(event_id)))
        for path in (e.app, e.detail.get("target_image")):
            if path:
                keys.append(("processes", _basename(str(path))))
    elif e.source == "entra" and e.error_code is not None:
        keys.append(("entra_errors", str(e.error_code)))
    elif e.source == "ual":
        keys.append(("ual_operations", e.action.rstrip(".").lower()))
    return keys


@dataclass
class FindingGroup:
    """All findings of one rule, explained once."""

    rule_id: str
    explanation: Explanation | None
    titles: list[str]
    severity: str
    techniques: list[Explanation]
    unknown_techniques: list[str]


@dataclass
class SeenEntry:
    explanation: Explanation
    count: int
    flagged: int  # how many of those events are evidence of a finding


@dataclass
class DossierExplanation:
    kind: str
    target: str
    since: str
    until: str
    groups: list[FindingGroup] = field(default_factory=list)
    seen: list[SeenEntry] = field(default_factory=list)
    gaps: list[tuple[str, str, int]] = field(default_factory=list)


_SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _group_findings(findings: list[Finding], kb: KnowledgeBase) -> list[FindingGroup]:
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    groups: list[FindingGroup] = []
    for rule_id, items in by_rule.items():
        techniques: list[Explanation] = []
        unknown: list[str] = []
        for tid in dict.fromkeys(t for f in items for t in f.mitre):
            hit = kb.get("techniques", tid)
            if hit is None:
                unknown.append(tid)
            else:
                techniques.append(hit)
        groups.append(FindingGroup(
            rule_id=rule_id, explanation=kb.get("rules", rule_id), titles=[f.title for f in items],
            severity=min((f.severity for f in items), key=lambda s: _SEVERITY.get(s, 9)),
            techniques=techniques, unknown_techniques=unknown,
        ))
    groups.sort(key=lambda g: (_SEVERITY.get(g.severity, 9), g.rule_id))
    return groups


def explain_dossier(dossier: Dossier, kb: KnowledgeBase) -> DossierExplanation:
    """Explain what a dossier contains: its findings, and the kinds of events in its window.

    Quiet entries (routine noise such as a successful sign-in) are left out of the event list. Event kinds with
    no entry in the base are listed as gaps, so the analyst can tell 'unremarkable' from 'not covered'. Process
    names with no entry are not listed: almost every process is ordinary and would drown the gaps that matter.
    """
    flagged = dossier.flagged_ids
    counts: Counter[tuple[str, str]] = Counter()
    flagged_counts: Counter[tuple[str, str]] = Counter()
    for e in dossier.events:
        for key in event_keys(e):
            counts[key] += 1
            if id(e) in flagged:
                flagged_counts[key] += 1

    seen: list[SeenEntry] = []
    gaps: list[tuple[str, str, int]] = []
    for (table, key), n in counts.items():
        hit = kb.get(table, key)
        if hit is None:
            if table != "processes":
                gaps.append((table, key, n))
        elif not hit.quiet:
            seen.append(SeenEntry(hit, n, flagged_counts[(table, key)]))
    seen.sort(key=lambda s: (-(s.flagged > 0), -s.count, s.explanation.table, s.explanation.key))
    gaps.sort(key=lambda g: (-g[2], g[0], g[1]))
    return DossierExplanation(
        kind=dossier.kind, target=dossier.target, since=dossier.since.strftime("%Y-%m-%d %H:%M"),
        until=dossier.until.strftime("%Y-%m-%d %H:%M"), groups=_group_findings(dossier.findings, kb),
        seen=seen, gaps=gaps,
    )


# --------------------------------------------------------------------------- rendering

DISCLAIMER = (
    "> Kontekst, nie werdykt: wpis mówi, co dany artefakt znaczy ogólnie. Czy w TYM przypadku jest groźny, "
    "rozstrzyga kontekst: kto, skąd, kiedy oraz co było przedtem i potem. Treść pochodzi z ręcznie pisanej "
    "bazy wiedzy, nic nie jest generowane."
)


def _entry_md(x: Explanation, level: str = "###", suffix: str = "") -> list[str]:
    lines = [f"{level} {x.title}{suffix}", "", f"*{x.kind}*", "",
             f"**Co to jest:** {x.what}", "", f"**Jakie zagrożenie:** {x.risk}", "",
             f"**Jak wygląda normalnie:** {x.normal}", "", "**Co sprawdzić:**"]
    lines += [f"- {c}" for c in x.check]
    lines += ["", f"Źródło: <{x.source}>", ""]
    return lines


def render_lookup_markdown(term_results: list[tuple[str, list[Explanation]]]) -> str:
    lines = ["# Wyjaśnienie", "", DISCLAIMER, ""]
    for term, results in term_results:
        if not results:
            lines += [f"## `{term}`", "", "Brak wpisu w bazie wiedzy. Nie zgaduję: sprawdź w dokumentacji "
                      "producenta albo dopisz własny wpis (`--kb`).", ""]
            continue
        for x in results:
            lines += _entry_md(x, "##")
    return "\n".join(lines)


def render_dossier_markdown(ex: DossierExplanation) -> str:
    lines = [f"# Wyjaśnienie dossier: {ex.kind} `{ex.target}`", "", f"Okno (UTC): {ex.since} → {ex.until}", "",
             DISCLAIMER, ""]
    lines += ["## Wykrycia", ""]
    if not ex.groups:
        lines += ["Brak wykryć w oknie.", ""]
    for g in ex.groups:
        lines += [f"**[{g.severity.upper()}] {g.rule_id}**: " + "; ".join(g.titles), ""]
        if g.explanation:
            lines += _entry_md(g.explanation, "###")
        else:
            lines += [f"*Reguła `{g.rule_id}` nie ma wpisu w bazie wiedzy.*", ""]
        if g.techniques:
            lines += ["Techniki ATT&CK:", ""]
            lines += [f"- **{t.key}**: {t.what} (<{t.source}>)" for t in g.techniques]
            lines.append("")
        if g.unknown_techniques:
            lines += [f"Techniki bez wpisu: {', '.join(g.unknown_techniques)}", ""]
    lines += ["## Zdarzenia w oknie, które warto rozumieć", ""]
    if not ex.seen:
        lines += ["Brak zdarzeń z wpisem w bazie wiedzy.", ""]
    for s in ex.seen:
        suffix = f" ×{s.count}" + (f", w tym {s.flagged} jako dowód wykrycia" if s.flagged else "")
        lines += _entry_md(s.explanation, "###", suffix)
    if ex.gaps:
        lines += ["## Bez wyjaśnienia", "",
                  "Te rodzaje zdarzeń są w oknie, ale baza ich nie opisuje. To nie znaczy, że są niegroźne, tylko "
                  "że nie ma dla nich wpisu (dopisz go przez `--kb`).", ""]
        lines += [f"- {TABLES[t]} `{k}` ×{n}" for t, k, n in ex.gaps]
        lines.append("")
    return "\n".join(lines)


def lookup_to_dict(term_results: list[tuple[str, list[Explanation]]]) -> list[dict[str, Any]]:
    return [{"term": term, "found": bool(results), "entries": [x.to_dict() for x in results]}
            for term, results in term_results]


def dossier_to_dict(ex: DossierExplanation) -> dict[str, Any]:
    return {
        "kind": ex.kind, "target": ex.target, "since": ex.since, "until": ex.until,
        "findings": [
            {"rule_id": g.rule_id, "severity": g.severity, "titles": g.titles,
             "explanation": g.explanation.to_dict() if g.explanation else None,
             "techniques": [t.to_dict() for t in g.techniques], "unknown_techniques": g.unknown_techniques}
            for g in ex.groups
        ],
        "events": [{"count": s.count, "flagged": s.flagged, **s.explanation.to_dict()} for s in ex.seen],
        "gaps": [{"kind": TABLES[t], "key": k, "count": n} for t, k, n in ex.gaps],
    }
