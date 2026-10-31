"""Turn Sigma matches on Windows events into findings, one per (rule, host)."""

from __future__ import annotations

from typing import Any

from hunterscope.models import Event, Finding, host_key
from hunterscope.sigma import RuleSet, SigmaRule

SOURCE_URL = "https://github.com/SigmaHQ/sigma"


def sigma_findings(events: list[Event], ruleset: RuleSet, cfg: dict[str, Any]) -> list[Finding]:
    """Findings are grouped by level (`sigma_high`, ...), so the score's diminishing returns apply per level and a
    chatty rule family cannot drown the rest. Events without a retained raw record are ignored."""
    groups: dict[tuple[str, str], tuple[SigmaRule, list[Event]]] = {}
    for e in events:
        if e.raw is None:
            continue
        for rule in ruleset.match(e.raw):
            key = (rule.id or rule.title, host_key(e.host))
            groups.setdefault(key, (rule, []))[1].append(e)

    out: list[Finding] = []
    weights = cfg["weights"]
    cap = int(cfg["max_evidence"])
    for (_, _), (rule, evs) in groups.items():
        iocs: list[tuple[str, str]] = []
        first = evs[0]
        if first.command_line:
            iocs.append(("command", first.command_line[:200]))
        if first.app and first.action == "process_create":
            iocs.append(("process", first.app))
        host = first.host or "unknown host"
        note = f" {len(evs)} matching events." if len(evs) > 1 else ""
        out.append(
            Finding(
                rule_id=f"sigma_{rule.level}",
                title=rule.title,
                severity=rule.level,
                tactic=rule.tactics[0] if rule.tactics else "unknown",
                mitre=list(dict.fromkeys(rule.techniques)),
                weight=float(weights.get(rule.level, 0)),
                description=f"Sigma rule {rule.id or '(no id)'} on {host}.{note} {rule.description[:300]} "
                            f"Source: {SOURCE_URL}",
                evidence=evs[:cap],
                iocs=iocs,
            )
        )
    return out
