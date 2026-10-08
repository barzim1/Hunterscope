"""Explainable risk score: every point is traceable to a rule."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from hunterscope.models import Finding


@dataclass
class Contribution:
    rule_id: str
    tactic: str
    hits: int
    points: float


@dataclass
class Score:
    total: int
    level: str
    contributions: list[Contribution] = field(default_factory=list)
    bonus: int = 0
    bonus_reason: str = ""


def level_for(total: float, levels: dict[str, int]) -> str:
    for name, threshold in sorted(levels.items(), key=lambda kv: kv[1], reverse=True):
        if total >= threshold:
            return name
    return "info"


def compute_score(findings: list[Finding], cfg: dict[str, Any]) -> Score:
    sc = cfg["scoring"]
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(f)

    contributions: list[Contribution] = []
    for rule_id, group in by_rule.items():
        weight = group[0].weight
        raw = weight * (1 + (len(group) - 1) * sc["repeat_factor"])
        points = min(raw, weight * sc["rule_cap_multiplier"])
        contributions.append(Contribution(rule_id, group[0].tactic, len(group), round(points, 1)))
    contributions.sort(key=lambda c: c.points, reverse=True)

    tactics = {c.tactic for c in contributions}
    bonus = 0
    reason = ""
    if len(tactics) > 1:
        bonus = min(sc["multi_stage_bonus_cap"], sc["multi_stage_bonus"] * (len(tactics) - 1))
        reason = f"multi-stage activity across {len(tactics)} tactics: {', '.join(sorted(tactics))}"

    total = min(100, round(sum(c.points for c in contributions) + bonus))
    return Score(total, level_for(total, sc["levels"]), contributions, bonus, reason)
