from __future__ import annotations

from typing import Any

from hunterscope.detect.rules import META_RULES, RULES
from hunterscope.models import Event, Finding


def run_detections(events: list[Event], cfg: dict[str, Any]) -> list[Finding]:
    """Run every enabled rule over time-ordered events, then meta rules that correlate their findings."""
    ordered = sorted(events, key=lambda e: e.ts)
    findings: list[Finding] = []
    for rule_id, fn in RULES.items():
        rule_cfg = cfg["rules"].get(rule_id)
        if not rule_cfg or not rule_cfg.get("enabled", True):
            continue
        findings.extend(fn(ordered, rule_cfg, rule_id))
    for rule_id, meta in META_RULES.items():
        rule_cfg = cfg["rules"].get(rule_id)
        if rule_cfg and rule_cfg.get("enabled", True):
            findings.extend(meta(ordered, rule_cfg, rule_id, findings))
    return sorted(findings, key=lambda f: f.ts)
