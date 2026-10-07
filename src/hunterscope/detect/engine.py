from __future__ import annotations

from typing import Any

from hunterscope.detect.rules import RULES
from hunterscope.models import Event, Finding


def run_detections(events: list[Event], cfg: dict[str, Any]) -> list[Finding]:
    """Run every enabled rule over time-ordered events, return findings in time order."""
    ordered = sorted(events, key=lambda e: e.ts)
    findings: list[Finding] = []
    for rule_id, fn in RULES.items():
        rule_cfg = cfg["rules"].get(rule_id)
        if not rule_cfg or not rule_cfg.get("enabled", True):
            continue
        findings.extend(fn(ordered, rule_cfg, rule_id))
    return sorted(findings, key=lambda f: f.ts)
