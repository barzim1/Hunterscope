"""Load a directory of Sigma rules, apply the pre-registered filter, index by logsource, match records."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from hunterscope.sigma.logsource import SUPPORTED_CATEGORIES, SUPPORTED_SERVICES, keys_for
from hunterscope.sigma.rule import LEVELS, Rec, SigmaRule, parse_rule

DEFAULT_STATUSES = ("stable", "test", "experimental")


@dataclass
class LoadStats:
    files: int = 0
    rules: int = 0
    unparseable_files: int = 0
    filtered_out: int = 0          # level / status / product outside the pre-registered filter
    unmapped_logsource: Counter[str] = field(default_factory=Counter)
    unsupported: Counter[str] = field(default_factory=Counter)
    loaded: int = 0

    @property
    def eligible(self) -> int:
        return self.rules - self.filtered_out


class RuleSet:
    def __init__(self, rules: list[SigmaRule], stats: LoadStats) -> None:
        self.rules = rules
        self.stats = stats
        self._by_category: dict[str, list[SigmaRule]] = defaultdict(list)
        self._by_service: dict[str, list[SigmaRule]] = defaultdict(list)
        self._generic: list[SigmaRule] = []
        for r in rules:
            if r.category:
                self._by_category[r.category].append(r)
            elif r.service:
                self._by_service[r.service].append(r)
            else:
                self._generic.append(r)

    def __len__(self) -> int:
        return len(self.rules)

    def match(self, record: dict[str, Any]) -> list[SigmaRule]:
        rec = Rec(record)
        cats, service = keys_for(rec)
        candidates: list[SigmaRule] = list(self._generic)
        for c in cats:
            candidates.extend(self._by_category.get(c, ()))
        if service:
            candidates.extend(self._by_service.get(service, ()))
        out = []
        for r in candidates:
            if r.service and r.category and r.service != service:
                continue
            assert r.match is not None
            if r.match(rec):
                out.append(r)
        return out


def load_ruleset(
    root: Path,
    min_level: str = "medium",
    statuses: tuple[str, ...] = DEFAULT_STATUSES,
) -> RuleSet:
    floor = LEVELS.index(min_level)
    stats = LoadStats()
    kept: list[SigmaRule] = []
    for path in sorted(Path(root).rglob("*.yml")):
        stats.files += 1
        try:
            docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(d, dict)]
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
            stats.unparseable_files += 1
            continue
        for doc in docs:
            if "detection" not in doc:
                continue
            stats.rules += 1
            rule = parse_rule(doc, str(path))
            ls = rule.logsource
            if (
                rule.level not in LEVELS
                or LEVELS.index(rule.level) < floor
                or rule.status not in statuses
                or ls.get("product", "windows") != "windows"
            ):
                stats.filtered_out += 1
                continue
            mapped = (
                (rule.category in SUPPORTED_CATEGORIES) if rule.category
                else (rule.service in SUPPORTED_SERVICES) if rule.service
                else True
            )
            if not mapped:
                stats.unmapped_logsource[rule.category or rule.service or "?"] += 1
                continue
            if rule.unsupported:
                stats.unsupported[rule.unsupported.split(":")[0].split("'")[0].strip()] += 1
                continue
            kept.append(rule)
    stats.loaded = len(kept)
    return RuleSet(kept, stats)
