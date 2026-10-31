"""Benchmark third-party Sigma rules on the same labelled datasets and the same dev / holdout split.

See docs/sigma-protocol.md: the rule filter and the field mapping were fixed before measuring. Precision is NOT
measured (no benign baseline); "off-label" counts are a noise signal, not a false-positive rate.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hunterscope import coverage as cov
from hunterscope.sigma import RuleSet, SigmaRule


@dataclass
class SigmaDatasetResult:
    dataset: cov.Dataset
    records: int
    hits: Counter[str]  # rule id -> number of matching records
    rules: dict[str, SigmaRule]

    @property
    def got(self) -> set[str]:
        return {t for r in self.rules.values() for t in r.techniques}

    @property
    def split(self) -> str:
        return cov.split_of(self.dataset.id)


def records_from_zip(path: Path) -> Iterator[dict[str, Any]]:
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if not info.filename.lower().endswith(".json") or info.file_size > cov.MAX_MEMBER_BYTES:
                continue
            with zf.open(info) as raw:
                for line in io.TextIOWrapper(raw, encoding="utf-8", errors="replace"):
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(rec, dict):
                        yield rec


def run_sigma_otrf(datasets: list[cov.Dataset], ruleset: RuleSet) -> list[SigmaDatasetResult]:
    out: list[SigmaDatasetResult] = []
    for ds in datasets:
        hits: Counter[str] = Counter()
        rules: dict[str, SigmaRule] = {}
        records = 0
        for f in ds.files:
            if f.suffix != ".zip":
                continue
            for rec in records_from_zip(f):
                records += 1
                for rule in ruleset.match(rec):
                    hits[rule.id] += 1
                    rules[rule.id] = rule
        out.append(SigmaDatasetResult(ds, records, hits, rules))
    return out


# ------------------------------------------------------------------------------------ comparison


@dataclass
class Compare:
    split: str
    datasets: int
    hunterscope: int
    sigma: int
    union: int


def _hit(labels: list[str], got: set[str]) -> bool:
    return any(cov.family_hit(t, got) for t in labels)


def compare(pairs: list[tuple[cov.DatasetResult, SigmaDatasetResult]],
            subset: Callable[[cov.Dataset], bool]) -> list[Compare]:
    rows = []
    for name in ("dev", "holdout", "all"):
        chosen = [(h, s) for h, s in pairs if subset(h.dataset) and (name == "all" or h.split == name)]
        hs = sum(_hit(h.dataset.techniques, h.got) for h, _ in chosen)
        sg = sum(_hit(s.dataset.techniques, s.got) for _, s in chosen)
        un = sum(_hit(h.dataset.techniques, h.got | s.got) for h, s in chosen)
        rows.append(Compare(name, len(chosen), hs, sg, un))
    return rows


def _fmt(k: int, n: int) -> str:
    lo, hi = cov.wilson(k, n)
    return f"{k} / {n} ({cov._pct(k, n)}, CI {lo:.0%}-{hi:.0%})"


def _table(rows: list[Compare]) -> list[str]:
    out = ["| Split | Datasets | HunterScope rules | Sigma alone | Union |", "|---|---:|---|---|---|"]
    for r in rows:
        out.append(f"| {r.split} | {r.datasets} | {_fmt(r.hunterscope, r.datasets)} | {_fmt(r.sigma, r.datasets)} | "
                   f"{_fmt(r.union, r.datasets)} |")
    return out


def render_sigma(ruleset: RuleSet, results: list[SigmaDatasetResult], hs_results: list[cov.DatasetResult],
                 declared: set[str], rev: str = "") -> list[str]:
    by_id = {r.dataset.id: r for r in results}
    pairs = [(h, by_id[h.dataset.id]) for h in hs_results if h.dataset.id in by_id]
    st = ruleset.stats
    unsupported = ", ".join(f"{k}: {v}" for k, v in st.unsupported.most_common()) or "none"
    loaded_families = {f for r in ruleset.rules for f in r.families}

    in_scope = lambda ds: any(cov.covered_by_rule(t, declared) for t in ds.techniques)  # noqa: E731
    sigma_scope = lambda ds: any(cov.parent(t) in loaded_families for t in ds.techniques)  # noqa: E731

    out = [
        "", f"## Sigma: third-party rules on the same datasets{f' @ SigmaHQ `{rev}`' if rev else ''}", "",
        "Protocol fixed before measuring: [`sigma-protocol.md`](sigma-protocol.md). The Sigma rules were written by "
        "other people who never saw these datasets, so they cannot be overfitted by me; what could go wrong is my "
        "engine and field mapping, which were debugged on dev datasets only. Holdout appears only in this report.",
        "",
        f"- Rules in the directory: **{st.rules:,}**; inside the pre-registered filter (status stable/test/"
        f"experimental, level medium or higher, product windows): **{st.eligible:,}**.",
        f"- Loaded and evaluated: **{st.loaded:,}**. Not evaluated: **{sum(st.unmapped_logsource.values())}** for a "
        "log source the datasets do not contain (e.g. PowerShell script blocks) and "
        f"**{sum(st.unsupported.values())}** using an unsupported Sigma feature ({unsupported}).",
        f"- Records scanned: **{sum(r.records for r in results):,}**.",
        "", "### A. The datasets HunterScope's own rules were in scope for", "",
        "Same denominator as the table above, so the numbers are directly comparable.", "",
        *_table(compare(pairs, in_scope)),
        "", "### B. Every dataset labelled with a technique some loaded Sigma rule is tagged with", "",
        "Chosen from rule tags alone, without looking at telemetry. A wider denominator: HunterScope has no "
        "rule for many of these techniques.", "",
        *_table(compare(pairs, sigma_scope)),
    ]

    gained = [(h, s) for h, s in pairs if sigma_scope(h.dataset) and _hit(s.dataset.techniques, s.got)
              and not _hit(h.dataset.techniques, h.got)]
    out += ["", f"Datasets only Sigma caught ({len(gained)}): "
            + "; ".join(f"{h.dataset.id} ({h.split}: {h.dataset.title[:40]})" for h, _ in gained[:25])
            + (" ..." if len(gained) > 25 else "") + ".", ""]

    # Noise signal: a rule matched in a dataset but none of its ATT&CK families is a label of that dataset.
    stats = {"dev": [0, 0, 0], "holdout": [0, 0, 0]}  # (dataset, rule) pairs, off-label, untagged
    off_by_rule: Counter[str] = Counter()
    for _, s in pairs:
        labelled = {cov.parent(t) for t in s.dataset.techniques}
        for rid, rule in s.rules.items():
            row = stats[s.split]
            row[0] += 1
            if not rule.families:
                row[2] += 1
            elif not (rule.families & labelled):
                row[1] += 1
                off_by_rule[rid] += 1
    titles = {r.id: r for r in ruleset.rules}
    out += ["### Noise signal (not precision)", "",
            "A (dataset, rule) pair is *off-label* when the rule matched but none of its ATT&CK families is a label of "
            "that dataset. The labs run ancillary tooling, so this is not a false-positive rate; there is no benign "
            "baseline here.", "",
            "| Split | (dataset, rule) pairs | Off-label | Rule without ATT&CK tag |", "|---|---:|---:|---:|"]
    for name, (n, off, untagged) in stats.items():
        out.append(f"| {name} | {n} | {off} ({cov._pct(off, n)}) | {untagged} |")
    out += ["", "Rules that were off-label in the most datasets:", "", "| Rule | Level | Datasets |", "|---|---|---:|"]
    for rid, n in off_by_rule.most_common(10):
        r = titles[rid]
        out.append(f"| {r.title[:70].replace('|', '/')} | {r.level} | {n} |")

    # Per-technique table over every label.
    labels: dict[str, list[tuple[cov.DatasetResult, SigmaDatasetResult]]] = {}
    for h, s in pairs:
        for t in set(h.dataset.techniques):
            labels.setdefault(t, []).append((h, s))
    out += ["", "### Per technique (every label, with or without a HunterScope rule)", "",
            "| Technique | Datasets | HunterScope | Sigma | Union |", "|---|---:|---:|---:|---:|"]
    ordered = sorted(labels.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for t, rows in ordered:
        hs = sum(cov.family_hit(t, h.got) for h, _ in rows)
        sg = sum(cov.family_hit(t, s.got) for _, s in rows)
        un = sum(cov.family_hit(t, h.got | s.got) for h, s in rows)
        link = f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)"
        out.append(f"| {link} | {len(rows)} | {hs} | {sg} | {un} |")
    out.append("")
    return out
