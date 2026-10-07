"""Measure what the detections actually catch on public, labelled datasets.

OTRF Security-Datasets ship ATT&CK labels per dataset (YAML metadata), so recall can be computed per
technique. EVTX-ATTACK-SAMPLES only labels the *tactic* (folder name), so it yields a coarser
"any finding" rate. Neither contains benign baselines: precision is NOT measurable here.
"""

from __future__ import annotations

import io
import json
import subprocess
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from hunterscope.detect import run_detections
from hunterscope.ingest.parsers import parse_windows
from hunterscope.models import Event, Finding

MAX_MEMBER_BYTES = 300 * 1024 * 1024  # refuse zip members that decompress to more than this


def parent(technique: str) -> str:
    return technique.split(".")[0]


# --------------------------------------------------------------------------- labels (OTRF)


@dataclass
class Dataset:
    id: str
    title: str
    techniques: list[str]
    files: list[Path]


def _technique_id(mapping: dict[str, Any]) -> str | None:
    tech = mapping.get("technique")
    if not tech:
        return None
    sub = mapping.get("sub-technique")
    return f"{tech}.{int(sub):03d}" if sub not in (None, "") else str(tech)


def load_otrf(root: Path) -> list[Dataset]:
    """Windows `host` datasets with their ATT&CK labels. Files that were not fetched are skipped."""
    out: list[Dataset] = []
    for meta_path in sorted((root / "datasets" / "atomic" / "_metadata").glob("*.yaml")):
        meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
        if "Windows" not in (meta.get("platform") or []):
            continue
        techniques = [t for m in meta.get("attack_mappings") or [] if (t := _technique_id(m)) and t != "T0000"]
        files: list[Path] = []
        for f in meta.get("files") or []:
            if str(f.get("type")).lower() != "host" or "/master/" not in str(f.get("link")):
                continue
            local = root / str(f["link"]).split("/master/", 1)[1]
            if local.is_file():
                files.append(local)
        if techniques and files:
            out.append(Dataset(str(meta["id"]), str(meta.get("title", "")), techniques, files))
    return out


def events_from_zip(path: Path) -> tuple[list[Event], int]:
    """Read NDJSON members in memory (never extracted to disk). Returns (events, skipped records)."""
    events: list[Event] = []
    skipped = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if not info.filename.lower().endswith(".json") or info.file_size > MAX_MEMBER_BYTES:
                continue
            with zf.open(info) as raw:
                for line in io.TextIOWrapper(raw, encoding="utf-8", errors="replace"):
                    if not line.strip():
                        continue
                    try:
                        events.append(parse_windows(json.loads(line)))
                    except (ValueError, KeyError, TypeError, ValidationError):
                        skipped += 1
    return events, skipped


# ------------------------------------------------------------------------------ matching


def declared_techniques(cfg: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for rule in cfg["rules"].values():
        if not rule.get("enabled", True):
            continue
        out.update(rule["mitre"])
        for pat in rule.get("patterns", []):
            out.update(pat.get("mitre", []))
    return out


def covered_by_rule(label: str, declared: set[str]) -> bool:
    """A rule for T1003.001 does not cover T1003.002. A rule for the parent covers its sub-techniques;
    a rule for any sub-technique counts for the parent label."""
    if label in declared:
        return True
    if "." in label:
        return parent(label) in declared
    return any(parent(d) == label for d in declared)


def exact_hit(label: str, got: set[str]) -> bool:
    """Label T1003.001 needs T1003.001; label T1003 is satisfied by T1003 or any sub-technique."""
    return label in got or (label == parent(label) and any(parent(g) == label for g in got))


def family_hit(label: str, got: set[str]) -> bool:
    return parent(label) in {parent(g) for g in got}


@dataclass
class DatasetResult:
    dataset: Dataset
    events: int
    skipped: int
    findings: list[Finding]
    telemetry: int = 0  # process-creation + logon events: what the rules can actually look at

    @property
    def got(self) -> set[str]:
        return {m for f in self.findings for m in f.mitre}


LAB_UNEVALUABLE = ("off_hours_login",)  # depends on a workday clock that lab data does not have


def lab_config(cfg: dict[str, Any]) -> dict[str, Any]:
    from copy import deepcopy

    out = deepcopy(cfg)
    for rule_id in LAB_UNEVALUABLE:
        if rule_id in out["rules"]:
            out["rules"][rule_id]["enabled"] = False
    return out


def run_otrf(datasets: list[Dataset], cfg: dict[str, Any]) -> list[DatasetResult]:
    cfg = lab_config(cfg)
    results: list[DatasetResult] = []
    for ds in datasets:
        events: list[Event] = []
        skipped = 0
        for f in ds.files:
            if f.suffix == ".zip":
                ev, sk = events_from_zip(f)
                events += ev
                skipped += sk
        usable = sum(e.action in {"process_create", "logon"} for e in events)
        results.append(DatasetResult(ds, len(events), skipped, run_detections(events, cfg), usable))
    return results


@dataclass
class TechniqueRow:
    technique: str
    datasets: int = 0
    exact: int = 0
    family: int = 0
    has_rule: bool = False
    example: str = ""


def technique_table(results: list[DatasetResult], declared: set[str]) -> list[TechniqueRow]:
    rows: dict[str, TechniqueRow] = {}
    for r in results:
        got = r.got
        for label in set(r.dataset.techniques):
            row = rows.setdefault(label, TechniqueRow(label, has_rule=covered_by_rule(label, declared)))
            row.datasets += 1
            row.exact += exact_hit(label, got)
            row.family += family_hit(label, got)
            row.example = row.example or r.dataset.id
    return sorted(rows.values(), key=lambda x: (not x.has_rule, -x.datasets, x.technique))


def off_label(results: list[DatasetResult]) -> dict[str, tuple[int, int]]:
    """rule_id -> (findings, findings whose technique family is not among the dataset's labels)."""
    stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in results:
        labelled = {parent(t) for t in r.dataset.techniques}
        for f in r.findings:
            stats[f.rule_id][0] += 1
            if not ({parent(m) for m in f.mitre} & labelled):
                stats[f.rule_id][1] += 1
    return {k: (v[0], v[1]) for k, v in sorted(stats.items())}


# --------------------------------------------------------------------- EVTX-ATTACK-SAMPLES


def flatten_evtx_record(doc: dict[str, Any]) -> dict[str, Any]:
    """python `evtx` JSON ({"Event": {"System": ..., "EventData": ...}}) -> flat record parse_windows reads."""
    ev = doc["Event"]
    system, data = ev["System"], ev.get("EventData") or {}
    event_id = system["EventID"]
    if isinstance(event_id, dict):
        event_id = event_id.get("#text")
    flat = {k: v for k, v in data.items() if isinstance(v, (str, int, float))} if isinstance(data, dict) else {}
    flat.update(
        EventID=int(event_id),
        TimeCreated=system["TimeCreated"]["#attributes"]["SystemTime"],
        Computer=system.get("Computer"),
    )
    return flat


def events_from_evtx(path: Path) -> tuple[list[Event], int]:
    try:
        from evtx import PyEvtxParser
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("EVTX support needs the 'evtx' package: pip install 'hunterscope[bench]'") from exc
    events: list[Event] = []
    skipped = 0
    for rec in PyEvtxParser(str(path)).records_json():
        try:
            events.append(parse_windows(flatten_evtx_record(json.loads(rec["data"]))))
        except (ValueError, KeyError, TypeError, ValidationError):
            skipped += 1
    return events, skipped


@dataclass
class TacticRow:
    tactic: str
    files: int = 0
    unreadable: int = 0
    with_findings: int = 0
    rules: Counter[str] = field(default_factory=Counter)


def run_evtx(root: Path, cfg: dict[str, Any]) -> list[TacticRow]:
    tactics = ["Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
               "Credential Access", "Discovery", "Lateral Movement", "Command and Control"]
    cfg = lab_config(cfg)
    rows: list[TacticRow] = []
    for tactic in tactics:
        row = TacticRow(tactic)
        for path in sorted((root / tactic).glob("*.evtx")):
            row.files += 1
            try:
                events, _ = events_from_evtx(path)
            except RuntimeError:
                raise
            except Exception:  # corrupt/unsupported file: count it, keep going
                row.unreadable += 1
                continue
            findings = run_detections(events, cfg)
            if findings:
                row.with_findings += 1
                row.rules.update({f.rule_id for f in findings})
        if row.files:
            rows.append(row)
    return rows


# ------------------------------------------------------------------------------ report


def git_head(path: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"], capture_output=True,
                              text=True, check=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.0f}%" if d else "n/a"


def render(otrf: list[DatasetResult] | None, evtx: list[TacticRow] | None, cfg: dict[str, Any],
           otrf_rev: str = "", evtx_rev: str = "") -> str:
    declared = declared_techniques(cfg)
    out = ["# Detection coverage: measured, not claimed", "",
           "Generated by `hunterscope coverage`. Re-run it after changing any rule; do not edit by hand.", ""]
    if otrf is not None:
        rows = technique_table(otrf, declared)
        in_scope = [r for r in otrf if any(covered_by_rule(t, declared) for t in r.dataset.techniques)]
        hit = [r for r in in_scope if any(family_hit(t, r.got) for t in r.dataset.techniques)]
        evaluable = [r for r in in_scope if r.telemetry]
        evaluable_hit = [r for r in evaluable if r in hit]
        labelled = {r.technique for r in rows}
        ruled = {r.technique for r in rows if r.has_rule}
        ruled_hit = {r.technique for r in rows if r.has_rule and r.family}
        out += [
            f"## OTRF Security-Datasets (Windows, `host` telemetry){f' @ `{otrf_rev}`' if otrf_rev else ''}", "",
            f"- Datasets analysed: **{len(otrf)}**, events: **{sum(r.events for r in otrf):,}**",
            f"- ATT&CK techniques labelled in them: **{len(labelled)}**; with at least one HunterScope rule: "
            f"**{len(ruled)}**; actually detected at least once: **{len(ruled_hit)}**",
            f"- Datasets whose labels include a technique we have a rule for: **{len(in_scope)}**; "
            f"of those, at least one finding in the right technique family: **{len(hit)}** "
            f"({_pct(len(hit), len(in_scope))})",
            "- ...restricted to datasets that contain process-creation or logon events at all (the only things "
            f"the rules read): **{len(evaluable_hit)} / {len(evaluable)}** "
            f"({_pct(len(evaluable_hit), len(evaluable))})",
            "", "| Technique | Rule? | Datasets | Family hit | Exact hit | Recall (family) | Example |",
            "|---|:-:|---:|---:|---:|---:|---|",
        ]
        for r in rows:
            out.append(f"| [{r.technique}](https://attack.mitre.org/techniques/{r.technique.replace('.', '/')}/) | "
                       f"{'yes' if r.has_rule else '-'} | {r.datasets} | {r.family if r.has_rule else '-'} | "
                       f"{r.exact if r.has_rule else '-'} | {_pct(r.family, r.datasets) if r.has_rule else '-'} | "
                       f"{r.example} |")
        misses = [r for r in in_scope if r not in hit]
        out += ["", "### In-scope datasets with no finding in the right family", "",
                "Why each was missed, as far as can be told from the telemetry: `no process/logon events` means "
                "the rule had nothing to read (a data-source gap, not a pattern gap).", "",
                "| Dataset | Title | Rule-covered labels | Events | Process/logon events | Note |",
                "|---|---|---|---:|---:|---|"]
        for r in misses:
            labels = ", ".join(t for t in r.dataset.techniques if covered_by_rule(t, declared))
            note = "no process/logon events" if not r.telemetry else "pattern gap or non-command-line technique"
            out.append(f"| {r.dataset.id} | {r.dataset.title[:60].replace('|', '/')} | {labels} | {r.events:,} | "
                       f"{r.telemetry:,} | {note} |")
        out += ["", "### Findings not backed by a dataset label", "",
                "A finding is *off-label* when none of its techniques matches a label of that dataset. "
                "Off-label is **not** automatically a false positive (the lab also runs ancillary activity), "
                "but it is where to look first.", "", "| Rule | Findings | Off-label |", "|---|---:|---:|"]
        for rule_id, (total, off) in off_label(otrf).items():
            out.append(f"| {rule_id} | {total} | {off} |")
        out.append("")
    if evtx is not None:
        out += [f"## EVTX-ATTACK-SAMPLES{f' @ `{evtx_rev}`' if evtx_rev else ''}", "",
                "Labels are per **tactic folder only**, so this is the share of sample files on which at "
                "least one rule produced any finding, not technique-level recall.", "",
                "| Tactic | Files | Unreadable | With ≥1 finding | Share | Rules that fired |",
                "|---|---:|---:|---:|---:|---|"]
        for t in evtx:
            readable = t.files - t.unreadable
            fired = ", ".join(f"{k} ({v})" for k, v in t.rules.most_common())
            out.append(f"| {t.tactic} | {t.files} | {t.unreadable} | {t.with_findings} | "
                       f"{_pct(t.with_findings, readable)} | {fired} |")
        out.append("")
    out += ["## How to read this", "",
            "- **Scope is deliberate.** HunterScope is an identity/phishing triage tool with a thin Windows layer "
            "(command-line patterns and logon correlation). It is not an EDR; low recall on injection, "
            "persistence or lateral-movement techniques is expected and shown, not hidden.",
            "- `off_hours_login` is disabled for these runs: it needs a real working-day clock, which lab data lacks.",
            "- **No benign baseline in these datasets**, so precision and false-positive rate are not measured here. "
            "Benign look-alike fixtures live in `data/samples` and `tests/`.",
            "- Cloud rules (Entra ID, M365, phishing) have no public labelled dataset in this set; they are "
            "validated by synthetic scenarios with documented expected outcomes.",
            "- 'Family hit' compares at parent-technique level (T1003 vs T1003.001); 'Exact hit' needs the "
            "sub-technique the dataset is labelled with.", ""]
    return "\n".join(out)
