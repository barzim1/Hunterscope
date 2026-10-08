"""Load JSON / NDJSON exports, auto-detect the source of each record."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from hunterscope.ingest.eml import parse_eml
from hunterscope.ingest.parsers import PARSERS, detect_source
from hunterscope.models import Event


@dataclass
class LoadResult:
    events: list[Event] = field(default_factory=list)
    skipped: int = 0
    sources: Counter[str] = field(default_factory=Counter)


def _iter_records(path: Path) -> Iterator[dict[str, Any] | None]:
    """Yield records; `None` marks an unparseable line (counted as skipped)."""
    text = path.read_text(encoding="utf-8-sig")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                yield None
                continue
            yield rec if isinstance(rec, dict) else None
        return
    if isinstance(doc, dict):
        # Graph API style envelope: {"value": [...]}
        doc = doc["value"] if isinstance(doc.get("value"), list) else [doc]
    for rec in doc:
        yield rec if isinstance(rec, dict) else None


_SUFFIXES = {".json", ".ndjson", ".jsonl", ".eml"}


def expand_paths(paths: Iterable[Path]) -> list[Path]:
    """Directories are expanded (recursively) to the supported log/mail files they contain."""
    out: list[Path] = []
    for path in map(Path, paths):
        if path.is_dir():
            out.extend(sorted(p for p in path.rglob("*") if p.suffix.lower() in _SUFFIXES))
        else:
            out.append(path)
    return out


def load_events(paths: Iterable[Path]) -> LoadResult:
    result = LoadResult()
    for path in expand_paths(paths):
        if path.suffix.lower() == ".eml":
            try:
                emails = parse_eml(path)
            except (OSError, ValueError, ValidationError):
                result.skipped += 1
                continue
            result.events.extend(emails)
            result.sources["email"] += len(emails)
            continue
        for rec in _iter_records(path):
            source = detect_source(rec) if rec else None
            if source is None:
                result.skipped += 1
                continue
            try:
                event = PARSERS[source](rec)
            except (KeyError, ValueError, TypeError, ValidationError):
                result.skipped += 1
                continue
            result.events.append(event)
            result.sources[source] += 1
    result.events.sort(key=lambda e: e.ts)
    return result
