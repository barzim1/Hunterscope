"""The analyst's context tools: asset inventory, user directory, change calendar, threat intel.

A lookup that finds nothing is a legitimate answer, so every function returns `None` rather than inventing data.
"""

from __future__ import annotations

import re
from datetime import datetime
from fnmatch import fnmatch

from hunterscope.trainer.model import LOOKUP_KINDS, TZ, Scenario

_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")


def normalize(kind: str, value: str) -> str:
    """One canonical form per (kind, value) so that a lookup of `https://x.top/a` matches an expected `ti:x.top`."""
    v = value.strip().lower()
    if kind == "asset":
        return v.split(".")[0]
    if kind == "user":
        return v.split("\\")[-1].split("@")[0]
    if kind == "change":
        return v.split(".")[0] if re.search(r"[a-z]", v) else v
    if kind == "ti":
        m = _SHA256.search(v) or _SHA1.search(v)
        if m:
            return m.group(0)
        v = re.sub(r"^[a-z]+://", "", v)
        return v.split("/")[0].split(":")[0]
    return v


def lookup_key(kind: str, value: str) -> str:
    return f"{kind}:{normalize(kind, value)}"


def lookup(scn: Scenario, kind: str, value: str) -> dict:
    if kind not in LOOKUP_KINDS:
        raise ValueError(f"unknown lookup kind: {kind!r}")
    key = normalize(kind, value)
    ctx = scn.context
    if kind == "asset":
        rec = ctx.assets.get(key)
        return _single("Ewidencja zasobów (CMDB)", rec, key, "Brak wpisu w ewidencji dla tego hosta.")
    if kind == "user":
        rec = ctx.users.get(key)
        return _single("Katalog użytkowników / HR", rec, key, "Brak użytkownika o tym identyfikatorze w katalogu.")
    if kind == "ti":
        rec = ctx.ti.get(key)
        if rec is None:
            rec = next((r for k, r in ctx.ti.items() if key.endswith("." + k)), None)
        return _single("Threat intelligence (symulacja)", rec, key, "Brak danych o tym wskaźniku. Brak wpisu nie oznacza, że jest bezpieczny.")
    return _changes(scn, key)


def _single(title: str, rec: dict[str, str] | None, key: str, empty: str) -> dict:
    if rec is None:
        return {"title": title, "found": False, "message": empty, "records": []}
    return {"title": title, "found": True, "message": "", "records": [list(rec.items())]}


def _changes(scn: Scenario, key: str) -> dict:
    at = scn.alert.ts
    records = []
    for c in scn.context.changes:
        scope = c["scope"]
        if scope == "*" or scope == key or fnmatch(key, scope):
            start = datetime.strptime(c["start"], "%Y-%m-%d %H:%M").replace(tzinfo=TZ)
            end = datetime.strptime(c["end"], "%Y-%m-%d %H:%M").replace(tzinfo=TZ)
            inside = start <= at <= end
            records.append([("Zmiana", c["title"]), ("Zgłoszenie", c["ticket"]), ("Okno", f"{c['start']} – {c['end']} (CET)"),
                            ("Czas alertu w oknie", "TAK" if inside else "NIE")])
    title = "Kalendarz zmian i zgłoszeń"
    if not records:
        return {"title": title, "found": False, "message": "Brak zmian ani zgłoszeń dla tego obiektu w okolicy czasu alertu.", "records": []}
    return {"title": title, "found": True, "message": "", "records": records}
