"""Stateful / correlation detections.

Each rule takes time-ordered events plus its config block and returns Findings.
Stateless pattern matching belongs in Sigma; these need windows, counters or context.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from collections.abc import Callable
from datetime import timedelta
from typing import Any
from zoneinfo import ZoneInfo

from hunterscope.models import Event, Finding, user_key

RuleFn = Callable[[list[Event], dict[str, Any], str], list[Finding]]
RULES: dict[str, RuleFn] = {}

CRED_FAILURE_CODES = {50126}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def rule(name: str) -> Callable[[RuleFn], RuleFn]:
    def register(fn: RuleFn) -> RuleFn:
        RULES[name] = fn
        return fn

    return register


def _finding(
    rule_id: str,
    cfg: dict[str, Any],
    title: str,
    description: str,
    evidence: list[Event],
    iocs: list[tuple[str, str]] | None = None,
    severity: str | None = None,
    extra_mitre: list[str] | None = None,
) -> Finding:
    mitre = list(dict.fromkeys([*cfg["mitre"], *(extra_mitre or [])]))
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity or cfg["severity"],
        tactic=cfg["tactic"],
        mitre=mitre,
        weight=float(cfg["weight"]),
        description=description,
        evidence=evidence,
        iocs=iocs or [],
    )


def _is_auth(e: Event) -> bool:
    return e.source in {"entra", "windows"} and e.action in {"signin", "logon"}


def _is_cred_failure(e: Event) -> bool:
    if not _is_auth(e) or e.outcome != "failure":
        return False
    return e.error_code in CRED_FAILURE_CODES if e.source == "entra" else True


@rule("failures_then_success")
def failures_then_success(events: list[Event], cfg: dict[str, Any], rid: str) -> list[Finding]:
    window = timedelta(minutes=cfg["window_minutes"])
    recent: dict[tuple[str, str | None], list[Event]] = defaultdict(list)
    out: list[Finding] = []
    for e in events:
        if not _is_auth(e):
            continue
        key = (user_key(e.user), e.ip)
        if _is_cred_failure(e):
            recent[key].append(e)
        elif e.outcome == "success":
            fails = [f for f in recent[key] if e.ts - f.ts <= window]
            if len(fails) >= cfg["threshold"]:
                out.append(
                    _finding(
                        rid, cfg,
                        "Brute force / password spraying succeeded",
                        f"{len(fails)} failed credential attempts from {e.ip} within "
                        f"{cfg['window_minutes']} min, then a successful authentication.",
                        [*fails, e],
                        iocs=[("ip", e.ip)] if e.ip else [],
                    )
                )
            recent[key].clear()
    return out


@rule("mfa_fatigue")
def mfa_fatigue(events: list[Event], cfg: dict[str, Any], rid: str) -> list[Finding]:
    window = timedelta(minutes=cfg["window_minutes"])
    codes = set(cfg["error_codes"])
    pending: dict[str, list[Event]] = defaultdict(list)
    out: list[Finding] = []
    for e in events:
        if e.source != "entra":
            continue
        key = user_key(e.user)
        if e.outcome == "failure" and e.error_code in codes:
            pending[key].append(e)
        elif e.outcome == "success":
            prompts = [p for p in pending[key] if e.ts - p.ts <= window]
            if len(prompts) >= cfg["threshold"]:
                out.append(
                    _finding(
                        rid, cfg,
                        "MFA fatigue: repeated denied prompts followed by success",
                        f"{len(prompts)} failed/denied MFA prompts within {cfg['window_minutes']} "
                        "min, then the sign-in was approved.",
                        [*prompts, e],
                        iocs=[("ip", e.ip)] if e.ip else [],
                    )
                )
            pending[key].clear()
    return out


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi, dlmb = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(a))


@rule("impossible_travel")
def impossible_travel(events: list[Event], cfg: dict[str, Any], rid: str) -> list[Finding]:
    last: dict[str, Event] = {}
    out: list[Finding] = []
    for e in events:
        if e.source != "entra" or e.outcome != "success" or e.lat is None or e.lon is None:
            continue
        key = user_key(e.user)
        prev = last.get(key)
        last[key] = e
        if prev is None or prev.lat is None or prev.lon is None:
            continue
        dist = haversine_km(prev.lat, prev.lon, e.lat, e.lon)
        hours = max((e.ts - prev.ts).total_seconds() / 3600, 1 / 3600)
        speed = dist / hours
        if dist >= cfg["min_distance_km"] and speed > cfg["max_speed_kmh"]:
            out.append(
                _finding(
                    rid, cfg,
                    "Impossible travel between successful sign-ins",
                    f"{prev.city or '?'}, {prev.country or '?'} -> {e.city or '?'}, "
                    f"{e.country or '?'}: {dist:.0f} km in {hours * 60:.0f} min "
                    f"(~{speed:.0f} km/h, limit {cfg['max_speed_kmh']}).",
                    [prev, e],
                    iocs=[("ip", e.ip)] if e.ip else [],
                )
            )
    return out


@rule("off_hours_login")
def off_hours_login(events: list[Event], cfg: dict[str, Any], rid: str) -> list[Finding]:
    tz = ZoneInfo(cfg["timezone"])
    hits: list[Event] = []
    for e in events:
        if not _is_auth(e) or e.outcome != "success":
            continue
        local = e.ts.astimezone(tz)
        weekend = cfg["weekends_off_hours"] and local.weekday() >= 5
        if weekend or local.hour < cfg["work_start"] or local.hour >= cfg["work_end"]:
            hits.append(e)
    if not hits:
        return []
    return [
        _finding(
            rid, cfg,
            "Successful logon outside working hours",
            f"{len(hits)} successful logon(s) outside {cfg['work_start']:02d}:00-"
            f"{cfg['work_end']:02d}:00 {cfg['timezone']}.",
            hits,
        )
    ]


_INBOX_OPS = {"new-inboxrule", "set-inboxrule", "updateinboxrules"}
_FORWARD_KEYS = ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
_KEYWORD_KEYS = ("SubjectContainsWords", "BodyContainsWords", "SubjectOrBodyContainsWords")


@rule("suspicious_inbox_rule")
def suspicious_inbox_rule(events: list[Event], cfg: dict[str, Any], rid: str) -> list[Finding]:
    internal = {d.lower() for d in cfg["internal_domains"]}
    folders = {f.lower() for f in cfg["suspicious_folders"]}
    keywords = [k.lower() for k in cfg["keywords"]]
    out: list[Finding] = []
    for e in events:
        if e.source != "ual" or e.action.lower() not in _INBOX_OPS:
            continue
        params: dict[str, str] = e.detail.get("params", {})
        reasons: list[str] = []
        iocs: list[tuple[str, str]] = []
        for key in _FORWARD_KEYS:
            for addr in EMAIL_RE.findall(params.get(key, "")):
                external = addr.rpartition("@")[2].lower() not in internal
                reasons.append(f"{key} {'external' if external else 'internal'} address {addr}")
                if external:
                    iocs.append(("email", addr))
        if params.get("DeleteMessage", "").lower() == "true":
            reasons.append("deletes matching messages")
        folder = params.get("MoveToFolder", "")
        if folder.lower() in folders:
            reasons.append(f"moves messages to '{folder}'")
        text = " ".join(params.get(k, "") for k in _KEYWORD_KEYS).lower()
        hit_words = [k for k in keywords if k in text]
        if hit_words:
            reasons.append(f"matches sensitive keywords ({', '.join(hit_words)})")
        if not reasons:
            continue
        if e.ip:
            iocs.append(("ip", e.ip))
        out.append(
            _finding(
                rid, cfg,
                f"Suspicious mailbox rule ({e.action})",
                "; ".join(reasons) + ".",
                [e],
                iocs=iocs,
            )
        )
    return out


@rule("oauth_consent")
def oauth_consent(events: list[Event], cfg: dict[str, Any], rid: str) -> list[Finding]:
    risky = {s.lower() for s in cfg["risky_scopes"]}
    out: list[Finding] = []
    for e in events:
        if e.source != "ual" or e.action.rstrip(".").lower() != "consent to application":
            continue
        params: dict[str, str] = e.detail.get("params", {})
        scopes = params.get("Scope", "").replace(",", " ").split()
        bad = [s for s in scopes if s.lower() in risky]
        app = params.get("AppName") or e.app or "unknown app"
        out.append(
            _finding(
                rid, cfg,
                f"OAuth consent granted to '{app}'",
                f"Scopes: {', '.join(scopes) or 'n/a'}."
                + (f" High-risk: {', '.join(bad)}." if bad else ""),
                [e],
                iocs=[("oauth_app", app)] + ([("ip", e.ip)] if e.ip else []),
                severity="high" if bad else cfg["severity"],
            )
        )
    return out


@rule("lotl_commandline")
def lotl_commandline(events: list[Event], cfg: dict[str, Any], rid: str) -> list[Finding]:
    patterns = [(p, re.compile(p["regex"])) for p in cfg["patterns"]]
    out: list[Finding] = []
    for e in events:
        if e.action != "process_create" or not e.command_line:
            continue
        for p, rx in patterns:
            if rx.search(e.command_line):
                out.append(
                    _finding(
                        rid, cfg,
                        f"Suspicious command line: {p['label']}",
                        f"{e.app or 'process'} on {e.host or '?'} ran: {e.command_line[:200]}",
                        [e],
                        iocs=[("command", e.command_line[:200])],
                        extra_mitre=p.get("mitre"),
                    )
                )
    return out
