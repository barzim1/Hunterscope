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


@rule("lsass_access")
def lsass_access(events: list[Event], cfg: dict[str, Any], rid: str) -> list[Finding]:
    """Credential dumping signal from Sysmon 10. One finding per (host, source process), not per event:
    legitimate and malicious tools alike open lsass many times in a row."""
    target = re.compile(cfg["target"])
    allowed = [re.compile(p) for p in cfg["allowed_sources"]]
    bit = int(cfg["vm_read_bit"])
    groups: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.action != "process_access" or not target.search(e.detail.get("target_image", "")):
            continue
        try:
            mask = int(str(e.detail.get("granted_access", "")), 16)
        except ValueError:
            continue
        src = e.app or ""
        if not mask & bit or any(a.search(src) for a in allowed):
            continue
        groups[((e.host or "").lower(), src.lower())].append(e)
    out: list[Finding] = []
    for (host, _), evs in groups.items():
        src = evs[0].app or ""  # original casing for display and IOCs; grouping key is lower-cased
        masks = sorted({str(e.detail["granted_access"]).lower() for e in evs})
        out.append(
            _finding(
                rid, cfg,
                f"Process read access to lsass.exe from {src.rsplit(chr(92), 1)[-1] or '?'}",
                f"{src or '?'} opened lsass.exe {len(evs)} time(s) on {host or '?'} with memory-read "
                f"access (GrantedAccess {', '.join(masks)}).",
                evs,
                iocs=[("process", src)] if src else [],
            )
        )
    return out


# --------------------------------------------------------------------------- phishing

_LEET = str.maketrans("0134578", "oleastb")
_DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(exe|scr|js|vbs|lnk|html?|bat|cmd)$", re.I)
_DOMAIN_IN_TEXT = re.compile(
    r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)|\b([\w-]+(?:\.[\w-]+)*\.(?:com|net|org|pl|eu|io))\b", re.I
)
_URL_LIKE_TEXT = re.compile(r"^(?:https?://)?([\w-]+(?:\.[\w-]+)+)(?:[/?#]\S*)?$", re.I)


def defang(value: str) -> str:
    """hxxp://evil[.]test: safe to paste into tickets and chat."""
    return re.sub(r"^http", "hxxp", value, flags=re.I).replace(".", "[.]")


def _host(url: str) -> str:
    from urllib.parse import urlsplit

    return (urlsplit(url).hostname or "").lower().removeprefix("www.")


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _in_domain(domain: str, domains: set[str]) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in domains)


def email_signals(e: Event, cfg: dict[str, Any]) -> tuple[list[str], list[str], list[tuple[str, str]]]:
    """Return (strong signals, weak signals, IOCs) for one email event."""
    d = e.detail
    internal = {x.lower() for x in cfg["internal_domains"]}
    strong: list[str] = []
    weak: list[str] = []
    iocs: list[tuple[str, str]] = []

    from_addr: str = d.get("from_addr", "")
    from_dom = from_addr.rpartition("@")[2]
    external_sender = bool(from_dom) and not _in_domain(from_dom, internal)

    for key in ("spf", "dkim", "dmarc"):
        if d.get(key) in {"fail", "softfail", "permerror"}:
            strong.append(f"{key.upper()} {d[key]}")

    if from_dom.startswith("xn--") or ".xn--" in from_dom:
        strong.append(f"punycode sender {from_addr}")
    if external_sender:
        label = from_dom.translate(_LEET)
        for dom in internal:
            brand = dom.split(".")[0]
            if brand in label or _edit_distance(label, dom) <= 2:
                strong.append(f"sender {from_addr} imitates {dom}")
                break
    name_dom = _DOMAIN_IN_TEXT.search(d.get("from_name", ""))
    if name_dom:
        shown = (name_dom.group(1) or name_dom.group(2)).lower()
        if shown != from_dom:
            strong.append(f"display name shows {shown} but sender is {from_addr}")

    for att in d.get("attachments", []):
        name = str(att["filename"])
        ext = name.rpartition(".")[2].lower()
        if ext in cfg["risky_extensions"] or _DOUBLE_EXT.search(name):
            strong.append(f"risky attachment {name}")
            iocs.append(("sha256", str(att["sha256"])))

    for link in d.get("urls", []):
        host = _host(link["href"])
        if _is_ip(host):
            strong.append(f"link to raw IP {host}")
        elif host in cfg["shorteners"]:
            weak.append(f"URL shortener {host}")
        m = _URL_LIKE_TEXT.match(link.get("text", ""))
        if m and not _in_domain(host, {m.group(1).lower().removeprefix("www.")}):
            strong.append(f"link text shows {m.group(1)} but points to {host}")
        iocs.append(("url", defang(link["href"])))

    reply_dom = d.get("reply_to", "").rpartition("@")[2]
    if reply_dom and reply_dom != from_dom:
        weak.append(f"Reply-To {d['reply_to']} differs from sender")
    path_dom = d.get("return_path", "").rpartition("@")[2]
    if path_dom and from_dom and not (path_dom == from_dom or path_dom.endswith("." + from_dom)):
        weak.append(f"Return-Path {d['return_path']} differs from sender")
    subject = d.get("subject", "").lower()
    lures = [k for k in cfg["lure_keywords"] if k in subject]
    if lures:
        weak.append(f"lure keywords in subject ({', '.join(lures)})")

    if external_sender and from_addr:
        iocs.append(("sender", from_addr))
    return list(dict.fromkeys(strong)), weak, iocs


def _edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@rule("suspicious_email")
def suspicious_email(events: list[Event], cfg: dict[str, Any], rid: str) -> list[Finding]:
    out: list[Finding] = []
    for e in events:
        if e.source != "email":
            continue
        strong, weak, iocs = email_signals(e, cfg)
        if not strong and len(weak) < cfg["weak_signals_needed"]:
            continue
        if e.ip:
            iocs.append(("ip", e.ip))
        subject = e.detail.get("subject", "")
        out.append(
            _finding(
                rid, cfg,
                f"Suspicious email: {subject[:80]}",
                "; ".join([*strong, *weak]) + ".",
                [e],
                iocs=iocs,
                severity="high" if len(strong) >= 2 else cfg["severity"],
            )
        )
    return out


# ------------------------------------------------------------------- meta rules

MetaRuleFn = Callable[[list[Event], dict[str, Any], str, list[Finding]], list[Finding]]
META_RULES: dict[str, MetaRuleFn] = {}


def meta_rule(name: str) -> Callable[[MetaRuleFn], MetaRuleFn]:
    def register(fn: MetaRuleFn) -> MetaRuleFn:
        META_RULES[name] = fn
        return fn

    return register


@meta_rule("phish_then_new_signin")
def phish_then_new_signin(
    events: list[Event], cfg: dict[str, Any], rid: str, findings: list[Finding]
) -> list[Finding]:
    """Suspicious email, then a successful sign-in from an IP the user never used before it."""
    window = timedelta(hours=cfg["window_hours"])
    out: list[Finding] = []
    for f in findings:
        if f.rule_id != "suspicious_email":
            continue
        mail = f.evidence[0]
        key = user_key(mail.user)
        signins = [
            e for e in events
            if e.source == "entra" and e.outcome == "success" and user_key(e.user) == key and e.ip
        ]
        baseline = {e.ip for e in signins if e.ts < mail.ts}
        if not baseline:
            continue  # no history: cannot call an IP "new"
        hit = next((e for e in signins if mail.ts < e.ts <= mail.ts + window and e.ip not in baseline), None)
        if hit is None:
            continue
        gap = int((hit.ts - mail.ts).total_seconds() // 60)
        out.append(
            _finding(
                rid, cfg,
                "Possible account takeover after suspicious email",
                f"Sign-in from previously unseen IP {hit.ip} ({hit.city or '?'}, {hit.country or '?'}) "
                f"{gap} min after the suspicious email '{mail.detail.get('subject', '')[:60]}'.",
                [mail, hit],
                iocs=[("ip", hit.ip)] if hit.ip else [],
            )
        )
    return out
