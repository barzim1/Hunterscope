"""Source-specific parsers: raw record (dict) -> normalized Event."""

from __future__ import annotations

import re
from typing import Any

from hunterscope.models import Event

_IPV4_WITH_PORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$")
_IPV6_WITH_PORT = re.compile(r"^\[([0-9a-fA-F:]+)\]:\d+$")

_ENTRA_REASONS = {
    0: "Success",
    50126: "Invalid username or password",
    50053: "Account locked",
    50074: "Strong authentication required",
    50076: "MFA required",
    500121: "MFA failed / prompt denied or unanswered",
}


def _clean_ip(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if value in {"-", ""}:
        return None
    for pattern in (_IPV4_WITH_PORT, _IPV6_WITH_PORT):
        m = pattern.match(value)
        if m:
            return m.group(1)
    return value


def parse_entra(rec: dict[str, Any]) -> Event:
    """Entra ID sign-in log (Microsoft Graph `signIn` resource shape)."""
    status = rec.get("status") or {}
    code = int(status.get("errorCode", 0))
    loc = rec.get("location") or {}
    geo = loc.get("geoCoordinates") or {}
    return Event(
        ts=rec["createdDateTime"],
        source="entra",
        action="signin",
        outcome="success" if code == 0 else "failure",
        user=rec.get("userPrincipalName"),
        ip=_clean_ip(rec.get("ipAddress")),
        app=rec.get("appDisplayName"),
        country=loc.get("countryOrRegion"),
        city=loc.get("city"),
        lat=geo.get("latitude"),
        lon=geo.get("longitude"),
        error_code=code,
        detail={
            "client_app": rec.get("clientAppUsed"),
            "reason": status.get("failureReason") or _ENTRA_REASONS.get(code),
        },
    )


def parse_ual(rec: dict[str, Any]) -> Event:
    """Microsoft 365 Unified Audit Log record."""
    params: dict[str, str] = {}
    for p in rec.get("Parameters") or []:
        params[str(p.get("Name"))] = str(p.get("Value", ""))
    status = str(rec.get("ResultStatus", "")).lower()
    outcome = "success" if status in {"true", "succeeded", "success"} else (
        "failure" if status in {"false", "failed"} else "unknown"
    )
    return Event(
        ts=rec["CreationTime"],
        source="ual",
        action=str(rec["Operation"]),
        outcome=outcome,
        user=rec.get("UserId"),
        ip=_clean_ip(rec.get("ClientIP")),
        app=params.get("AppName"),
        detail={"params": params},
    )


_WIN_PROCESS_IDS = {1, 4688}
_WIN_GROUP_IDS = {4728, 4732, 4756}


_WIN_TIME_KEYS = ("TimeCreated", "@timestamp", "EventTime", "UtcTime")


def _win_time(rec: dict[str, Any]) -> Any:
    """Exports differ: Winlogbeat uses TimeCreated/@timestamp, NXLog (older OTRF sets) uses EventTime."""
    for key in _WIN_TIME_KEYS:
        if rec.get(key):
            return rec[key]
    raise KeyError("no timestamp field")


def _win_user(rec: dict[str, Any], event_id: int) -> str | None:
    """Sysmon has `User`. Security 4624/4625 log the *target* account (Subject is the machine/SYSTEM);
    every other Security event we handle acts as the subject."""
    if rec.get("User") or rec.get("SourceUser"):
        return str(rec.get("User") or rec["SourceUser"])
    prefix = "Target" if event_id in {4624, 4625} else "Subject"
    name = rec.get(f"{prefix}UserName")
    if not name or name == "-":
        return None
    domain = rec.get(f"{prefix}DomainName")
    return f"{domain}\\{name}" if domain and domain != "-" else str(name)


def parse_windows(rec: dict[str, Any]) -> Event:
    """Windows Security / Sysmon event as flat JSON (Winlogbeat/WEF/OTRF style)."""
    event_id = int(rec["EventID"])
    base: dict[str, Any] = {
        "ts": _win_time(rec),
        "source": "windows",
        "user": _win_user(rec, event_id),
        "host": rec.get("Computer") or rec.get("Hostname"),
        "ip": _clean_ip(rec.get("IpAddress")),
        "detail": {"event_id": event_id},
    }
    if event_id in _WIN_PROCESS_IDS:
        return Event(
            **base,
            action="process_create",
            outcome="success",
            command_line=rec.get("CommandLine"),
            app=rec.get("Image") or rec.get("NewProcessName"),
        )
    if event_id == 10:  # Sysmon ProcessAccess
        base["detail"] = {
            **base["detail"],
            "target_image": rec.get("TargetImage") or "",
            "granted_access": rec.get("GrantedAccess") or "",
            "call_trace": rec.get("CallTrace") or "",
        }
        return Event(**base, action="process_access", outcome="success", app=rec.get("SourceImage"))
    if event_id == 4624:
        return Event(**base, action="logon", outcome="success")
    if event_id == 4625:
        return Event(**base, action="logon", outcome="failure")
    if event_id in _WIN_GROUP_IDS:
        return Event(**base, action="group_add", outcome="success")
    return Event(**base, action=f"event_{event_id}", outcome="unknown")


def detect_source(rec: dict[str, Any]) -> str | None:
    if "createdDateTime" in rec and "userPrincipalName" in rec:
        return "entra"
    if "CreationTime" in rec and "Operation" in rec:
        return "ual"
    if "EventID" in rec and any(k in rec for k in _WIN_TIME_KEYS):
        return "windows"
    return None


PARSERS = {"entra": parse_entra, "ual": parse_ual, "windows": parse_windows}
