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


def parse_windows(rec: dict[str, Any]) -> Event:
    """Windows Security / Sysmon event exported as flat JSON (Winlogbeat/WEF style)."""
    event_id = int(rec["EventID"])
    user = rec.get("User") or rec.get("SubjectUserName") or rec.get("TargetUserName")
    base: dict[str, Any] = {
        "ts": rec["TimeCreated"],
        "source": "windows",
        "user": user,
        "host": rec.get("Computer"),
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
    if "EventID" in rec and "TimeCreated" in rec:
        return "windows"
    return None


PARSERS = {"entra": parse_entra, "ual": parse_ual, "windows": parse_windows}
