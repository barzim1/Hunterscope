"""Which Sigma `logsource`s a flat Windows event record belongs to, and field aliases for Security 4688."""

from __future__ import annotations

from hunterscope.sigma.rule import Rec

SYSMON_CHANNEL = "microsoft-windows-sysmon/operational"

_SYSMON_CATEGORY: dict[str, tuple[str, ...]] = {
    "1": ("process_creation",),
    "2": ("file_change",),
    "3": ("network_connection",),
    "5": ("process_termination",),
    "6": ("driver_load",),
    "7": ("image_load",),
    "8": ("create_remote_thread",),
    "9": ("raw_access_thread",),
    "10": ("process_access",),
    "11": ("file_event",),
    "12": ("registry_event",),
    "13": ("registry_event", "registry_set"),
    "14": ("registry_event", "registry_rename"),
    "15": ("create_stream_hash",),
    "17": ("pipe_created",),
    "18": ("pipe_created",),
    "19": ("wmi_event",),
    "20": ("wmi_event",),
    "21": ("wmi_event",),
    "22": ("dns_query",),
    "23": ("file_delete",),
    "25": ("process_tampering",),
    "26": ("file_delete",),
}

_SERVICE_BY_CHANNEL = {
    "security": "security",
    "system": "system",
    "application": "application",
    SYSMON_CHANNEL: "sysmon",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell-classic",
    "microsoft-windows-taskscheduler/operational": "taskscheduler",
    "microsoft-windows-wmi-activity/operational": "wmi",
}

SUPPORTED_CATEGORIES = {c for cats in _SYSMON_CATEGORY.values() for c in cats} | {
    "process_creation", "registry_add", "registry_delete",
}
SUPPORTED_SERVICES = set(_SERVICE_BY_CHANNEL.values())

# Sysmon field name <- Security 4688 field name. Rules are written against the Sysmon names.
_ALIASES_4688 = {
    "image": "newprocessname",
    "parentimage": "parentprocessname",
    "user": "subjectusername",
}


def keys_for(rec: Rec) -> tuple[tuple[str, ...], str | None]:
    """(categories, service) this record can satisfy. Adds Sysmon-style aliases in place for 4688."""
    channel = rec.l.get("channel", "")
    event_id = rec.l.get("eventid", "")
    service = _SERVICE_BY_CHANNEL.get(channel)
    cats: tuple[str, ...] = ()
    if service == "sysmon":
        cats = _SYSMON_CATEGORY.get(event_id, ())
        if event_id == "12":
            kind = rec.l.get("eventtype", "")
            if kind == "createkey":
                cats += ("registry_add",)
            elif kind in {"deletekey", "deletevalue"}:
                cats += ("registry_delete",)
    elif service == "security" and event_id == "4688":
        cats = ("process_creation",)
        for sysmon_name, security_name in _ALIASES_4688.items():
            if sysmon_name not in rec.l and security_name in rec.l:
                rec.l[sysmon_name] = rec.l[security_name]
                rec.o[sysmon_name] = rec.o[security_name]
    return cats, service
