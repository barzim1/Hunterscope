"""Event constructors, one per log source. They only format; what a scenario means is decided by the templates."""

from __future__ import annotations

from datetime import datetime, timezone

from hunterscope.trainer.model import TZ, Event, basename

SOURCES = {
    "sysmon": "Sysmon",
    "winsec": "Windows Security",
    "eset": "ESET",
    "proxy": "Proxy",
    "dns": "DNS",
    "fw": "Firewall",
    "entra": "Entra ID",
    "m365": "M365 Audit",
    "mail": "Poczta",
    "waf": "WAF",
}


def _local(ts: datetime) -> str:
    return ts.astimezone(TZ).strftime("%Y-%m-%d %H:%M:%S")


def _utc(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _kv(header: str, fields: dict[str, str]) -> str:
    return header + "\n" + "\n".join(f"{k}: {v}" for k, v in fields.items())


def _clip(text: str, n: int = 140) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


# --- Sysmon -----------------------------------------------------------------------------------------------------
def _sysmon(eid: int, name: str, ts: datetime, host: str, fields: dict[str, str], summary: str, user: str = "") -> Event:
    fields = {"EventID": str(eid), **fields}
    raw = _kv(f"Microsoft-Windows-Sysmon/Operational  EventID={eid} ({name})\nComputer: {host}\nTimeCreated: {_local(ts)}",
              {k: v for k, v in fields.items() if k != "EventID"})
    return Event(ts=ts, source="sysmon", host=host, user=user, summary=summary, fields=fields, raw=raw)


def sysmon_proc(ts, host, user, image, cmd, parent_image, parent_cmd, pid, ppid, *, sha256="", signed="Yes",
                signer="Microsoft Windows", integrity="Medium", cwd="", original="") -> Event:
    user_full = user if "\\" in user or user in ("SYSTEM", "NT AUTHORITY\\SYSTEM") else f"NORDWIND\\{user}"
    fields = {
        "Image": image,
        "OriginalFileName": original or basename(image),
        "CommandLine": cmd,
        "CurrentDirectory": cwd or ("C:\\Windows\\system32\\" if user_full.endswith("SYSTEM") else "C:\\Users\\"),
        "User": user_full,
        "IntegrityLevel": "System" if user_full.endswith("SYSTEM") else integrity,
        "Hashes": f"SHA256={sha256}" if sha256 else "SHA256=(not computed)",
        "Signed": signed,
        "Signature": signer if signed == "Yes" else "-",
        "ProcessId": str(pid),
        "ParentImage": parent_image,
        "ParentCommandLine": parent_cmd or parent_image,
        "ParentProcessId": str(ppid),
    }
    summary = f"{basename(parent_image)} → {basename(image)}  {_clip(cmd, 110)}"
    return _sysmon(1, "Process Create", ts, host, fields, summary, user_full)


def sysmon_net(ts, host, user, image, pid, dst_ip, dst_port, dst_host="", *, src_ip="", proto="tcp") -> Event:
    fields = {
        "Image": image, "ProcessId": str(pid), "User": user, "Protocol": proto, "Initiated": "true",
        "SourceIp": src_ip, "DestinationIp": dst_ip, "DestinationPort": str(dst_port),
        "DestinationHostname": dst_host,
    }
    summary = f"{basename(image)} → {dst_host or dst_ip}:{dst_port}"
    return _sysmon(3, "Network connection", ts, host, fields, summary, user)


def sysmon_file(ts, host, user, image, pid, target, *, size="") -> Event:
    fields = {"Image": image, "ProcessId": str(pid), "TargetFilename": target, "User": user}
    if size:
        fields["Size"] = size
    return _sysmon(11, "File created", ts, host, fields, f"{basename(image)} utworzył {target}", user)


def sysmon_motw(ts, host, user, target, host_url, referrer="", zone="3") -> Event:
    """Sysmon 15 (FileCreateStreamHash): the Zone.Identifier stream, i.e. Mark-of-the-Web."""
    contents = f"[ZoneTransfer] ZoneId={zone} HostUrl={host_url}" + (f" ReferrerUrl={referrer}" if referrer else "")
    fields = {"TargetFilename": f"{target}:Zone.Identifier", "Contents": contents, "User": user}
    return _sysmon(15, "FileCreateStreamHash", ts, host, fields, f"Mark-of-the-Web: {basename(target)} ← {host_url}", user)


def sysmon_access(ts, host, user, src, dst, access, *, calltrace="") -> Event:
    fields = {
        "SourceImage": src, "TargetImage": dst, "GrantedAccess": access, "SourceUser": user,
        "CallTrace": calltrace or "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2a5b4",
    }
    return _sysmon(10, "ProcessAccess", ts, host, fields, f"{basename(src)} → {basename(dst)} (GrantedAccess {access})", user)


def sysmon_reg(ts, host, user, image, target, details) -> Event:
    fields = {"EventType": "SetValue", "Image": image, "TargetObject": target, "Details": details, "User": user}
    return _sysmon(13, "Registry value set", ts, host, fields, f"{basename(image)} ustawił {target}", user)


# --- Windows Security -------------------------------------------------------------------------------------------
def winsec(ts, host, eid: int, title: str, fields: dict[str, str], summary: str, user: str = "") -> Event:
    fields = {"EventID": str(eid), **fields}
    raw = _kv(f"Microsoft-Windows-Security-Auditing  EventID={eid}  {title}\nComputer: {host}\nTimeCreated: {_local(ts)}",
              {k: v for k, v in fields.items() if k != "EventID"})
    return Event(ts=ts, source="winsec", host=host, user=user, summary=summary, fields=fields, raw=raw)


def logon_ok(ts, host, user, src_ip, logon_type: int, *, workstation="") -> Event:
    kinds = {2: "interaktywne", 3: "sieciowe", 10: "RDP"}
    f = {"LogonType": str(logon_type), "TargetUserName": user, "TargetDomainName": "NORDWIND", "IpAddress": src_ip,
         "WorkstationName": workstation, "AuthenticationPackageName": "Kerberos" if logon_type != 3 else "NTLM"}
    return winsec(ts, host, 4624, "An account was successfully logged on", f,
                  f"Logowanie {kinds.get(logon_type, logon_type)}: {user}" + (f" z {src_ip}" if src_ip else " (lokalnie)"), user)


def logon_fail(ts, host, user, src_ip, *, logon_type=3, status="0xC000006A", workstation="") -> Event:
    why = {"0xC000006A": "złe hasło", "0xC0000064": "nieznany użytkownik", "0xC0000234": "konto zablokowane"}
    f = {"LogonType": str(logon_type), "TargetUserName": user, "TargetDomainName": "NORDWIND", "IpAddress": src_ip,
         "WorkstationName": workstation, "Status": "0xC000006D", "SubStatus": status}
    return winsec(ts, host, 4625, "An account failed to log on", f,
                  f"Nieudane logowanie ({why.get(status, status)}): {user} z {src_ip}", user)


# --- ESET -------------------------------------------------------------------------------------------------------
def eset(ts, computer, user, threat, threat_type, obj_type, obj, sha1, action, handled, process, detector,
         severity="Threat", *, reputation="Unknown", popularity="Rare", extra: dict[str, str] | None = None) -> Event:
    """ESET PROTECT 'Detections' row. Field names follow the console; values are simulated."""
    f = {
        "Computer name": computer, "Detection": threat, "Threat type": threat_type, "Object type": obj_type,
        "Object": obj, "SHA-1": sha1, "Action taken": action, "Handled": "Yes" if handled else "No",
        "Process": process, "User": user, "Detector": detector, "Severity": severity,
        "LiveGrid reputation": reputation, "LiveGrid popularity": popularity, **(extra or {}),
    }
    raw = _kv(f"ESET PROTECT: Detections\nOccurred: {_local(ts)}", f)
    return Event(ts=ts, source="eset", host=computer, user=user, summary=f"{threat}: {_clip(obj, 70)} → {action}",
                 fields=f, raw=raw)


# --- network ----------------------------------------------------------------------------------------------------
def proxy(ts, src_ip, user, method, url, status, bytes_out, bytes_in, *, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
          category="Business", action="Allowed", host="", content_type="") -> Event:
    f = {
        "SourceIp": src_ip, "User": user, "Method": method, "Url": url, "Status": str(status),
        "BytesOut": str(bytes_out), "BytesIn": str(bytes_in), "UserAgent": ua, "Category": category,
        "Action": action,
    }
    if content_type:
        f["ContentType"] = content_type
    raw = (f'{_local(ts)} {src_ip} {user or "-"} "{method} {url}" {status} out={bytes_out} in={bytes_in} '
           f'cat="{category}" action={action} ua="{ua}"')
    short = url.split("://", 1)[-1]
    return Event(ts=ts, source="proxy", host=host, user=user, summary=f"{method} {_clip(short, 80)} → {status} ({bytes_in} B)",
                 fields=f, raw=raw)


def dns(ts, client_ip, qname, qtype="A", rcode="NOERROR", answer="", *, host="") -> Event:
    f = {"ClientIp": client_ip, "QueryName": qname, "QueryType": qtype, "ResponseCode": rcode, "Answer": answer}
    raw = f"{_local(ts)} client={client_ip} query={qname} type={qtype} rcode={rcode} answer={answer or '-'}"
    return Event(ts=ts, source="dns", host=host, summary=f"{qtype}? {_clip(qname, 90)} → {rcode}", fields=f, raw=raw)


def fw(ts, action, proto, src, sport, dst, dport, *, bytes_out=0, bytes_in=0, rule="", app="", host="") -> Event:
    f = {"Action": action, "Protocol": proto, "SourceIp": src, "SourcePort": str(sport), "DestinationIp": dst,
         "DestinationPort": str(dport), "BytesOut": str(bytes_out), "BytesIn": str(bytes_in), "Rule": rule, "App": app}
    raw = (f"{_local(ts)} action={action} proto={proto} src={src}:{sport} dst={dst}:{dport} "
           f"bytes_out={bytes_out} bytes_in={bytes_in} rule={rule!r} app={app!r}")
    return Event(ts=ts, source="fw", host=host, summary=f"{action.upper()} {proto} {src}:{sport} → {dst}:{dport}",
                 fields=f, raw=raw)


def waf(ts, src_ip, method, uri, status, rule, action, bytes_in, *, ua="", host="SRV-WEB01", user="") -> Event:
    f = {"SourceIp": src_ip, "Method": method, "Uri": uri, "Status": str(status), "Rule": rule, "Action": action,
         "BytesIn": str(bytes_in), "UserAgent": ua, "User": user}
    raw = f'{_local(ts)} waf src={src_ip} "{method} {uri}" status={status} action={action} rule="{rule}" resp={bytes_in} ua="{ua}"'
    return Event(ts=ts, source="waf", host=host, user=user, summary=f"{method} {_clip(uri, 80)} → {status} [{action}]",
                 fields=f, raw=raw)


# --- cloud identity and mail ------------------------------------------------------------------------------------
_ENTRA_ERR = {
    0: "Success", 50126: "Invalid username or password", 50076: "MFA required", 500121: "MFA failed",
    50053: "Account locked", 53003: "Blocked by Conditional Access",
}


def entra(ts, upn, ip, country, city, app, *, error=0, client="Browser", ua="", device_id="", managed="No", mfa="",
          mfa_detail="", os="", display="") -> Event:
    ok = error == 0
    f = {
        "UserPrincipalName": upn, "IpAddress": ip, "Location": f"{city}, {country}", "Application": app,
        "ClientApp": client, "Status": "Success" if ok else "Failure", "ErrorCode": str(error),
        "FailureReason": _ENTRA_ERR.get(error, "Other") if not ok else "-",
        "DeviceId": device_id or "-", "DeviceManaged": managed, "OS": os or "-",
        "AuthenticationRequirement": mfa or "singleFactorAuthentication", "MfaDetail": mfa_detail or "-",
        "UserAgent": ua or "-",
    }
    raw = _kv(f"Entra ID SignInLogs  createdDateTime(UTC)={_utc(ts)}", f)
    state = "OK" if ok else f"FAIL {error}"
    return Event(ts=ts, source="entra", user=upn, summary=f"Logowanie {state}: {upn} z {city}, {country} ({ip}) [{client}]",
                 fields=f, raw=raw)


def m365(ts, upn, operation, ip, *, details: dict[str, str] | None = None, client="") -> Event:
    f = {"UserId": upn, "Operation": operation, "ClientIP": ip, "ClientInfoString": client or "-", **(details or {})}
    raw = _kv(f"Unified Audit Log  CreationTime(UTC)={_utc(ts)}", f)
    return Event(ts=ts, source="m365", user=upn, summary=f"{operation}: {upn} z {ip}", fields=f, raw=raw)


def mail(ts, sender, rcpt, subject, attachment="", *, spf="pass", dkim="pass", dmarc="pass", verdict="Delivered",
         sender_ip="", host="SRV-MGW01", extra: dict[str, str] | None = None) -> Event:
    f = {"From": sender, "To": rcpt, "Subject": subject, "Attachment": attachment or "-", "SPF": spf, "DKIM": dkim,
         "DMARC": dmarc, "SenderIp": sender_ip or "-", "Verdict": verdict, **(extra or {})}
    raw = _kv(f"Mail gateway  {_local(ts)}", f)
    att = f" [{attachment}]" if attachment else ""
    return Event(ts=ts, source="mail", host=host, user=rcpt, summary=f"{sender} → {rcpt}: {_clip(subject, 60)}{att}",
                 fields=f, raw=raw)
