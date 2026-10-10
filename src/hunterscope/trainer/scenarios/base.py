"""Scenario builder, template registry and background noise shared by every scenario template."""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from hunterscope.trainer import sources as src
from hunterscope.trainer.model import TZ, Alert, Context, Event, Lessons, Scenario, Truth, basename
from hunterscope.trainer.world import BENIGN_SITES, Person, Remote, World, anchor

# What a careful analyst does by default for each verdict; templates add what is specific to the case.
_DEFAULT_REQUIRED = {"tp": ["escalate_l2"], "btp": ["close"], "fp": ["close"]}
_DEFAULT_HARMFUL = {
    "tp": ["close", "close_tune"],
    "btp": ["escalate_l2", "isolate_host", "reset_creds"],
    "fp": ["escalate_l2", "isolate_host", "reset_creds"],
}


@dataclass
class Proc:
    pid: int
    image: str
    cmd: str


@dataclass
class Template:
    id: str
    variants: tuple[str, ...]
    lessons: Lessons
    build: Callable[[Builder, str], None]


REGISTRY: dict[str, Template] = {}


def template(tid: str, variants: tuple[str, ...], lessons: Lessons):
    def deco(fn: Callable[[Builder, str], None]):
        REGISTRY[tid] = Template(tid, variants, lessons, fn)
        return fn

    return deco


class Builder:
    def __init__(self, token: str, template_id: str, difficulty: int, rng: random.Random, world: World, t0: datetime):
        self.token = token
        self.template_id = template_id
        self.difficulty = difficulty
        self.rng = rng
        self.w = world
        self.t0 = t0
        self.events: list[Event] = []
        self.ctx = Context()
        self.people: dict[str, Person] = {}
        self.result: Scenario | None = None
        self._hosts_used: set[str] = set()

    # --- time and events --------------------------------------------------------------------------------------
    def t(self, minutes: float = 0, seconds: float = 0) -> datetime:
        """Time relative to the alert; negative minutes are earlier."""
        return self.t0 + timedelta(minutes=minutes, seconds=seconds)

    def add(self, ev: Event) -> Event:
        self.events.append(ev)
        return ev

    def at_hour(self, hour: int, minute: int | None = None, *, weekday: bool = True) -> None:
        self.t0 = anchor(self.rng, hour, minute, weekday)

    @property
    def hard(self) -> bool:
        return self.difficulty >= 3

    # --- people and hosts -------------------------------------------------------------------------------------
    def person(self, dept: str | None = None, **ctx_user) -> Person:
        p = self.w.person(dept)
        self.use(p, **ctx_user)
        return p

    def use(self, p: Person, **ctx_user) -> Person:
        self.people[p.sam] = p
        rng = self.rng
        self.ctx.users[p.sam] = {
            "Użytkownik": f"{p.display} ({p.sam})",
            "Stanowisko": f"{p.title}, {p.dept}",
            "Przełożony": p.manager,
            "Status HR": "Aktywny",
            "Typowe godziny pracy": "08:00–16:00, pn–pt",
            "Typowa lokalizacja": "Warszawa (biuro HQ)",
            "MFA": "Microsoft Authenticator (powiadomienie push)",
            "Ostatnia zmiana hasła": f"{rng.randint(20, 80)} dni temu",
            "Uprawnienia": "Użytkownik standardowy, bez praw lokalnego administratora",
            "Delegacje / urlopy": "brak wpisów",
            **ctx_user,
        }
        self.ctx.assets[p.host.lower()] = {
            "Host": p.host,
            "Typ": "Stacja robocza",
            "Właściciel": f"{p.display} ({p.dept})",
            "System": "Windows 11 23H2",
            "Adres IP (DHCP)": p.ip,
            "Krytyczność": "Niska",
            "ESET": "Endpoint Security 11.0, moduły aktualne (wczoraj)",
            "Ostatni patch": f"{rng.randint(3, 25)} dni temu",
            "Lokalny administrator": "Nie",
            "Uwagi": "-",
        }
        return p

    def server(self, name: str, **ctx_asset):
        s = self.w.server(name)
        self.ctx.assets[name.lower()] = {
            "Host": s.name,
            "Typ": "Serwer",
            "Rola": s.role,
            "System": s.os,
            "Adres IP": s.ip,
            "Krytyczność": s.criticality,
            "Właściciel": s.owner,
            "ESET": "Server Security 10.0, moduły aktualne (dzisiaj)",
            "Uwagi": "-",
            **ctx_asset,
        }
        return s

    def admin(self, sam: str, display: str, **ctx_user) -> str:
        self.ctx.users[sam] = {
            "Użytkownik": f"{display} ({sam})",
            "Stanowisko": "Administrator systemów, IT",
            "Status HR": "Aktywny",
            "Typowe godziny pracy": "08:00–16:00, pn–pt; okna serwisowe wg kalendarza zmian",
            "Uprawnienia": "Konto administracyjne (Domain Admins nie, Server Operators tak)",
            "MFA": "Klucz sprzętowy FIDO2",
            **ctx_user,
        }
        return sam

    # --- processes --------------------------------------------------------------------------------------------
    def spawn(self, parent: Proc, image: str, cmd: str, ts: datetime, host: str, user: str, *, signed="Yes",
              signer="Microsoft Windows", sha256="", integrity="Medium", cwd="", original="", record=True) -> tuple[Event, Proc]:
        pid = self.w.pid()
        ev = src.sysmon_proc(ts, host, user, image, cmd, parent.image, parent.cmd, pid, parent.pid,
                             sha256=sha256 or self.w.digest(basename(image).lower()), signed=signed, signer=signer,
                             integrity=integrity, cwd=cwd, original=original)
        if record:
            self.add(ev)
        return ev, Proc(pid, image, cmd)

    def session(self, p: Person, hours_ago: float = 3.0) -> dict[str, Proc]:
        """A normal logged-in desktop (explorer, Outlook, Chrome) so scenario processes have realistic parents."""
        root = Proc(self.w.pid(), r"C:\Windows\System32\userinit.exe", "userinit.exe")
        t = self.t(minutes=-hours_ago * 60)
        _, explorer = self.spawn(root, r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE", t, p.host, p.sam,
                                 cwd="C:\\Windows\\system32\\")
        procs = {"explorer": explorer}
        for name, image, cmd, signer in [
            ("outlook", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", r'"OUTLOOK.EXE"', "Microsoft Corporation"),
            ("chrome", r"C:\Program Files\Google\Chrome\Application\chrome.exe", r'"chrome.exe"', "Google LLC"),
        ]:
            t = t + timedelta(minutes=self.rng.uniform(0.2, 2))
            _, procs[name] = self.spawn(explorer, image, cmd, t, p.host, p.sam, signer=signer, cwd=p.profile)
        return procs

    # --- threat intel -----------------------------------------------------------------------------------------
    def ti_bad(self, indicator: str, kind: str, *, age_days=3, tags: str = "", hosts_seen=1) -> None:
        d = self.difficulty
        verdict, sources = (
            ("Złośliwy", f"{self.rng.randint(11, 19)}/90 silników") if d == 1
            else ("Podejrzany", f"{self.rng.randint(2, 5)}/90 silników") if d == 2
            else ("Brak jednoznacznej klasyfikacji", "0/90 silników (świeży wskaźnik)")
        )
        self.ctx.ti[indicator.lower()] = {
            "Wskaźnik": indicator, "Typ": kind, "Werdykt TI (symulacja)": verdict, "Źródła": sources,
            "Pierwszy raz widziany": f"{age_days} dni temu",
            "Wiek rejestracji domeny" if kind == "domena" else "Wiek wskaźnika": f"{age_days} dni",
            "Tagi": tags or "-",
            "Występowanie w organizacji": f"{hosts_seen} host w ostatnich 30 dniach",
            "Komentarz": "Brak wpisu nie oznacza, że wskaźnik jest bezpieczny: sprawdź wiek i kontekst."
            if d >= 3 else "-",
        }

    def threat(self, *, site_only: bool = False, brand: str = "", kind: str = "") -> Remote:
        """Attacker infrastructure. Not always a throw-away domain: see `world.Remote`."""
        return self.w.threat_host(self.difficulty, site_only=site_only, brand=brand, kind=kind)

    def ti_threat(self, remote: Remote, *, ip: str = "", tags: str = "", ip_tags: str = "") -> None:
        """Threat intel for attacker infrastructure. A shared service is clean by reputation: only behaviour betrays it."""
        if remote.kind == "service":
            self.ti_good(remote.zone, "domena", owner=remote.owner, age_years=10, hosts_seen=300,
                         note="Wskaźnik dotyczy usługi współdzielonej, nie konkretnej zawartości. Czysta reputacja domeny "
                              "niczego nie przesądza: oceń proces, który pobiera, URL i kontekst.")
            if ip:
                self.ti_good(ip, "IP", owner=f"{remote.owner}, zakres dostawcy usługi", age_years=8, hosts_seen=300)
            return
        self.ti_bad(remote.name, "domena", age_days=remote.age_days, tags=tags or remote.kind)
        if ip:
            self.ti_bad(ip, "IP", age_days=min(remote.age_days, 30), tags=ip_tags or "hosting")

    def ti_good(self, indicator: str, kind: str, *, owner: str, age_years=10, hosts_seen=150, note="-") -> None:
        self.ctx.ti[indicator.lower()] = {
            "Wskaźnik": indicator, "Typ": kind, "Werdykt TI (symulacja)": "Czysty, znany dostawca",
            "Właściciel": owner, "Pierwszy raz widziany": f"{age_years} lat temu",
            "Występowanie w organizacji": f"{hosts_seen} hostów w ostatnich 30 dniach", "Komentarz": note,
        }

    def change(self, scope: str, start: datetime, end: datetime, title: str, ticket: str) -> None:
        self.ctx.changes.append({
            "scope": scope.lower(), "title": title, "ticket": ticket,
            "start": start.astimezone(TZ).strftime("%Y-%m-%d %H:%M"), "end": end.astimezone(TZ).strftime("%Y-%m-%d %H:%M"),
        })

    # --- finishing --------------------------------------------------------------------------------------------
    def truth(self, verdict: str, severity: str, summary: str, note: str, *, required=(), harmful=(),
              lookups=(), drop=(), allow=()) -> Truth:
        """`drop` removes a default required action, `allow` removes a default harmful one (e.g. closing a contained TP)."""
        req = [a for a in dict.fromkeys([*_DEFAULT_REQUIRED[verdict], *required]) if a not in drop]
        bad = [a for a in dict.fromkeys([*_DEFAULT_HARMFUL[verdict], *harmful]) if a not in req and a not in allow]
        return Truth(verdict, severity, summary, note, req, bad, list(lookups))

    def finish(self, trigger: Event, *, source: str, rule: str, severity: str, description: str, truth: Truth,
               lessons: Lessons, file: dict | None = None) -> Scenario:
        nat = self.w.office_nat_ip()
        self.ti_good(nat, "IP", owner="Nordwind Logistics (adres wyjściowy biura, NAT)", age_years=10, hosts_seen=400,
                     note="Własny adres firmy: logowania stąd są zwykle zgodne z pracą w biurze.")
        self.events.sort(key=lambda e: e.ts)
        for i, e in enumerate(self.events, 1):
            e.id = f"E{i:03d}"
        if trigger not in self.events:
            raise ValueError("alert trigger must be one of the scenario events")
        alert = Alert(source, rule, severity, trigger.ts, trigger.host, trigger.user, description, trigger)
        self.result = Scenario(self.token, self.template_id, self.difficulty, alert, self.events, self.ctx, truth,
                               lessons, file)
        return self.result


# --- noise ------------------------------------------------------------------------------------------------------
_OFFICE_PROCS = [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", '"chrome.exe" --type=renderer --lang=pl', "Google LLC"),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", '"OUTLOOK.EXE"', "Microsoft Corporation"),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", '"EXCEL.EXE" /dde', "Microsoft Corporation"),
    (r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "OneDrive.exe /background", "Microsoft Corporation"),
    (r"C:\Program Files\WindowsApps\MSTeams\ms-teams.exe", "ms-teams.exe", "Microsoft Corporation"),
    (r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs -p -s Schedule", "Microsoft Windows"),
]


def noise(b: Builder, *, profile: str = "office", involved: list[Person] | None = None) -> None:
    """Background events in the 3 hours before the alert and 20 minutes after. `night` is much quieter."""
    rng, w = b.rng, b.w
    people = list(involved or b.people.values())
    background = [w.person() for _ in range(rng.randint(5, 8))]
    pool = background + people
    n = {1: 25, 2: 55, 3: 100}[b.difficulty]
    n = n if profile == "office" else max(6, n // 4)
    for _ in range(n):
        ts = b.t(minutes=-rng.uniform(-20, 180))
        p = rng.choice(pool)
        kind = rng.choice(["proxy", "proxy", "dns", "dns", "logon", "proc", "fw", "entra"] if profile == "office"
                          else ["dns", "fw", "proc", "logon"])
        site = rng.choice(BENIGN_SITES)
        if kind == "proxy":
            b.add(src.proxy(ts, p.ip, p.sam, "GET", f"https://{site}/", 200, rng.randint(400, 2400),
                            rng.randint(4_000, 400_000), host=p.host))
        elif kind == "dns":
            b.add(src.dns(ts, p.ip, site, "A", "NOERROR", w.service_ip(), host=p.host))
        elif kind == "logon":
            if profile == "night":
                b.add(src.logon_ok(ts, "SRV-BKP01", "svc_backup", "10.10.30.20", 3))
            else:
                b.add(src.logon_ok(ts, p.host, p.sam, "", 2) if rng.random() < 0.5
                      else src.logon_ok(ts, "SRV-FILE01", p.sam, p.ip, 3, workstation=p.host))
        elif kind == "proc":
            image, cmd, signer = rng.choice(_OFFICE_PROCS)
            image = image.replace("{u}", p.sam)
            parent = Proc(w.pid(), r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE")
            b.spawn(parent, image, cmd, ts, p.host, p.sam, signer=signer)
        elif kind == "fw":
            b.add(src.fw(ts, "allow", "tcp", p.ip, rng.randint(49152, 65000), rng.choice(["10.10.10.10", "10.10.20.5"]),
                         rng.choice([445, 389, 88, 53]), bytes_out=rng.randint(200, 9000), bytes_in=rng.randint(200, 90000),
                         rule="LAN-to-Servers", app="smb/ldap/kerberos", host=""))
        else:
            city = rng.choice([("PL", "Warszawa"), ("PL", "Gdańsk")])
            b.add(src.entra(ts, p.upn, w.office_nat_ip(), city[0], city[1], "Microsoft Office 365", mfa="multiFactorAuthentication",
                            mfa_detail="Authenticator push (interactive)", device_id=w.digest(p.sam, "md5")[:16], managed="Yes",
                            os="Windows 11", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121"))


__all__ = ["Builder", "Proc", "Template", "REGISTRY", "template", "noise"]
