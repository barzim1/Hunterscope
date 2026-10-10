"""The fictional company the scenarios happen in.

Everything is made up. IPs come from documentation and benchmark ranges (RFC 5737, RFC 2544), so no real
address is ever labelled malicious; external domains are invented, the benign ones are well-known services.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from hunterscope.trainer.model import TZ

COMPANY = "Nordwind Logistics"
AD_DOMAIN = "NORDWIND"
DNS_DOMAIN = "nordwind.local"
MAIL_DOMAIN = "nordwind.example"

FIRST = [
    ("Anna", "anna", "f"), ("Piotr", "piotr", "m"), ("Katarzyna", "katarzyna", "f"), ("Marcin", "marcin", "m"),
    ("Magdalena", "magdalena", "f"), ("Tomasz", "tomasz", "m"), ("Agnieszka", "agnieszka", "f"),
    ("Paweł", "pawel", "m"), ("Joanna", "joanna", "f"), ("Michał", "michal", "m"), ("Ewa", "ewa", "f"),
    ("Krzysztof", "krzysztof", "m"), ("Monika", "monika", "f"), ("Łukasz", "lukasz", "m"),
    ("Aleksandra", "aleksandra", "f"), ("Jakub", "jakub", "m"), ("Marta", "marta", "f"),
    ("Rafał", "rafal", "m"), ("Karolina", "karolina", "f"), ("Grzegorz", "grzegorz", "m"),
]
LAST = [
    ("Nowak", "nowak"), ("Kowalski", "kowalski"), ("Wiśniewski", "wisniewski"), ("Wójcik", "wojcik"),
    ("Kamiński", "kaminski"), ("Lewandowski", "lewandowski"), ("Zieliński", "zielinski"),
    ("Szymański", "szymanski"), ("Woźniak", "wozniak"), ("Dąbrowski", "dabrowski"),
    ("Kozłowski", "kozlowski"), ("Jankowski", "jankowski"), ("Mazur", "mazur"), ("Krawczyk", "krawczyk"),
    ("Piotrowski", "piotrowski"), ("Grabowski", "grabowski"), ("Pawłowski", "pawlowski"),
    ("Michalski", "michalski"), ("Król", "krol"), ("Wieczorek", "wieczorek"),
]

# department -> (host code, job titles, vlan)
DEPTS = {
    "Księgowość": ("KSG", ["Specjalista ds. księgowości", "Referent ds. rozliczeń", "Główny księgowy"], 31),
    "HR": ("HR", ["Specjalista ds. kadr", "HR Business Partner"], 32),
    "Sprzedaż": ("SPR", ["Handlowiec", "Key Account Manager", "Kierownik sprzedaży"], 33),
    "Logistyka": ("LOG", ["Spedytor", "Koordynator transportu", "Planista"], 34),
    "Zarząd": ("ZAR", ["Dyrektor operacyjny", "Asystent zarządu"], 35),
    "Marketing": ("MKT", ["Specjalista ds. marketingu", "Grafik"], 36),
    "IT": ("IT", ["Administrator systemów", "Specjalista helpdesk"], 37),
}

GEO_FOREIGN = [
    ("NG", "Lagos"), ("RO", "Bucharest"), ("VN", "Hanoi"), ("BR", "São Paulo"), ("US", "Ashburn"),
    ("RU", "Moscow"), ("IN", "Mumbai"), ("TR", "Istanbul"), ("ID", "Jakarta"),
]
GEO_PL = [("PL", "Warszawa"), ("PL", "Gdańsk"), ("PL", "Kraków"), ("PL", "Wrocław")]

BENIGN_SITES = [
    "outlook.office.com", "teams.microsoft.com", "login.microsoftonline.com", "www.google.com", "github.com",
    "www.onet.pl", "allegro.pl", "www.linkedin.com", "www.youtube.com", "pue.zus.pl", "www.gov.pl",
    "nordwind.sharepoint.example", "ctldl.windowsupdate.com", "fonts.gstatic.com", "stackoverflow.com",
    "www.ceneo.pl", "docs.microsoft.com", "www.bankier.pl",
]

_BAD_WORDS = ["secure", "update", "cdn", "portal", "login", "cloud", "sync", "office", "mail", "docs", "support",
              "verify", "service", "static", "assets", "drive", "share"]
_BAD_TLDS = ["top", "xyz", "click", "icu", "site", "cc", "work", "buzz"]


@dataclass
class Person:
    sam: str
    display: str
    dept: str
    title: str
    host: str
    ip: str
    manager: str
    gender: str

    @property
    def upn(self) -> str:
        return f"{self.sam}@{MAIL_DOMAIN}"

    @property
    def netbios(self) -> str:
        return f"{AD_DOMAIN}\\{self.sam}"

    @property
    def profile(self) -> str:
        return f"C:\\Users\\{self.sam}"


@dataclass
class Server:
    name: str
    ip: str
    role: str
    os: str
    criticality: str
    owner: str = "Dział IT"

    @property
    def fqdn(self) -> str:
        return f"{self.name.lower()}.{DNS_DOMAIN}"


SERVERS = [
    Server("DC01", "10.10.10.10", "Kontroler domeny (AD DS, DNS)", "Windows Server 2022", "Krytyczna"),
    Server("DC02", "10.10.10.11", "Kontroler domeny (AD DS, DNS)", "Windows Server 2022", "Krytyczna"),
    Server("SRV-FILE01", "10.10.20.5", "Serwer plików (udziały działów)", "Windows Server 2019", "Wysoka"),
    Server("SRV-SQL01", "10.10.20.12", "SQL Server (ERP, WMS)", "Windows Server 2019", "Krytyczna"),
    Server("SRV-WEB01", "172.16.5.20", "Serwer WWW (portal klienta, DMZ)", "Windows Server 2019", "Wysoka"),
    Server("SRV-SCCM01", "10.10.30.4", "MECM/SCCM: dystrybucja oprogramowania", "Windows Server 2022", "Wysoka"),
    Server("SRV-SCAN01", "10.10.30.9", "Skaner podatności (cotygodniowe skany)", "Ubuntu 22.04", "Średnia"),
    Server("SRV-BKP01", "10.10.30.20", "Serwer kopii zapasowych", "Windows Server 2022", "Wysoka"),
    Server("SRV-MGW01", "10.10.30.30", "Brama pocztowa (antyspam), zapytania reputacji do chmury producenta", "Debian 12", "Średnia"),
    Server("SRV-MON01", "10.10.30.15", "Monitoring (Zabbix): ICMP, SNMP, HTTP co 5 minut", "Debian 12", "Średnia"),
    Server("JUMP01", "10.10.40.5", "Serwer skokowy administratorów", "Windows Server 2022", "Wysoka"),
]


class World:
    def __init__(self, rng: random.Random, token: str):
        self.rng = rng
        self.token = token
        self._used: set[str] = set()
        self._n = 0
        self.servers = {s.name: s for s in SERVERS}

    # --- people -----------------------------------------------------------------------------------------------
    def person(self, dept: str | None = None) -> Person:
        rng = self.rng
        dept = dept or rng.choice([d for d in DEPTS if d != "IT"])
        code, titles, vlan = DEPTS[dept]
        while True:
            first = rng.choice(FIRST)
            last = rng.choice(LAST)
            sam = first[1][0] + last[1]
            if sam not in self._used:
                break
        self._used.add(sam)
        surname = last[0][:-3] + "ska" if first[2] == "f" and last[0].endswith("ski") else last[0]
        self._n += 1
        return Person(
            sam=sam,
            display=f"{first[0]} {surname}",
            dept=dept,
            title=rng.choice(titles),
            host=f"WKS-{code}-{rng.randint(1, 60):03d}",
            ip=f"10.20.{vlan}.{rng.randint(20, 240)}",
            manager=f"{rng.choice(FIRST)[0]} {rng.choice(LAST)[0]}",
            gender=first[2],
        )

    def server(self, name: str) -> Server:
        return self.servers[name]

    # --- network ----------------------------------------------------------------------------------------------
    def attacker_ip(self) -> str:
        return f"203.0.113.{self.rng.randint(10, 250)}"

    def service_ip(self) -> str:
        """A 'cloud/SaaS' address. Benign by construction (documentation range)."""
        return f"198.51.100.{self.rng.randint(10, 250)}"

    def office_nat_ip(self) -> str:
        return "198.18.4.10"

    def mobile_ip(self) -> str:
        return f"198.18.{self.rng.randint(100, 120)}.{self.rng.randint(2, 250)}"

    def foreign_geo(self) -> tuple[str, str]:
        return self.rng.choice(GEO_FOREIGN)

    def bad_domain(self) -> str:
        r = self.rng
        return f"{r.choice(_BAD_WORDS)}-{r.choice(_BAD_WORDS)}{r.randint(10, 99)}.{r.choice(_BAD_TLDS)}"

    # --- artefacts --------------------------------------------------------------------------------------------
    def digest(self, label: str, algo: str = "sha256") -> str:
        return hashlib.new(algo, f"{self.token}:{label}".encode()).hexdigest()

    def pid(self) -> int:
        return self.rng.randrange(1200, 9800, 4)


def anchor(rng: random.Random, hour: int, minute: int | None = None, weekday: bool = True) -> datetime:
    """A deterministic 'alert time' on a winter day (so CET without DST), at the requested hour."""
    day = datetime(2026, 1, 12, tzinfo=TZ) + timedelta(days=rng.randrange(0, 56))
    while weekday and day.weekday() >= 5:
        day += timedelta(days=1)
    return day.replace(hour=hour, minute=rng.randrange(0, 60) if minute is None else minute, second=rng.randrange(60))
