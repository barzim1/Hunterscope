"""The fictional company the scenarios happen in.

Everything is made up. IPs come from documentation and benchmark ranges (RFC 5737, RFC 2544), so no real
address is ever labelled malicious. The same pool serves every role (attacker, SaaS, mobile carrier): an
address range must never tell the analyst the verdict. Malicious infrastructure comes in three shapes that
real incidents also have: fresh throw-away domains, typosquats on trusted-looking TLDs (sometimes aged), and
legitimate shared services abused as hosting (cloud storage, code hosting), whose reputation is clean.
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
_ODD_TLDS = ["top", "xyz", "click", "icu", "site", "cc", "work", "buzz"]
_TRUSTED_TLDS = ["com", "net", "org", "pl", "eu", "io", "co", "info"]
BRANDS = ["microsoft", "office365", "sharepoint", "onedrive", "docusign", "dropbox", "adobe", "dhl", "inpost", "allegro", "nordwind",
          "zoom"]

# Public ranges used for every external address, whatever its role. 198.18.0.0/15 is the benchmark block.
_PUBLIC_POOLS = [(192, 0, 2), (198, 51, 100), (203, 0, 113), (198, 18, None)]

# (zone, style, proxy category, owner): shared services that attackers abuse as hosting. TI is about the service.
_SERVICES = [
    ("blob.core.windows.net", "bucket", "Cloud Storage", "Microsoft (Azure Storage)"),
    ("s3.amazonaws.com", "bucket", "Cloud Storage", "Amazon (S3)"),
    ("storage.googleapis.com", "gcs", "Cloud Storage", "Google (Cloud Storage)"),
    ("raw.githubusercontent.com", "github", "Code Hosting", "GitHub"),
    ("cdn.discordapp.com", "discord", "File Sharing", "Discord"),
]


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


@dataclass(frozen=True)
class Remote:
    """External infrastructure used by an attacker. `kind` decides what threat intel can and cannot say."""

    name: str
    kind: str  # "fresh" | "typosquat" | "service"
    category: str  # what the web gateway would label it
    age_days: int
    zone: str = ""  # service only: the shared zone TI knows about
    owner: str = ""
    prefix: str = "/"
    brand: str = ""

    def url(self, path: str = "") -> str:
        return f"https://{self.name}{self.prefix}{path}"

    @property
    def blurb(self) -> str:
        if self.kind == "service":
            return f"legalna usługa ({self.owner}) użyta jako hosting złośliwej treści"
        if self.kind == "typosquat":
            return f"domena podszywająca się pod markę „{self.brand}”"
        return "świeża, nieznana domena"


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
        self._nat: str | None = None
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
    def public_ip(self) -> str:
        """Any external address. Same pool for attackers, SaaS, carriers and partners on purpose."""
        r = self.rng
        while True:
            a, b, c = r.choice(_PUBLIC_POOLS)
            ip = (f"{a}.{r.choice([18, 19])}.{r.randint(5, 250)}.{r.randint(2, 250)}" if c is None
                  else f"{a}.{b}.{c}.{r.randint(10, 250)}")
            if ip != self._nat:
                return ip

    # Kept as role names for readability at the call site; they deliberately share one pool.
    attacker_ip = service_ip = mobile_ip = public_ip

    def office_nat_ip(self) -> str:
        """The company's own egress address. Drawn per scenario, so no fixed address says 'benign'."""
        if self._nat is None:
            self._nat = self.public_ip()
        return self._nat

    def foreign_geo(self) -> tuple[str, str]:
        return self.rng.choice(GEO_FOREIGN)

    def bad_domain(self) -> str:
        """A dedicated attacker domain (never a shared service): for mail senders, phishing pages, DNS tunnels."""
        return self.threat_host(2, site_only=True).name

    def threat_host(self, difficulty: int, *, site_only: bool = False, brand: str = "", kind: str = "") -> Remote:
        r = self.rng
        kind = kind or r.choices(["fresh", "typosquat"] if site_only else ["fresh", "typosquat", "service"],
                                 [0.4, 0.6] if site_only else [0.3, 0.35, 0.35])[0]
        if kind == "service":
            return self._service()
        if kind == "typosquat":
            brand = brand or r.choice(BRANDS)
            tlds = _TRUSTED_TLDS if difficulty >= 2 or r.random() < 0.5 else _ODD_TLDS
            age = r.randint(1, 6) if difficulty == 1 else r.randint(5, 60) if difficulty == 2 else r.randint(90, 420)
            category = (r.choice(["Newly Registered Domain", "Uncategorized"]) if difficulty == 1
                        else "Uncategorized" if difficulty == 2 else r.choice(["Business", "Technology", "Uncategorized"]))
            return Remote(f"{self._typosquat(brand)}.{r.choice(tlds)}", "typosquat", category, age, brand=brand)
        tlds = _ODD_TLDS if difficulty == 1 or r.random() < 0.5 else _TRUSTED_TLDS
        age = r.randint(1, 6) if difficulty == 1 else r.randint(3, 20) if difficulty == 2 else r.randint(10, 60)
        category = "Newly Registered Domain" if difficulty == 1 else r.choice(["Newly Registered Domain", "Uncategorized"]) if difficulty == 2 else "Uncategorized"
        return Remote(f"{r.choice(_BAD_WORDS)}-{r.choice(_BAD_WORDS)}{r.randint(10, 99)}.{r.choice(tlds)}", "fresh", category, age)

    def _typosquat(self, brand: str) -> str:
        r = self.rng
        word, num = r.choice(_BAD_WORDS), r.randint(10, 99)
        i = r.randrange(len(brand) - 1)
        tricks = [
            lambda: brand.replace("o", "0", 1) if "o" in brand else None,
            lambda: brand.replace("m", "rn", 1) if "m" in brand else None,
            lambda: brand.replace("l", "1", 1) if "l" in brand else None,
            lambda: brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:],
            lambda: f"{brand}-{word}{num}",
            lambda: f"{word}-{brand}{num}",
            lambda: f"{brand}{word}{num}",
        ]
        r.shuffle(tricks)
        for trick in tricks:
            name = trick()
            if name and name != brand:
                # a short token keeps an invented squat from colliding with a registered name
                return name if any(ch.isdigit() for ch in name) and "-" in name else f"{name}-{r.choice(_BAD_WORDS)}{num}"
        return f"{brand}-{word}{num}"

    def _service(self) -> Remote:
        r = self.rng
        zone, style, category, owner = r.choice(_SERVICES)
        token = "".join(r.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=r.randint(5, 8)))
        if style == "bucket":
            label = f"{r.choice(_BAD_WORDS)}{token}{r.choice(['docs', 'files', 'assets', 'share'])}"
            return Remote(f"{label}.{zone}", "service", category, 3650, zone, owner, f"/{r.choice(['public', 'share', 'dl', 'files'])}/")
        if style == "gcs":
            return Remote(zone, "service", category, 3650, zone, owner, f"/{r.choice(_BAD_WORDS)}-{token}/")
        if style == "github":
            return Remote(zone, "service", category, 3650, zone, owner, f"/{token}/{r.choice(_BAD_WORDS)}-tools/main/")
        digits = lambda n: "".join(r.choices("0123456789", k=n))  # noqa: E731
        return Remote(zone, "service", category, 3650, zone, owner, f"/attachments/{digits(18)}/{digits(18)}/")

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
