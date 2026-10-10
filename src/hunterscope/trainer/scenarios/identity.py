"""Identity and mail scenarios: Entra ID sign-ins, M365 audit log, Windows logons."""

from __future__ import annotations

from hunterscope.trainer import sources as src
from hunterscope.trainer.model import Lessons
from hunterscope.trainer.scenarios.base import Builder, noise, template
from hunterscope.trainer.world import GEO_PL

UA_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0 Safari/537.36"
UA_LINUX = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0 Safari/537.36"
UA_PY = "python-requests/2.31.0"
UA_IOS = "Microsoft Outlook/4.2410.0 (iPhone; iOS 17.3)"


def _device(b: Builder, sam: str) -> str:
    return b.w.digest("dev:" + sam, "md5")[:16]


# ======================================================================================================================
# Password spraying / brute force
# ======================================================================================================================
LESSONS_SPRAY = Lessons(
    title="Wiele nieudanych logowań z jednego źródła",
    category="Tożsamość",
    tp_signs=[
        "Jedno zewnętrzne IP próbuje wielu różnych kont, po jednym lub dwa razy (spraying), w równych odstępach.",
        "Logowanie udane po serii porażek z tego samego IP, często przez stary protokół (IMAP/EAS), który omija MFA.",
        "Po udanym logowaniu natychmiast dostęp do poczty (MailItemsAccessed) z tego samego adresu.",
        "Wariant z MFA: poprawne hasło, wiele prośb MFA odrzuconych przez użytkownika i w końcu zatwierdzona (zmęczenie MFA).",
    ],
    fp_signs=[
        "Jedno konto, jedno wewnętrzne źródło (stacja użytkownika), stały odstęp czasu, błąd „złe hasło”.",
        "Zaczęło się po zmianie hasła (zapamiętane hasło w mapowanym dysku, Outlooku, telefonie).",
        "Skończyło się blokadą konta i udanym logowaniem po jego odblokowaniu z tego samego hosta.",
    ],
    checklist=[
        "Ile kont jest celem: jedno czy wiele? Jedno źródło czy wiele?",
        "Źródło wewnętrzne czy zewnętrzne, kraj, reputacja IP?",
        "Czy jest udane logowanie po porażkach i z jakiego protokołu / aplikacji?",
        "Co robiło konto po sukcesie (poczta, reguły, zmiany MFA)?",
        "Czy użytkownik niedawno zmienił hasło? Czy jest okno testów penetracyjnych na to IP?",
        "Hasło i sesje: reset i unieważnienie tokenów, jeśli sukces jest potwierdzony.",
    ],
    pitfalls=[
        "Liczba porażek sama nic nie mówi. Ważne: ile kont, skąd i czy był sukces.",
        "Nie ignoruj „drobnego” skanowania z jednego IP: spraying celowo trzyma się poniżej progów blokady.",
        "Test penetracyjny wygląda dokładnie jak atak. Różnicą jest wpis w kalendarzu i zgodne IP.",
    ],
    attack=["T1110.003 Password Spraying", "T1078 Valid Accounts", "T1621 MFA Request Generation"],
    tips=[
        "Entra ID → Sign-in logs → filtr po IP: pivot po wszystkich kontach, które widziało to IP.",
        "Kody błędów: 50126 złe hasło, 50076 wymagane MFA (hasło poprawne!), 500121 MFA nieudane.",
        "AD: 4625 (SubStatus 0xC000006A = złe hasło), 4740 = blokada konta.",
    ],
    hints=[
        "Policz, ilu różnych użytkowników dotyczą porażki i skąd pochodzą.",
        "Szukaj udanego logowania po serii porażek i sprawdź, przez jaką aplikację lub protokół.",
        "Zajrzyj do Kontekstu: zmiana hasła użytkownika, okno testów penetracyjnych, reputacja IP.",
    ],
)


@template("spray_bruteforce", ("tp", "fp", "btp"), LESSONS_SPRAY)
def spray_bruteforce(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    if variant == "fp":
        b.at_hour(rng.choice([8, 9, 10, 13]))
        p = b.person()
        b.use(p, **{"Ostatnia zmiana hasła": "wczoraj, 16:40 (samodzielnie, po wygaśnięciu)"})
        b.server("SRV-FILE01")
        b.session(p, hours_ago=1.5)
        for i in range(16):
            ev = b.add(src.logon_fail(b.t(-60 + i * 4, rng.randint(0, 20)), "SRV-FILE01", p.sam, p.ip, workstation=p.host))
            if i == 0:
                ev.key("Seria zaczyna się o poranku, po wczorajszej zmianie hasła: stare hasło zapamiętane w sesji (mapowany dysk).")
        trigger = b.add(src.logon_fail(b.t(0), "SRV-FILE01", p.sam, p.ip, workstation=p.host))
        trigger.herring("Dziesiątki porażek brzmią groźnie, ale to jedno konto, jedno wewnętrzne źródło i stały odstęp co kilka minut.")
        b.add(src.winsec(b.t(1), "DC01", 4740, "A user account was locked out", {"TargetUserName": p.sam, "CallerComputerName": p.host},
                         f"Konto zablokowane: {p.sam} (źródło {p.host})", p.sam)).key(
            "Blokada konta wywołana przez stację samego użytkownika: pętla starych poświadczeń, nie atak z zewnątrz.")
        b.add(src.logon_ok(b.t(14), "SRV-FILE01", p.sam, p.ip, 3, workstation=p.host)).key(
            "Po odblokowaniu konta logowanie z tej samej stacji kończy się sukcesem: użytkownik ma teraz poprawne hasło.")
        noise(b, involved=[p])
        truth = b.truth(
            "fp", "low",
            f"{p.sam} zmienił hasło dzień wcześniej, a jego stacja ({p.host}) co kilka minut próbuje stare hasło (zapamiętane połączenie z udziałem SRV-FILE01), co doprowadziło do blokady konta.",
            f"FP. 17 nieudanych logowań ({p.sam}) na SRV-FILE01, wyłącznie z {p.host} ({p.ip}), co ~4 min, zła hasło. Zmiana hasła dzień wcześniej, blokada 4740, po odblokowaniu "
            "udane logowanie z tego samego hosta. Zamykam jako FP; proszę użytkownika o ponowne zalogowanie/odpięcie dysków.",
            required=["notify_user"], lookups=[f"user:{p.sam}"])
    else:
        b.at_hour(rng.choice([2, 3, 4, 11, 15]))
        p = b.person()
        ip = w.public_ip()
        country, city = w.foreign_geo()
        app = "Office 365 Exchange Online"
        targets = [w.person() for _ in range(rng.randint(10, 14) if not b.hard else 8)]
        if not b.hard or variant == "btp":
            targets = [*targets, p]
        step = 25 if not b.hard else 160
        for i, t_user in enumerate(targets):
            is_victim = t_user is p
            if variant == "tp" and is_victim:
                continue
            ev = b.add(src.entra(b.t(-(len(targets) + 1 - i) * step / 60, rng.randint(0, 9)), t_user.upn, ip, country, city, app,
                                 error=50126, client="Exchange ActiveSync" if not b.hard else "Browser",
                                 ua=UA_PY if not b.hard else UA_LINUX))
            if i < 2:
                ev.key(f"Pojedyncza nieudana próba na koncie {t_user.sam} z {ip}. Takie próby trafiają w kolejne konta, każde raz.")
        if variant == "tp":
            if not b.hard:
                trigger = b.add(src.entra(b.t(0), p.upn, ip, country, city, app, client="IMAP4", ua=UA_PY, mfa="singleFactorAuthentication"))
                trigger.key(f"Sukces dla {p.sam} z tego samego IP po serii porażek, przez IMAP4, czyli stary protokół, który nie wymaga MFA.")
            else:
                b.add(src.entra(b.t(-6), p.upn, ip, country, city, app, error=50076, client="Browser", ua=UA_LINUX, os="Linux")).key(
                    "Hasło jest poprawne (50076 oznacza, że dopiero wymagane jest MFA). Atakujący zna hasło użytkownika.")
                for k in (-4, -2):
                    b.add(src.entra(b.t(k), p.upn, ip, country, city, app, error=500121, client="Browser", ua=UA_LINUX, os="Linux",
                                    mfa="multiFactorAuthentication", mfa_detail="Authenticator push denied by user")).key(
                        "Użytkownik odrzuca prośby MFA, których nie wywołał.")
                trigger = b.add(src.entra(b.t(0), p.upn, ip, country, city, app, client="Browser", ua=UA_LINUX, os="Linux",
                                          mfa="multiFactorAuthentication", mfa_detail="Authenticator push approved"))
                trigger.key("Po kilku odrzuceniach użytkownik zatwierdza prośbę: zmęczenie MFA. Konto przejęte z obcego IP.")
            b.add(src.m365(b.t(3), p.upn, "MailItemsAccessed", ip, details={"MailboxOwnerUPN": p.upn, "OperationCount": "212"},
                           client="Client=IMAP;")).key("Zaraz po logowaniu masowy odczyt skrzynki z tego samego IP: przejęcie poczty.")
            b.ti_bad(ip, "IP", age_days=14, tags="password spraying, hosting")
            noise(b, involved=[p])
            truth = b.truth(
                "tp", "high",
                f"Z {ip} ({city}, {country}) przeprowadzono password spraying na {len(targets) - (0 if b.hard else 1)} kont; konto {p.sam} zostało przejęte "
                f"({'przez IMAP bez MFA' if not b.hard else 'zmęczenie MFA'}), a skrzynka została odczytana.",
                f"TP. Spraying z {ip} na ~{len(targets)} kont (jedna próba na konto). Sukces {p.sam} z tego IP "
                f"({'IMAP4, brak MFA' if not b.hard else 'po odrzuconych MFA zatwierdzono prośbę'}), następnie MailItemsAccessed (212). Eskaluję, wnoszę o reset hasła i unieważnienie sesji "
                f"{p.sam}, blokadę IP, przegląd reguł skrzynki.",
                required=["reset_creds", "block_ioc"], lookups=[f"ti:{ip}"])
        else:
            trigger = b.add(src.entra(b.t(0), targets[-1].upn, ip, country, city, app, error=50126, client="Exchange ActiveSync", ua=UA_PY))
            trigger.herring("Wygląda jak spraying z zewnętrznego IP, ale IP należy do firmy testującej.")
            b.ti_bad(ip, "IP", age_days=40, tags="scanner, password spraying (zgłoszenia społeczności)")
            b.change(ip, b.t(-120), b.t(180), f"Test penetracyjny (zewnętrzny, password spraying) wykonawca: SecAudit sp. z o.o., źródłowy IP {ip}", "CHG-1107")
            for ev in b.events[-2:]:
                ev.key("Seria jednej próby na konto z jednego IP bez żadnego sukcesu: wzorzec zgodny z autoryzowanym testem.")
            noise(b, involved=[p])
            truth = b.truth(
                "btp", "info",
                f"Spraying z {ip} to autoryzowany test penetracyjny (CHG-1107): okno czasowe i źródłowy IP zgadzają się z wpisem. Nie było udanych logowań.",
                f"BTP. {len(targets)} prób z {ip} jedna na konto, bez sukcesu. CHG-1107: test penetracyjny SecAudit, IP {ip}, okno obejmuje czas alertu. Zamykam bez eskalacji.",
                lookups=[f"change:{ip}"])
    b.finish(trigger, source="SIEM", rule="Multiple failed sign-ins from a single source", severity="high",
             description=f"Wiele nieudanych logowań z jednego źródła ({trigger.fields.get('IpAddress', '')}), konto lub konta: {trigger.user}.",
             truth=truth, lessons=LESSONS_SPRAY)


# ======================================================================================================================
# Atypical travel
# ======================================================================================================================
LESSONS_TRAVEL = Lessons(
    title="Logowanie z nietypowej lokalizacji",
    category="Tożsamość",
    tp_signs=[
        "Dwa logowania w krótkim czasie z odległych miejsc, a drugie z urządzenia, którego konto nigdy wcześniej nie używało.",
        "Inny system i przeglądarka (Linux, python-requests), brak DeviceId, urządzenie niezarządzane.",
        "MFA „satisfied by claim in the token”: sesja odtworzona z przechwyconego tokenu (AiTM), nie interaktywne MFA.",
        "Chwilę wcześniej użytkownik wszedł na stronę logowania podszywającą się pod Microsoft.",
    ],
    fp_signs=[
        "Drugie logowanie z urządzenia, którego DeviceId konto zna od tygodni (telefon, laptop).",
        "Geolokalizacja IP operatora komórkowego lub VPN/proxy często jest błędna.",
        "Delegacja lub wyjazd użytkownika w HR (BTP): urządzenie to firmowy laptop, wcześniejsze logowania z Polski dni temu.",
    ],
    checklist=[
        "Porównaj oba logowania: IP, kraj, aplikacja, DeviceId, system, UA, sposób MFA.",
        "Czy DeviceId drugiego logowania pojawiał się wcześniej dla tego konta?",
        "Czy odstęp czasu fizycznie umożliwia podróż?",
        "Co robiono po logowaniu (MailItemsAccessed, reguły, zmiany MFA)?",
        "Delegacje, urlopy, godziny pracy użytkownika (Kontekst).",
        "Czy użytkownik wcześniej wchodził na dziwną stronę logowania (proxy)?",
    ],
    pitfalls=[
        "Geolokalizacja IP jest przybliżona. Nie opieraj werdyktu wyłącznie na kraju.",
        "Zaliczone MFA nie znaczy „użytkownik to zatwierdził”: token mógł zostać skradziony po MFA.",
        "Wyjazd służbowy to nie incydent, ale tylko po sprawdzeniu urządzenia i HR.",
    ],
    attack=["T1078.004 Valid Accounts: Cloud Accounts", "T1557 Adversary-in-the-Middle", "T1539 Steal Web Session Cookie"],
    tips=[
        "Entra → Sign-in logs → kolumny Device ID, Join type, Compliant, Authentication details, Token issuer.",
        "Przy potwierdzonym przejęciu: Revoke sessions (Entra) + reset hasła + przegląd metod MFA i reguł skrzynki.",
        "Proxy: szukaj POST na domenach wyglądających jak login.microsoftonline (AiTM).",
    ],
    hints=[
        "Porównaj DeviceId, system i UA obu logowań.",
        "Sprawdź, czy DeviceId drugiego logowania pojawiał się dla tego konta wcześniej.",
        "Zobacz w Kontekście delegacje/urlopy użytkownika i reputację IP.",
    ],
)


@template("impossible_travel", ("tp", "fp", "btp"), LESSONS_TRAVEL)
def impossible_travel(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    b.at_hour(rng.choice([8, 9, 10, 13, 14, 20]))
    p = b.person()
    dev = _device(b, p.sam)
    pl_country, pl_city = rng.choice(GEO_PL)
    office = w.office_nat_ip()
    app = "Office 365 Exchange Online"
    desktop = dict(app="Microsoft Office 365", ua=UA_WIN, device_id=dev, managed="Yes", os="Windows 11", mfa="multiFactorAuthentication")
    if variant == "tp":
        gap = 14 if not b.hard else 41
        b.add(src.entra(b.t(-gap), p.upn, office, pl_country, pl_city, desktop["app"], ua=UA_WIN, device_id=dev, managed="Yes", os="Windows 11",
                        mfa="multiFactorAuthentication", mfa_detail="Authenticator push (interactive)"))
        country, city = ("DE", "Frankfurt") if b.hard else w.foreign_geo()
        ip = w.attacker_ip()
        trigger = b.add(src.entra(b.t(0), p.upn, ip, country, city, app, ua=UA_LINUX, os="Linux", managed="No", mfa="multiFactorAuthentication",
                                  mfa_detail="MFA requirement satisfied by claim in the token"))
        trigger.key(f"Drugie logowanie {gap} min po pierwszym z {city}, na nowym urządzeniu (brak DeviceId, Linux), a MFA zaliczone „claimem w tokenie”. To przechwycona sesja, nie świeże MFA.")
        if not b.hard:
            remote = b.threat(site_only=True, brand="microsoft")
            domain = remote.name
            b.add(src.proxy(b.t(-gap - 3), p.ip, p.sam, "GET", remote.url("share/doc"), 200, 600, 41_000,
                            category=remote.category, host=p.host)).key(
                "Chwilę przed drugim logowaniem użytkownik wchodzi na stronę logowania, która nie należy do Microsoftu (domena podszywająca się pod markę).")
            b.add(src.proxy(b.t(-gap - 2.5), p.ip, p.sam, "POST", remote.url("login"), 302, 4100, 800,
                            category=remote.category, host=p.host)).key("POST z danymi logowania na tej samej domenie: dane i token zostały wysłane atakującemu.")
            b.ti_threat(remote, tags="AiTM phishing")
            lk = f"ti:{domain}"
        else:
            lk = f"user:{p.sam}"
        b.add(src.m365(b.t(2), p.upn, "MailItemsAccessed", ip, details={"MailboxOwnerUPN": p.upn, "OperationCount": "96"}, client="Client=OWA;")).key(
            "Dostęp do skrzynki z obcego IP tuż po logowaniu.")
        b.ti_bad(ip, "IP", age_days=9, tags="hosting, proxy")
        truth = b.truth(
            "tp", "high",
            f"Dwa logowania w {gap} minut: Warszawa i {city}. Drugie z nowego, niezarządzanego urządzenia, MFA zaliczone claimem w tokenie. Sesja użytkownika została przejęta (AiTM).",
            f"TP. {p.sam}: logowanie z {pl_city} ({gap} min wcześniej) i z {city} ({ip}), Linux, brak DeviceId, MFA satisfied by claim in the token, potem MailItemsAccessed. "
            "Eskaluję, wnoszę o unieważnienie sesji i reset hasła, przegląd reguł skrzynki i metod MFA.",
            required=["reset_creds", "block_ioc"], lookups=[lk, f"user:{p.sam}"])
    elif variant == "fp":
        for d, days in enumerate((9, 3)):
            b.add(src.entra(b.t(-days * 1440), p.upn, w.mobile_ip(), "PL", pl_city, "Microsoft Outlook (mobile)", client="Mobile Apps and Desktop clients",
                            ua=UA_IOS, device_id=_device(b, p.sam + "ios"), managed="Yes", os="iOS 17.3", mfa="multiFactorAuthentication",
                            mfa_detail="Authenticator push (interactive)")).key(
                "Ten sam DeviceId telefonu logował się tygodnie wcześniej z operatora w Polsce: urządzenie jest znane kontu." if d == 0 else
                "Kolejne wcześniejsze logowanie z tego samego urządzenia.")
        b.add(src.entra(b.t(-13), p.upn, office, pl_country, pl_city, desktop["app"], ua=UA_WIN, device_id=dev, managed="Yes", os="Windows 11",
                        mfa="multiFactorAuthentication", mfa_detail="Authenticator push (interactive)"))
        trigger = b.add(src.entra(b.t(0), p.upn, w.mobile_ip(), "DE", "Frankfurt", "Microsoft Outlook (mobile)", client="Mobile Apps and Desktop clients",
                                  ua=UA_IOS, device_id=_device(b, p.sam + "ios"), managed="Yes", os="iOS 17.3", mfa="multiFactorAuthentication",
                                  mfa_detail="MFA requirement satisfied by claim in the token"))
        trigger.herring("„Frankfurt” i MFA z claima w tokenie wyglądają jak AiTM, ale to znany, zarządzany telefon użytkownika. Błąd geolokalizacji IP operatora komórkowego.")
        b.ti_good(trigger.fields["IpAddress"], "IP", owner="Operator komórkowy (zakres mobilny)", age_years=5, hosts_seen=60,
                  note="Zakresy mobilne bywają geolokalizowane do centrów danych operatora.")
        noise(b, involved=[p])
        truth = b.truth(
            "fp", "low",
            "Drugie logowanie pochodzi z iPhone'a użytkownika, zarejestrowanego i zarządzanego, który wielokrotnie logował się wcześniej z Polski. Adres z puli operatora został błędnie "
            "zlokalizowany do Frankfurtu.",
            f"FP. {p.sam}: logowanie z mobilnego IP geolokalizowanego do DE, ale DeviceId = zarządzany iPhone użytkownika, widziany w logowaniach 3 i 9 dni wcześniej z PL, "
            "aplikacja Outlook mobile. Brak aktywności po logowaniu. Zamykam jako FP.",
            lookups=[f"user:{p.sam}"])
    else:
        gap_days = 2
        b.ctx.users[p.sam]["Delegacje / urlopy"] = "Berlin, konferencja logistyczna, wyjazd służbowy zatwierdzony (dziś i jutro)"
        b.add(src.entra(b.t(-gap_days * 1440), p.upn, office, pl_country, pl_city, desktop["app"], ua=UA_WIN, device_id=dev, managed="Yes", os="Windows 11",
                        mfa="multiFactorAuthentication", mfa_detail="Authenticator push (interactive)")).key(
            "Poprzednie logowanie z tego samego, zarządzanego laptopa dwa dni wcześniej z Polski. Odstęp czasu wystarcza na podróż.")
        trigger = b.add(src.entra(b.t(0), p.upn, w.mobile_ip(), "DE", "Berlin", desktop["app"], ua=UA_WIN, device_id=dev, managed="Yes", os="Windows 11",
                                  mfa="multiFactorAuthentication", mfa_detail="Authenticator push (interactive)"))
        trigger.key("Ten sam firmowy laptop (DeviceId), przeglądarka i interaktywne MFA, tylko z Berlina.")
        b.ctx.ti[trigger.fields["IpAddress"].lower()] = {
            "Wskaźnik": trigger.fields["IpAddress"], "Typ": "IP", "Werdykt TI (symulacja)": "Czysty, zakres komercyjny (hotel / sieć konferencyjna)",
            "Występowanie w organizacji": "1 użytkownik", "Komentarz": "-"}
        noise(b, involved=[p])
        truth = b.truth(
            "btp", "info",
            "Detekcja jest zasadna (nowy kraj), ale to zatwierdzony wyjazd służbowy do Berlina z firmowym laptopem tym samym DeviceId, z interaktywnym MFA.",
            f"BTP. {p.sam}: logowanie z Berlina; ten sam zarządzany laptop (DeviceId) co 2 dni wcześniej z Polski, MFA interaktywne. HR/kalendarz: delegacja do Berlina (konferencja), "
            "zatwierdzona. Zamykam bez eskalacji.",
            lookups=[f"user:{p.sam}"])
    b.finish(trigger, source="SIEM", rule="Sign-in from atypical location or impossible travel", severity="medium",
             description=f"Logowanie {p.upn} z nietypowej lokalizacji: {trigger.fields['Location']}.", truth=truth, lessons=LESSONS_TRAVEL)


# ======================================================================================================================
# Inbox rule
# ======================================================================================================================
LESSONS_RULE = Lessons(
    title="Reguła skrzynki przekazująca pocztę",
    category="Tożsamość",
    tp_signs=[
        "Reguła przekazuje pocztę na zewnętrzny adres i kasuje lub ukrywa oryginały.",
        "Słowa kluczowe finansowe w warunkach (faktura, płatność, IBAN): przygotowanie pod oszustwo na przelew (BEC).",
        "Utworzona z obcego IP lub z nowego urządzenia, krótko po podejrzanym logowaniu.",
        "Nazwa reguły pusta, kropka lub nic nie znacząca.",
    ],
    fp_signs=[
        "Przekazanie na adres wewnętrzny (zastępstwo) ze znanego IP i klienta, przed urlopem.",
        "Nazwa reguły opisowa (np. „Urlop”), bez usuwania wiadomości.",
        "Potwierdzenie w HR / u przełożonego.",
    ],
    checklist=[
        "Dokąd przekazuje: domena wewnętrzna czy zewnętrzna, kto jest jej właścicielem?",
        "Czy reguła usuwa, oznacza jako przeczytane lub przenosi do ukrytego folderu?",
        "Kto i skąd ją utworzył (IP, klient, UserAgent)? Czy to to samo IP co zwykle?",
        "Co działo się wokół: logowania, MailItemsAccessed.",
        "Urlop użytkownika, umowa z partnerem, kalendarz zmian.",
    ],
    pitfalls=[
        "Nie każde przekazywanie jest atakiem: zastępstwa urlopowe i integracje z partnerami są normalne.",
        "Nie zapominaj sprawdzić, czy reguła istnieje także w transport rules (administracyjnych).",
    ],
    attack=["T1114.003 Email Forwarding Rule", "T1564.008 Email Hiding Rules", "T1534 Internal Spearphishing"],
    tips=[
        "M365: Unified Audit Log → operacje New-InboxRule / Set-InboxRule / UpdateInboxRules.",
        "Exchange admin: Get-InboxRule -Mailbox user | fl Name,ForwardTo,DeleteMessage,MoveToFolder.",
        "Po potwierdzeniu: usuń regułę, wymuś reset hasła i unieważnienie sesji, zbadaj wysłane oszukańcze maile.",
    ],
    hints=[
        "Dokąd trafia poczta i co dzieje się z oryginałami?",
        "Kto utworzył regułę (IP, klient) i co działo się z kontem tuż wcześniej?",
        "W Kontekście sprawdź użytkownika (urlop) i adres docelowy.",
    ],
)


@template("mail_rule", ("tp", "fp", "btp"), LESSONS_RULE)
def mail_rule(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    b.at_hour(rng.choice([9, 10, 11, 14, 22, 3]))
    p = b.person(rng.choice(["Księgowość", "Sprzedaż", "Zarząd"]))
    dev = _device(b, p.sam)
    office = w.office_nat_ip()
    if variant == "tp":
        country, city = ("PL", "Poznań") if b.hard else w.foreign_geo()
        ip = w.attacker_ip()
        b.add(src.entra(b.t(-12), p.upn, ip, country, city, "Office 365 Exchange Online", ua=UA_LINUX, os="Linux", managed="No",
                        mfa="multiFactorAuthentication", mfa_detail="MFA requirement satisfied by claim in the token")).key(
            f"Logowanie z nowego urządzenia (Linux, brak DeviceId) z {city}, tuż przed utworzeniem reguły."
            + (" IP w Polsce, więc geolokalizacja niczego nie ujawnia: o podejrzeniu decyduje urządzenie." if b.hard else ""))
        fwd = f"rozliczenia.biuro@{w.bad_domain()}"
        details = {"Name": ".", "ForwardTo": fwd, "SubjectOrBodyContainsWords": "faktura;płatność;invoice;iban;przelew",
                   "DeleteMessage": "False" if b.hard else "True", "MarkAsRead": "True",
                   "MoveToFolder": "RSS Subscriptions" if b.hard else "-", "StopProcessingRules": "True"}
        trigger = b.add(src.m365(b.t(0), p.upn, "New-InboxRule", ip, details=details, client="Client=REST;Client=RESTSystem;"))
        trigger.key("Reguła o nazwie „.” przekazuje na zewnętrzny adres wszystko o fakturach i płatnościach"
                    + (", przenosi oryginały do ukrytego folderu RSS." if b.hard else " i kasuje oryginały.") + " Klasyczne przygotowanie BEC.")
        b.add(src.m365(b.t(4), p.upn, "MailItemsAccessed", ip, details={"MailboxOwnerUPN": p.upn, "OperationCount": "140"}, client="Client=REST;")).key(
            "Odczyt wielu wiadomości z tego samego IP po utworzeniu reguły.")
        b.ti_bad(ip, "IP", age_days=6, tags="hosting, BEC")
        b.ti_bad(fwd.split("@")[1], "domena", age_days=5, tags="BEC, mail drop")
        noise(b, involved=[p])
        truth = b.truth(
            "tp", "high",
            f"Po logowaniu z nowego urządzenia z {city} utworzono regułę „.” przekazującą pocztę z fakturami i płatnościami na zewnętrzny adres {fwd}. Przygotowanie do oszustwa BEC.",
            f"TP. {p.upn}: New-InboxRule (Name \".\") z {ip} ({city}), przekazuje na {fwd} wiadomości z fakturami/płatnościami, "
            + ("przenosi oryginały do RSS Subscriptions. " if b.hard else "kasuje oryginały. ")
            + "Wcześniej logowanie z nowego urządzenia. Eskaluję, wnoszę o usunięcie reguły, unieważnienie sesji i reset hasła, przegląd wysłanych wiadomości.",
            required=["reset_creds", "block_ioc"], lookups=[f"ti:{ip}", f"user:{p.sam}"])
    elif variant == "fp":
        colleague = w.person(p.dept)
        b.ctx.users[p.sam]["Delegacje / urlopy"] = f"Urlop od jutra do końca tygodnia, zastępstwo: {colleague.display}"
        b.add(src.entra(b.t(-8), p.upn, office, "PL", "Warszawa", "Microsoft Office 365", ua=UA_WIN, device_id=dev, managed="Yes", os="Windows 11",
                        mfa="multiFactorAuthentication", mfa_detail="Authenticator push (interactive)")).key(
            "Logowanie z firmowego laptopa, znanego IP biura i interaktywne MFA tuż przed utworzeniem reguły.")
        details = {"Name": "Urlop: przekaż do zastępstwa", "ForwardTo": colleague.upn, "SubjectOrBodyContainsWords": "-",
                   "DeleteMessage": "False", "MarkAsRead": "False", "StopProcessingRules": "False"}
        trigger = b.add(src.m365(b.t(0), p.upn, "New-InboxRule", office, details=details, client="Client=OWA;Action=Outlook"))
        trigger.herring("Przekazywanie poczty to ogólnie ryzykowna operacja, ale tu adres docelowy to koleżanka/kolega z działu, a oryginały zostają w skrzynce.")
        noise(b, involved=[p])
        truth = b.truth(
            "fp", "low",
            f"{p.sam} przed urlopem ustawił regułę przekazującą pocztę do osoby zastępującej ({colleague.upn}), z firmowego laptopa i IP biura, bez usuwania wiadomości.",
            f"FP. {p.upn}: New-InboxRule „Urlop: przekaż do zastępstwa” → {colleague.upn} (adres wewnętrzny, ten sam dział), z IP biura, firmowy laptop, bez kasowania. "
            "HR: urlop od jutra, zastępstwo się zgadza. Zamykam jako FP.",
            lookups=[f"user:{p.sam}"])
    else:
        partner = "dispatch@partner-logistyka.example"
        b.ctx.ti["partner-logistyka.example"] = {
            "Wskaźnik": "partner-logistyka.example", "Typ": "domena", "Werdykt TI (symulacja)": "Czysty, partner biznesowy",
            "Występowanie w organizacji": "kontakty handlowe, 38 wiadomości w tym miesiącu",
            "Komentarz": "Partner z umową NDA 14/2025, wpis w rejestrze dostawców.", "Właściciel": "Partner Logistyka sp. z o.o."}
        b.change(p.host, b.t(-3 * 1440), b.t(60 * 24 * 30), f"Automatyczne przekazywanie zamówień ze skrzynki {p.sam} do partnera Partner Logistyka (NDA 14/2025)", "SEC-2026-031")
        b.add(src.entra(b.t(-6), p.upn, office, "PL", "Warszawa", "Microsoft Office 365", ua=UA_WIN, device_id=dev, managed="Yes", os="Windows 11",
                        mfa="multiFactorAuthentication", mfa_detail="Authenticator push (interactive)")).key("Logowanie ze znanego urządzenia i IP biura, interaktywne MFA.")
        details = {"Name": "Zamówienia → Partner Logistyka", "ForwardTo": partner, "SubjectOrBodyContainsWords": "zamówienie;ZK/",
                   "DeleteMessage": "False", "MarkAsRead": "False", "StopProcessingRules": "False"}
        trigger = b.add(src.m365(b.t(0), p.upn, "New-InboxRule", office, details=details, client="Client=OWA;Action=Outlook"))
        trigger.herring("Reguła przekazuje na ZEWNĘTRZNY adres. To powód alertu, ale warunek obejmuje tylko zamówienia, a adres należy do zatwierdzonego partnera.")
        noise(b, involved=[p])
        truth = b.truth(
            "btp", "info",
            "Detekcja jest zasadna (zewnętrzny adres docelowy), ale reguła przekazuje tylko zamówienia do zatwierdzonego partnera (SEC-2026-031, NDA 14/2025), z firmowego laptopa i IP biura.",
            f"BTP. {p.upn}: New-InboxRule → {partner} tylko dla tematów „zamówienie/ZK/”. Partner z umową NDA 14/2025, zatwierdzone w SEC-2026-031, logowanie ze znanego urządzenia. "
            "Zamykam bez eskalacji.",
            lookups=["ti:partner-logistyka.example", f"change:{p.host}"])
    b.finish(trigger, source="SIEM", rule="Inbox rule created with a forwarding action", severity="high",
             description=f"Utworzono regułę skrzynki {p.upn} z akcją przekazywania poczty.", truth=truth,
             lessons=LESSONS_RULE)

