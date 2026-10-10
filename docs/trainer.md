# Trener SOC L1

Symulator alertów do ćwiczenia decyzji **TP / BTP / FP**. Generuje alert z logami z kilku źródeł, ukrywa werdykt,
a po Twojej decyzji pokazuje, co naprawdę się wydarzyło, które zdarzenia były kluczowe, które były zmyłką i co
należało sprawdzić. Powstał dlatego, że na nocnej zmianie rzadko pojawia się cokolwiek do rozpracowania, a
umiejętność oceny alertu trzeba trenować na dużej liczbie różnych przypadków.

```bash
pip install -e .
hunterscope train                  # http://localhost:8765, otwiera przeglądarkę
hunterscope train --port 9000 --no-browser
```

Nic nie wymaga internetu: UI to statyczne pliki bez zewnętrznych zależności, a wszystkie dane są syntetyczne.

## Jak wygląda ćwiczenie

1. **Alert**: reguła SIEM albo detekcja ESET z podstawowymi polami i zdarzeniem, które ją wywołało.
2. **Logi**: do 150 zdarzeń (Sysmon, Windows Security, ESET, proxy, DNS, firewall, Entra ID, M365, poczta, WAF) z szumem
   tła. Szukasz po tekście (`powershell -chrome`, `"10.20.31.5"`), filtrujesz po źródle, pokazujesz ±10 min wokół
   zdarzenia. **Kliknięcie dowolnej wartości** (IP, host, użytkownik, hash) daje menu: filtruj, sprawdź w TI, CMDB, HR
   albo kalendarzu zmian. To jest ćwiczenie korelacji.
3. **Drzewo procesów** z Sysmon 1: rodzic, podpis, integralność, ścieżka.
4. **Plik**: podpis, Mark-of-the-Web, popularność w organizacji, wynik sandboxa (dla scenariuszy z plikiem).
5. **Kontekst**: ewidencja zasobów, katalog użytkowników z HR, kalendarz zmian, threat intel. Brak wpisu to też
   odpowiedź, zgodnie z rzeczywistością (nieznany ≠ czysty).
6. **Narzędzia**: dekoder Base64 (UTF-16LE dla `-enc`), URL, UTC→CET, długość i entropia ciągu (pod DNS tunneling).
7. **Decyzja**: werdykt, akcje, ★ przy zdarzeniach, na których opierasz wniosek, oraz **obowiązkowe uzasadnienie**.
   Trzy podpowiedzi, każda kosztuje 5 pkt.
8. **Rozbiór**: wynik, prawidłowy przebieg, Twoje uzasadnienie obok wzorcowej notatki do ticketu, dowody
   (znalezione i przeoczone), zmyłki, akcje, brakujące sprawdzenia, oznaki TP i FP dla tego typu alertu, checklista,
   pułapki, MITRE ATT&CK, wskazówki gdzie to kliknąć w ESET i SIEM. Po rozbiorze logi pokazują, które zdarzenia były
   kluczowe.

### Werdykty

| | |
|---|---|
| **TP** | realny incydent, wymaga reakcji |
| **BTP** (Benign True Positive) | detekcja trafnie opisała zdarzenie, ale jest ono autoryzowane: skan podatności, test penetracyjny, narzędzie admina w oknie zmiany, symulacja phishingu |
| **FP** | detekcja się pomyliła, zdarzenie jest zwyczajne (telemetria, agent, aktualizator) |

BTP vs FP to mała pomyłka (oba zamykają zgłoszenie). Uznanie prawdziwego incydentu za niegroźny to największy błąd i
ogranicza wynik całego alertu do 30 pkt.

### Punktacja (100)

| | pkt | za co |
|---|---|---|
| Werdykt | 50 | BTP↔FP daje 30, FP/BTP uznane za TP 10-15, przeoczone TP 0 |
| Akcje | 15 | wymagane akcje, minus 4 za każdą szkodliwą (np. izolacja serwera przy FP) |
| Dowody | 20 | odsetek kluczowych zdarzeń z ★, minus 4 za zmyłkę |
| Dochodzenie | 15 | czy sprawdziłeś to, co sprawdziłby doświadczony analityk (TI, CMDB, zmiany) |
| Podpowiedzi | −5 | za każdą |

## Tryby

- **Alert**: jeden scenariusz naraz, poziom 1-3 (losowy), kategoria, opcja **„Ćwicz słabe punkty”** (losuje częściej
  scenariusze, w których masz niski wynik).
- **Nocna zmiana**: kolejka 6-12 alertów w realistycznym stosunku: głównie FP i BTP, jeden lub dwa prawdziwe
  incydenty ukryte w szumie. Na końcu podsumowanie, lista przeoczonych incydentów i **notatka przekazania zmiany**
  zbudowana z Twoich uzasadnień.
- **Statystyki**: trafność, macierz pomyłek (czy przeoczasz TP, czy za często eskalujesz), wyniki per scenariusz,
  ostatnie próby. Zapis w lokalnym SQLite (`~/.hunterscope/trainer.db`, `$HUNTERSCOPE_TRAINER_DB` lub `--db`).

### Poziomy trudności

| 1 | 2 | 3 |
|---|---|---|
| mało szumu, TI jednoznaczne („złośliwy”) | więcej szumu, TI „podejrzany” | dużo szumu, TI „brak danych”, brakuje części dowodów, zmyłki i wariant „TP bez oczywistych śladów” (np. podpisany, przemianowany procdump; MFA fatigue; dropper usunięty przez ESET, ale po wykonaniu) |

## Scenariusze

16 typów, każdy w wariantach TP / BTP / FP, z losowaną firmą, użytkownikami, hostami, IP i czasem:

| Kategoria | Scenariusz | Warianty |
|---|---|---|
| Endpoint | PowerShell `-EncodedCommand` | TP (makro), FP (SCCM), BTP (admin z JUMP01) |
| | Dostęp do pamięci LSASS | TP (comsvcs / procdump), FP (ekrn.exe) |
| | Nowe zadanie harmonogramu | TP (udawany Edge), FP (aktualizator), BTP (agent z SCCM) |
| | Usuwanie kopii VSS | TP (ransomware w toku), FP (zadanie na serwerze kopii), BTP (admin, INC) |
| ESET / pliki | Detekcja ESET na dokumencie z makrem | TP (zatrzymany lub wykonany), FP (arkusz firmowy), BTP (symulacja phishingu) |
| | Pobrany plik wykonywalny | TP (typosquatting), FP (instalator IT), BTP (legalny, niezatwierdzony) |
| | Narzędzie zdalnego dostępu | TP (oszustwo „na support”), BTP (helpdesk) |
| Tożsamość | Wiele nieudanych logowań | TP (spraying / MFA fatigue), FP (stare hasło), BTP (test penetracyjny) |
| | Logowanie z nietypowej lokalizacji | TP (AiTM), FP (telefon, błędny geo-IP), BTP (delegacja) |
| | Reguła skrzynki przekazująca pocztę | TP (BEC), FP (urlop), BTP (partner) |
| Sieć | Beaconing | TP, FP (telemetria) |
| | Anomalie DNS | TP (tunel), FP (brama pocztowa) |
| | Duży wolumen wychodzący | TP (insider w okresie wypowiedzenia), FP (kopia off-site) |
| | Skan portów | TP, BTP (skaner podatności), FP (monitoring) |
| | Zdalna usługa przez ADMIN$ | TP, BTP (PsExec w oknie), FP (SCCM) |
| | WAF: SQL injection | TP (zablokowane lub z włamaniem), BTP (skan), FP (wiki) |

Scenariusz jest w pełni określony tokenem `<seed>-<scenariusz>-<poziom>-<tryb>`, więc ten sam przypadek można
odtworzyć. Werdykt wynika z seeda i nie jest zapisany w tokenie.

## Wskaźniki nie zdradzają werdyktu

Trener celowo odbiera skróty typu „ten zakres IP albo ta końcówka domeny to atak”:

- **Jedna pula adresów dla wszystkich ról.** Adres atakującego, usługi SaaS, operatora komórkowego i firmowego NAT
  pochodzi z tych samych zakresów publicznych (RFC 5737 i 198.18.0.0/15). Adres wyjściowy biura jest losowany dla
  każdego scenariusza i ma wpis w TI. Test pilnuje, że w kodzie scenariuszy nie ma wpisanych na stałe zakresów.
- **Trzy kształty infrastruktury atakującego:** świeża domena (także na zaufanych TLD), typosquat marki (czasem
  zarejestrowany dawno temu i skategoryzowany jako „Business”) oraz **legalna usługa nadużyta jako hosting**
  (Azure Blob, S3, Google Storage, GitHub raw, Discord CDN). W trzecim przypadku TI mówi „czysty, znany dostawca”,
  więc o werdykcie decyduje proces, jego rodzic, polecenie i kontekst, a nie reputacja celu.
- **Zasadne zdarzenia ze strasznymi wskaźnikami:** agent na młodej domenie bez reputacji, który wygląda jak beacon
  (regularny odstęp, prawie stałe rozmiary, identyfikator hosta w URL), źródło testu penetracyjnego z reputacją
  „skaner”, zasadna detekcja na obcej domenie symulacji phishingu.
- Wiele scenariuszy TP nie ma żadnego zewnętrznego wskaźnika (LSASS, ransomware, PsExec, skan wewnętrzny).

W rozbiorze każdy scenariusz mówi wprost, czego nie rozstrzygała reputacja, a co rozstrzygało zachowanie.

## Eksport logów do własnego SIEM

```bash
hunterscope train-export 482133-ps_encoded-2-p -o scenariusz.ndjson            # bez odpowiedzi
hunterscope train-export 482133-ps_encoded-2-p --with-truth                     # ze spoilerami
```

Pozwala przećwiczyć zapytania (SPL, KQL, Lucene) na tych samych danych w prawdziwym narzędziu.

## Dodawanie scenariusza

Szablon to funkcja w `src/hunterscope/trainer/scenarios/*.py` zarejestrowana przez `@template(id, variants, lessons)`:

1. Zbuduj zdarzenia konstruktorami z `trainer/sources.py` (`sysmon_proc`, `proxy`, `entra`, `eset`...).
2. Oznacz zdarzenia: `.key("dlaczego to rozstrzyga")` albo `.herring("dlaczego to zmyłka")`.
3. Dodaj kontekst: `b.ti_bad / b.ti_good`, `b.change`, `b.use(person, **pola)`.
4. Zakończ `b.finish(...)` z `b.truth(verdict, severity, summary, note, required=..., lookups=...)`.
5. `Lessons` to materiał dydaktyczny (oznaki TP i FP, checklista, pułapki, ATT&CK, podpowiedzi).

`tests/test_trainer.py` sprawdza automatycznie, że każdy wariant każdego scenariusza ma dowody, że wszystkie
wymagane sprawdzenia coś zwracają i że idealna odpowiedź daje 100 pkt.

## Bezpieczeństwo i ograniczenia

- Serwer słucha tylko na `127.0.0.1`, odrzuca obce nagłówki `Host` / `Origin` (DNS rebinding) i wymaga
  `application/json` dla POST.
- UI renderuje logi wyłącznie przez `textContent` i działa pod CSP `default-src 'none'; script-src 'self'`.
  Zawartość logów traktujemy jak niezaufaną, nawet syntetyczną.
- Dane są wymyślone: firma, ludzie, hosty i domeny. Adresy IP pochodzą ze wspólnej puli zakresów
  dokumentacyjnych (RFC 5737, RFC 2544), a TI i sandbox są symulowane, więc żaden prawdziwy wskaźnik nie jest oznaczony jako złośliwy.
- To trener rozumowania, nie replika konkretnego produktu. Pola ESET PROTECT i Sysmon odwzorowują prawdziwe nazwy,
  ale wartości (nazwy detekcji, reputacja LiveGrid) są symulowane.
- Zbiór 16 scenariuszy jest skończony: po kilkunastu podejściach rozpoznasz schematy. Wtedy pomagają poziom 3,
  nocna zmiana i dopisywanie własnych szablonów.
