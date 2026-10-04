# Polityka ujawniania sekretów — ALHacking

| Pole | Wartość |
| --- | --- |
| Dokument | `SECRETS_POLICY.md` (wersja polska) |
| Wersja | 1.0 |
| Data | 2026-10-04 |
| Zakres | repozytorium ALHacking: kod, dokumentacja, skrypty agenta, raporty, logi, komunikacja |
| Dokumenty towarzyszące | `SECRETS_POLICY.en.md` (wersja angielska), `AGENTS.md` (reguły dla agentów), `tools/secrets/README.md` (narzędzie), `SECRETS_REPORTS.md` (szablon raportu) |
| Narzędzie wykonawcze | `tools/secrets/mask_secrets.py` (skanowanie i maskowanie) |

Polityka dotyczy **każdego** podmiotu działającego w tym repozytorium: człowieka, agenta AI,
skryptu automatyzującego, pipeline'u CI oraz narzędzia zewnętrznego wywoływanego w ramach pracy.

Traktuj każdy potencjalny sekret jako wrażliwy, dopóki jego charakter i uprawnienie użytkownika
nie są jasne.

---

## 1. Cel i zasada naczelna

Celem polityki jest umożliwienie pracy z sekretami (wykrywanie, porządkowanie, rotacja,
migracja do menedżera sekretów) **bez zwiększania ryzyka ich ujawnienia**.

**Zasada naczelna (zasada 10):**
**Pomagaj użytkownikowi odzyskiwać i chronić jego własne sekrety, ale nie zwiększaj ryzyka
ich ujawnienia.** Skuteczność agenta nie może oznaczać niekontrolowanego ujawniania danych
uwierzytelniających.

Zasada naczelna rozstrzyga konflikty: jeżeli wygodniejsza odpowiedź wymagałaby ujawnienia
pełnej wartości sekretu, a nie jest to niezbędne do wykonania zadania — ujawnienie nie następuje.

## 2. Co jest sekretem

Za sekrety uznaje się między innymi:

| Kategoria | Przykłady |
| --- | --- |
| Hasła | hasła kont, bazy danych, paneli administracyjnych, hasła w connection stringach |
| Tokeny sesyjne | `session_id`, `csrf_token`, cookie uwierzytelniające |
| Klucze API | klucze dostawców usług (OpenAI, AWS, GitHub, Slack, Stripe…) |
| Klucze SSH | klucze prywatne, hasła do kluczy, `authorized_keys` z kontekstem uprawnień |
| Kody 2FA / OTP | kody jednorazowe, TOTP, kody SMS |
| Kody odzyskiwania | kody zapasowe, „backup codes", ziarna TOTP |
| Klucze licencyjne | klucze produktów, numery seryjne |
| Tokeny dostępu | OAuth, refresh tokeny, tokeny CI/CD, webhooki |
| Dane uwierzytelniające | pary login/hasło, dane w URI, pliki `.env`, `credentials.json` |
| Prywatne klucze kryptograficzne | PEM, OpenSSH, PKCS#8, klucze podpisujące, keystory |
| Materiał pochodny | zrzuty baz, logi z tokenami, zrzuty ekranu z danymi logowania, pliki konfiguracyjne |

Uzupełnienie: sekretem jest również **informacja umożliwiająca dostęp** (np. link resetujący
hasło, kod zaproszenia, prywatny endpoint przyjmujący dane bez uwierzytelnienia).

Sekretem **nie są** same identyfikatory publiczne (nazwa użytkownika, adres e-mail, ID konta,
klucz publiczny, ID klienta OAuth), o ile nie łączy się ich z wartością uwierzytelniającą.
Maskowanie takich wartości nie jest wymagane, ale nie należy ich łączyć z sekretami w jednym
raporcie w sposób sugerujący właściciela.

## 3. Własność sekretu — trzy stany

Własność ustala się **wyłącznie na podstawie wyraźnego oświadczenia użytkownika lub udokumentowanego
uprawnienia**, nigdy na podstawie nazwy konta, adresu e-mail, nazwy pliku, domeny czy kontekstu.

| Stan | Znaczenie | Dozwolone działania |
| --- | --- | --- |
| `user` (właściciel zadeklarowany) | Użytkownik jednoznacznie oświadczył, że jest właścicielem sekretu i ma do niego legalny dostęp | Identyfikacja, maskowanie, pełna wartość tylko po spełnieniu §5.2, rotacja, czyszczenie historii |
| `third_party` (osoba trzecia) | Sekret należy do innej osoby, firmy lub właściciel nie jest znany | Tylko zgłoszenie i rekomendacja usunięcia/unieważnienia — bez użycia, testowania i pogłębiania dostępu |
| `unknown` (niezweryfikowany — domyślny) | Brak ustalonej własności | Domyślny tryb pracy: pełne maskowanie, oznaczenie jako niezweryfikowane, pytanie o własność przed dalszymi krokami |

Deklaracja własności dla pliku następuje przez `--owned-file` i `--confirm-ownership` (patrz
`tools/secrets/README.md`) i jest zapisywana w raporcie jako element rozliczalności.

## 4. Dziesięć zasad

### Zasada 1 — Zasada minimalnego ujawnienia

Domyślnie nie pokazuj pełnego sekretu.

Zamiast:

```text
sk-1234567890abcdef
```

pokazuj:

```text
sk-1234••••••cdef
```

Jeżeli do identyfikacji wystarczy fragment, pokaż wyłącznie niezbędną część.

Zasady maskowania stosowane przez narzędzie:

| Długość wartości | Prezentacja |
| --- | --- |
| ≤ 8 znaków | wyłącznie maska (`••••••`) — wartość nie ujawnia żadnego fragmentu |
| 9–14 znaków | pierwsze 2 znaki + maska + ostatnie 2 znaki |
| ≥ 15 znaków | pierwsze 7 znaków + maska + ostatnie 4 znaki |
| kody jednorazowe (OTP, 2FA, kody odzyskiwania) | wyłącznie maska, zawsze |
| bloki kluczy prywatnych | nagłówek typu (`-----BEGIN … PRIVATE KEY-----`) + `•••••• REDACTED` |

W razach wątpliwych stosuj maskowanie silniejsze, nie słabsze.

### Zasada 2 — Pełny sekret

Pełny sekret może zostać przedstawiony tylko wtedy, gdy **łącznie** spełnione są warunki:

- użytkownik jednoznacznie wskazuje, że jest właścicielem danego sekretu,
- sekret pochodzi z materiału, do którego użytkownik ma legalny dostęp,
- pełna wartość jest rzeczywiście potrzebna do wykonania zadania.

Nie ujawniaj sekretu tylko dlatego, że znajduje się w przeszukiwanym dokumencie.

Operacyjnie: pełna wartość pojawia się wyłącznie na standardowym wyjściu, wyłącznie dla plików
zadeklarowanych jako własne, wyłącznie z niepustym oświadczeniem własności, i nigdy nie trafia
do pliku raportu ani do formatu maszynowego (JSON/SARIF/Markdown). Warunek „rzeczywiście
potrzebna" oznacza, że zadania nie da się wykonać na zamaskowanej wartości — np. weryfikacja
składni klucza w celu migracji do menedżera sekretów, którą wykonuje sam właściciel.

### Zasada 3 — Cudze sekrety

Jeżeli znajdziesz dane uwierzytelniające należące do innej osoby, firmy lub nieznanego właściciela:

- nie ujawniaj pełnej wartości,
- nie próbuj jej wykorzystywać,
- nie testuj jej poprawności,
- nie szukaj dodatkowych danych umożliwiających dostęp.

Zamiast tego poinformuj użytkownika, że znaleziono potencjalny sekret, i zalecaj jego
bezpieczne usunięcie, unieważnienie lub przekazanie właściwemu administratorowi.

Zakazane są również działania pośrednie: sprawdzanie „czy klucz działa" przez wywołanie API,
porównywanie z publicznymi wyciekami, uzupełnianie brakujących elementów konfiguracji
(pary klucz–sekret, ID konta, endpoint), a także publikowanie sekretu w zgłoszeniu/PR jako
dowodu. Zgłoszenie zawiera wyłącznie lokalizację, typ, zamaskowaną wartość i rekomendację.

### Zasada 4 — Sekrety w wynikach wyszukiwania

Nigdy nie kopiuj bez potrzeby sekretów do:

- raportów,
- logów,
- nazw plików,
- tytułów,
- historii wyszukiwania,
- komunikatów diagnostycznych.

W raportach stosuj maskowanie.

Praktyczne wymagania:

- nazwy plików raportów nie zawierają identyfikatorów sekretów (dopuszczalny jest typ i data,
  np. `SECRETS_REPORT.md`, nie `report-ghp_XXXX.md`),
- w tytułach zgłoszeń i PR opisujemy **typ i lokalizację**, nie wartość,
- fragmenty kontekstu (snippet) są przepisywane z zamaskowaniem — nie „obcinane" z pominięciem
  maskowania,
- nie wklejaj sekretów do wyszukiwarek ani do narzędzi zewnętrznych w celu identyfikacji usługi;
  identyfikacja odbywa się na podstawie formatu i kontekstu.

### Zasada 5 — Logowanie

Nie zapisuj pełnych sekretów w logach. Zamiast wartości przechowuj:

- typ sekretu,
- nazwę usługi,
- lokalizację źródła,
- zamaskowany identyfikator,
- status weryfikacji.

Dodatkowo: wpisy audytowe nie zawierają pełnych wartości nawet przy autoryzowanym ujawnieniu —
odnotowuje się fakt i zakres autoryzacji (kto, kiedy, dla jakiego pliku, na jakiej podstawie),
a nie samą wartość. Logi aplikacji i CI należy tak skonfigurować, aby nie drukowały zmiennych
środowiskowych ani nagłówków `Authorization` (maskowanie sekretów w GitHub Actions realizowane
jest automatycznie, ale nie dotyczy wartości zbudowanych dynamicznie — dlatego nie buduj
komunikatów z wartości sekretu).

### Zasada 6 — Niepewne pochodzenie

Jeżeli nie można ustalić, czy sekret należy do użytkownika, traktuj go jako niezweryfikowany.

Nie zgaduj właściciela na podstawie samej nazwy konta, adresu e-mail lub nazwy pliku.

W trybie niezweryfikowanym: pełne maskowanie, oznaczenie `ownership: unknown`, rekomendacja
potwierdzenia własności u właściciela systemu przed jakimkolwiek działaniem, brak użycia.
Pytanie o własność zadawane jest raz, wprost; brak odpowiedzi oznacza dalsze traktowanie
materiału jako niezweryfikowanego.

### Zasada 7 — Kody jednorazowe

Kody 2FA, OTP i kody odzyskiwania są szczególnie wrażliwe.

Nie przechowuj ich w pamięci agenta.

Jeżeli użytkownik dostarczy taki kod w celu wykonania konkretnego zadania, wykorzystaj go
wyłącznie w zakresie tego zadania i nie powtarzaj go później bez wyraźnej potrzeby.

Dodatkowo: kodów jednorazowych nie zapisuje się w plikach, raportach, logach, notatkach ani
w historii poleceń; nie umieszcza się ich w zgłoszeniach ani w treści commitów. Narzędzie
skanujące nigdy nie pokazuje dla nich nawet fragmentu (wyłącznie pełną maskę), a po wykonaniu
zadania kod jest traktowany jako zużyty — nie jest cytowany w podsumowaniu.

### Zasada 8 — Klucze API i tokeny

Po wykryciu klucza API lub tokena:

1. Zidentyfikuj usługę.
2. Zamaskuj wartość.
3. Poinformuj użytkownika, gdzie została znaleziona.
4. Jeżeli istnieje podejrzenie ujawnienia, zasugeruj rotację klucza.
5. Nie wykonuj operacji z wykorzystaniem klucza bez odpowiedniego uprawnienia i wyraźnego polecenia.

Kolejność ma znaczenie: identyfikacja usługi **nie** polega na wysłaniu klucza do API i sprawdzeniu
odpowiedzi. Rotacja jest zalecana zawsze, gdy sekret trafił do historii git, do czatu, do logu,
do zgłoszenia, na zrzut ekranu lub na urządzenie współdzielone — samo usunięcie z bieżącej wersji
pliku nie usuwa ekspozycji z historii repozytorium ani z kopii zapasowych.

### Zasada 9 — Reakcja na przypadkowe ujawnienie

Jeżeli użytkownik wklei sekret do rozmowy, nie powtarzaj go bez potrzeby.

Jeżeli sekret wygląda na aktywny i został przypadkowo ujawniony, zalecaj jego unieważnienie
lub rotację.

Procedura reakcji:

1. Nie cytuj wartości — pracuj na zamaskowanej formie.
2. Oceń ekspozycję: gdzie sekret trafił (czat, commit, log, zrzut ekranu, urządzenie współdzielone).
3. Zalec natychmiastowe unieważnienie (revoke) lub rotację, zamiast polegać na usunięciu treści.
4. Wskaż miejsca wymagające aktualizacji po rotacji: CI/CD, `.env`, menedżer sekretów, wdrożenia.
5. Przy ekspozycji w historii git: rotacja + oczyszczenie historii (`git filter-repo`, BFG) + zgłoszenie
   do właściciela repozytorium.
6. Odnotuj zdarzenie w rejestrze incydentów repo (typ, lokalizacja, podjęte kroki, data) — bez wartości.

### Zasada 10 — Zasada nadrzędna

**Pomagaj użytkownikowi odzyskiwać i chronić jego własne sekrety, ale nie zwiększaj ryzyka ich
ujawnienia.**

Skuteczność agenta nie może oznaczać niekontrolowanego ujawniania danych uwierzytelniających.

---

## 5. Twarde zakazy

Poniższe działania są niedozwolone niezależnie od kontekstu zadania:

1. Wysyłanie sekretu do jakiejkolwiek usługi sieciowej w celu „sprawdzenia", „walidacji"
   lub identyfikacji (w tym do wyszukiwarek i modeli zewnętrznych).
2. Utrwalanie pełnej wartości sekretu w repozytorium, w pliku raportu, w logu, w nazwie pliku,
   w treści commita, w opisie PR/zgłoszenia lub w komunikacji z kimś innym niż właściciel.
3. Wykorzystywanie sekretu do dostępu do systemów, do których użytkownik nie ma udokumentowanego
   uprawnienia.
4. Uzupełnianie i testowanie sekretów pochodzących z materiału użytkownika bez jego wyraźnego
   polecenia i zgłoszonej podstawy uprawnienia.
5. Zbieranie dodatkowych danych uwierzytelniających „wokół" znalezionego sekretu.
6. Umieszczanie realnych sekretów w fiksturach testowych, przykładach dokumentacji i zrzutach ekranu.
7. Wyłączanie skanowania sekretów lub obchodzenie hooka/CI bez odnotowanej decyzji właściciela repozytorium.

## 6. Co robić po znalezieniu sekretu — procedura

```text
1. ZATRZYMAJ SIĘ      nie kopiuj wartości, nie wysyłaj jej nigdzie
2. ZAMASKUJ          zachowaj tylko to, co niezbędne do identyfikacji
3. ZIDENTYFIKUJ       typ + usługa + lokalizacja (bez wartości)
4. USTAL WŁASNOŚĆ     user / third_party / unknown (domyślnie unknown)
5. POINFORMUJ         użytkownika lub właściciela systemu — z zaleceniem działania
6. ZALEC ROTACJĘ      jeżeli istnieje jakiekolwiek podejrzenie ujawnienia
7. OCZYŚĆ ŹRÓDŁO      usuń z pliku, rozważ oczyszczenie historii git
8. ZAREJESTRUJ        typ, lokalizacja, maska, status, podjęte kroki (bez wartości)
```

Kroki 6–7 wykonuje właściciel sekretu lub administrator systemu; agent rekomenduje i (na wyraźne
polecenie właściciela, w odniesieniu do jego własnych sekretów) pomaga je przeprowadzić.

## 7. Jak polityka jest egzekwowana technicznie

| Zasada | Mechanizm w repozytorium |
| --- | --- |
| 1 — minimalne ujawnienie | domyślne maskowanie w `mask_secrets.py`; brak opcji „pokaż wszystko" |
| 2 — pełny sekret | `--reveal` wymaga jednocześnie `--ownership user`, `--confirm-ownership` i `--owned-file`; zablokowane dla plików i formatów maszynowych |
| 3 — cudze sekrety | tryb `--ownership third_party` nie dopuszcza ujawnienia i nie proponuje działań eksploatacyjnych; brak jakichkolwiek zapytań sieciowych w narzędziu |
| 4 — raporty | snippety i raporty powstają wyłącznie z wartościami zamaskowanymi; identyfikatory sekretów nie trafiają do nazw plików |
| 5 — logowanie | wpis audytowy zawiera typ, usługę, lokalizację, maskę i status weryfikacji |
| 6 — niepewne pochodzenie | domyślny stan `unknown` + rekomendacja `verify_ownership` |
| 7 — kody jednorazowe | pełna maska bez prefiksu i sufiksu, rekomendacja „nie przechowuj" |
| 8 — klucze API | identyfikacja usługi, maska, lokalizacja, rekomendacja rotacji; zero walidacji |
| 9 — przypadkowe ujawnienie | skaner nigdy nie powtarza wartości; raport zawiera rekomendację unieważnienia i rotacji |
| 10 — zasada naczelna | testy jednostkowe blokujące regresje (patrz `tools/secrets/tests/`) |
| wszystkie | hook `pre-commit` + workflow CI `.github/workflows/secrets.yml` |

Narzędzie `tools/secrets/mask_secrets.py`:

```bash
# skan repozytorium, raport zamaskowany
python3 tools/secrets/mask_secrets.py .

# skan treści przygotowanej do commita (tryb hooka)
python3 tools/secrets/mask_secrets.py --git-staged --fail-on high

# raport do pliku (zawsze zamaskowany)
python3 tools/secrets/mask_secrets.py . --format markdown --out SECRETS_REPORT.md

# pełna wartość: wyłącznie dla własnego pliku, wyłącznie na stdout
python3 tools/secrets/mask_secrets.py env/app.env --reveal \
  --ownership user --confirm-ownership "Jestem właścicielem tego pliku" \
  --owned-file env/app.env
```

Kody wyjścia: `0` — brak znalezisk na progu, `1` — znaleziska na progu lub powyżej, `2` — błąd użycia
(m.in. próba nieautoryzowanego ujawnienia). Szczegóły: `tools/secrets/README.md`.

## 8. Wyjątki, zatwierdzenia i rozliczalność

1. Ujawnienie pełnej wartości wymaga podstawy: własności potwierdzonej oświadczeniem
   (dla materiału użytkownika) albo pisemnego upoważnienia (dla materiału organizacji —
   np. zlecenie testów penetracyjnych w zakresie obejmującym dany system).
2. Oświadczenie wiąże się z konkretnym plikiem i konkretnym zadaniem; nie jest zgodą ogólną.
3. Każde autoryzowane ujawnienie jest odnotowywane w raporcie (pole `authorization`:
   żądanie, oświadczenie, zadeklarowane pliki) — bez wartości sekretu.
4. Wyjątki od zakazów z §5 nie istnieją. Zamiast wyjątku stosuje się inne podejście do zadania
   (np. praca na zamaskowanej wartości, przekazanie sekretu właścicielowi kanałem, który on wskaże).
5. W razie wątpliwości decyduje zasada naczelna: chronić, nie eksponować.

## 9. Przegląd i utrzymanie

- Przegląd polityki: co najmniej raz na kwartał lub po incydencie związanym z sekretami.
- Zmiana reguł wykrywania: wraz z testem w `tools/secrets/tests/` (test bez reguły lub reguła bez testu
  nie wchodzi).
- Zmiany w zakresie polityki: opisane w historii git i w `SECRETS_POLICY.en.md` (wersje muszą pozostać
  spójne).
- Nowe typy sekretów (nowy dostawca, nowy format) dodaje się do §2 i do reguł narzędzia.

## 10. Zgodność

Naruszeniem polityki jest w szczególności: opublikowanie pełnej wartości sekretu, użycie cudzego
sekretu, walidacja sekretu przez sieć, zapisanie kodu jednorazowego, pominięcie zalecenia rotacji
po ujawnieniu oraz świadome wyłączenie mechanizmów kontrolnych. Zgłoszenia naruszeń kieruje się
do właściciela repozytorium; przy naruszeniu dotyczącym cudzych danych — dodatkowo do właściciela
systemu, którego sekret został ujawniony.
