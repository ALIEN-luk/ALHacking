# Raport o sekretach — szablon i rejestr

Szablon służy do raportowania znalezisk **bez ujawniania wartości** (zasady 1, 4 i 5 w
[`SECRETS_POLICY.md`](SECRETS_POLICY.md)). Wypełniaj pola nazwami z JSON-a narzędzia
(`tools/secrets/mask_secrets.py --format json`), aby raporty były spójne i nadawały się do
automatycznego przetwarzania.

## 1. Metadane

| Pole | Wartość |
| --- | --- |
| Raport ID | `SEC-<rok>-<nr>` |
| Data / autor | `<YYYY-MM-DD>` / `<osoba lub agent>` |
| Zakres | `<ścieżki, commit, gałąź>` |
| Własność materiału | `unknown` / `user` / `third_party` |
| Podstawa uprawnienia | `<oświadczenie właściciela lub dokument>` |
| Narzędzie | `mask_secrets <wersja>, reguły: <lista>` |
| Zapytania sieciowe | `brak` (walidacja sekretów nigdy nie jest wykonywana) |

## 2. Podsumowanie

| Krytyczne | Wysokie | Średnie | Razem | Wymaga rotacji |
| --- | --- | --- | --- | --- |
| `<n>` | `<n>` | `<n>` | `<n>` | `<n>` |

## 3. Znaleziska

| ID | Typ / usługa | Lokalizacja | Wartość (zamaskowana) | Własność | Status | Zalecenie |
| --- | --- | --- | --- | --- | --- | --- |
| `F-0001` | `openai_api_key` / OpenAI | `app.env:12` | `sk-proj••••••EEXA` | `unknown` | `pattern-match` | unieważnij lub zrotuj, usuń z pliku |
| `F-0002` | `otp_or_recovery_code` / kody jednorazowe | `notes.md:4` | `••••••` | `third_party` | `unverified` | zgłoś właścicielowi, nie używaj |
| `F-0003` | `uri_with_password` / connection string | `docker-compose.yml:9` | `EXAMPLE••••••d123` | `user` | `pattern-match` | rotacja hasła, przenieś do menedżera sekretów |

Zakazane w tym miejscu: pełne wartości, fragmenty pozwalające odtworzyć sekret, kopie plików
z sekretami, zrzuty ekranu z widoczną wartością.

## 4. Autoryzacja ujawnienia (wypełnij tylko, jeśli dotyczy)

| Pole | Wartość |
| --- | --- |
| Żądanie | `--reveal` / brak |
| Oświadczenie | `<treść oświadczenia właściciela>` |
| Zadeklarowane pliki | `<lista --owned-file>` |
| Kanał | `stdout` (nigdy plik ani log) |
| Data / osoba zatwierdzająca | `<...>` |

Ujawnienie pełnej wartości wymaga spełnienia wszystkich warunków z zasady 2; raport nigdy nie
zawiera samej wartości.

## 5. Kroki wykonane i planowane

- [ ] Sekret usunięty z bieżącej wersji pliku
- [ ] Sekret przeniesiony do menedżera sekretów / zmiennej środowiskowej poza kontrolą wersji
- [ ] Klucz unieważniony lub zrotowany (kiedy: `<data>`, przez kogo: `<kto>`)
- [ ] Zaktualizowane miejsca użycia po rotacji: CI/CD, `.env`, wdrożenia, integracje
- [ ] Oczyszczona historia git, jeśli sekret trafił do commitów (`git filter-repo` / BFG)
- [ ] Zgłoszenie do właściciela systemu (dla sekretów osoby trzeciej)
- [ ] Dodana reguła/test wykrywania, jeśli pojawił się nowy format

## 6. Rejestr incydentów (bez wartości)

| ID | Data | Typ / usługa | Lokalizacja | Ekspozycja | Podjęte kroki | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `SEC-2026-001` | `<data>` | `github_token` / GitHub | `old/scripts/deploy.sh:44` | historia git, kopia lokalna | rotacja + `filter-repo`, zgłoszenie | zamknięte |

## 7. Kontrola przed publikacją raportu

- [ ] Raport nie zawiera żadnej pełnej wartości sekretu (sprawdź cały plik, także komentarze i załączniki).
- [ ] Zamaskowane wartości zachowują tylko to, co niezbędne do identyfikacji.
- [ ] Kod jednorazowy nie pojawia się w żadnej formie (nawet zamaskowanej z fragmentami).
- [ ] Nazwy plików, identyfikatory zgłoszeń i tytuły nie zawierają identyfikatorów sekretów.
- [ ] Raport nie zawiera linków umożliwiających dostęp (linki resetujące hasło, kody zaproszeń),
  a jeśli zawiera — są unieważnione lub zredagowane.
- [ ] Dla sekretów osoby trzeciej raport zawiera wyłącznie lokalizację, typ i zalecenie zgłoszenia.
- [ ] Sama publikacja raportu nie zmienia stanu ryzyka: sekret jest już w trakcie rotacji lub unieważniony.
