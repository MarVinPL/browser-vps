# Telegram Mini App — kontrakt weryfikacji initData (etap L1)

Status: verifier, podpisany publiczny locator zaproszenia, wspólna operacja zużycia zaproszenia i osobny endpoint Mini App są przygotowane w Draft PR #520. Brak uruchomionych testów CI/E2E i wdrożenia.

## Źródło tożsamości

- Mini App przekazuje backendowi surowe Telegram.WebApp.initData przez HTTPS.
- initDataUnsafe jest wyłącznie danymi prezentacyjnymi; nigdy nie może stanowić dowodu tożsamości.
- Backend weryfikuje HMAC-SHA-256 zgodnie z Telegram Web Apps, używając tokenu istniejącego bota pobranego wyłącznie z serwerowego magazynu sekretów.
- Standardowy UX nie wymaga ręcznego wpisywania Telegram ID, username ani kodu. Link `https://t.me/<bot_username>?startapp=i1_<invite_id>_<mac>` nie zawiera kodu zaproszenia. Parametr jest publicznym, nieautoryzującym locator-em z MAC HMAC (wersja i identyfikator rekordu); backend weryfikuje MAC przy użyciu tokenu bota, a następnie odszukuje rekord po ID i atomowo zużywa właściwy hash zaproszenia. Nie jest to samodzielny grant dostępu. Link jest generowany wyłącznie po dwóch bramkach: Bot API `getMe` potwierdza `has_main_web_app=true`, a operator jawnie ustawia `BVP_TELEGRAM_MAIN_MINI_APP_URL=https://148-113-182-137.sslip.io/vps-telegram/mini` po potwierdzeniu dokładnego URL w BotFather. `getMe` potwierdza istnienie Main Mini App, ale nie zwraca jej URL. Telegram przekazuje wtedy startapp jako podpisany `start_param`. Bez tej zmiennej link pozostaje wyłączony i działa dotychczasowa ścieżka `/join_admin KOD`.
- Po weryfikacji zwracany jest numeryczny Telegram user ID, podpisany auth_date i opcjonalny podpisany start_param. start_param jest ograniczony do składni Telegram (1–512 znaków A-Z/a-z/0-9/_/-); backend może go użyć jako wskazania zaproszenia dopiero po sprawdzeniu go z trwałym rekordem zaproszenia.
- Backend nie może przyjmować invite ID, Telegram ID ani username z initDataUnsafe lub zwykłego JSON klienta. start_param musi pochodzić z pól objętych zweryfikowanym HMAC.

## Wymagania parsera i walidacji

- Ograniczenie rozmiaru payloadu i liczby pól; odrzucenie duplikatów, niepoprawnego kodowania, brakujących pól i niepoprawnego JSON.
- Kanoniczny data_check_string: pola posortowane leksykograficznie, po jednej parze key=value na linię, bez hash.
- Klucz pośredni: HMAC-SHA-256 z kluczem WebAppData i wiadomością równą tokenowi bota; podpis porównywany stałoczasowo.
- Świeżość auth_date: domyślnie maksymalnie 300 sekund; tolerancja zegara do 30 sekund w przyszłość.
- Token bota nie może pochodzić z requestu, logów, repozytorium ani klienta.

## Granica odpowiedzialności

Weryfikacja initData jest osobna od operacji zaproszenia. Osobny POST `/mini-join` w `src/telegram/bot.py` przyjmuje wyłącznie surowe initData w nagłówku, wymaga zweryfikowanego locator-a `i1_<invite_id>_<mac>` i przekazuje zweryfikowany Telegram user ID oraz invite ID do `coadmin.submit_invitation`. Kod jednorazowy nie trafia do URL; istniejący kod pozostaje dostępny wyłącznie jako fallback `/join_admin KOD`. Ta sama funkcja obsługuje teraz `/join_admin KOD`; nie jest konstruowany sztuczny update Bot API. W PostgreSQL istniejący hash zaproszenia jest zużywany atomowo (hash=NULL), z istniejącym limitem prób, pending_uid, terminem decyzji i jednorazowym nonce dla decyzji właściciela. Właściciel dostaje dotychczasowy przycisk approve/reject. Mini App otrzymuje tylko status zgłoszenia; nie dostaje dostępu do owner-only `/mini-api` ani `/mini-photo`.

Nadal nie ma osobnego rekordu przeglądarkowej sesji invitee ani enrollment grantu Passkey; ten etap nie tworzy sesji, nie zatwierdza zaproszenia i nie nadaje uprawnień.

Pozostaje: (1) potwierdzić w BotFather dokładny URL Main Mini App, ustawić jawne `BVP_TELEGRAM_MAIN_MINI_APP_URL` w kontrolowanym środowisku i sprawdzić, że `getMe.has_main_web_app=true`, (2) uruchomić testy jednostkowe i CI oraz wykonać E2E na testowej bazie PostgreSQL, (3) dopiero osobno zaprojektować powiązanie zaakceptowanego principal z sesją i jednorazowym grantem WebAuthn dla #517. Obecne `/mini`, `/mini-api` i `/mini-photo` pozostają owner-only. Telegram potwierdza kontrolę nad kontem Telegram, nie prawną tożsamość człowieka.

## Testy

`tests/test_telegram_webapp_init_data.py` pokrywa HMAC, tampering, obcy token, TTL, future skew, duplikaty, malformed input, Telegram user ID i signed start_param. `tests/test_coadmin_miniapp_join.py` pokrywa wspólne zużycie zaproszenia, replay, rate limit, wygasanie, istniejącego administratora i warunek Main Mini App. Testy nie kontaktują się z Telegramem ani VPS.

Brak GO do produkcji: zmiany są wyłącznie w Draft PR #520. Nie wykonywać deploymentu, nie włączać rejestracji Passkey ani nie zmieniać istniejącego logowania właściciela. Weryfikacja CI i E2E pozostaje niepotwierdzona.


## Ochrona kodu zaproszenia w deep-linku

Deep-link nie zawiera bearer kodu zaproszenia. `start_param` ma format `i1_<invite_id>_<32-hex HMAC tag>` i jest wyliczany z ID rekordu przy użyciu tokenu istniejącego bota jako klucza HMAC. Backend weryfikuje tag stałoczasowo, a następnie pobiera rekord po ID i wykorzystuje wyłącznie zapisany w bazie hash kodu do atomowego zużycia zaproszenia. Locator wskazuje rekord, ale nie nadaje uprawnień; wniosek nadal wymaga decyzji właściciela. Wariant kodowy `/join_admin KOD` pozostaje bez zmian.


## Rotacja i unieważnianie locatora
MAC jest wyliczany z wersji protokołu, invite ID oraz aktualnego SHA-256 kodu zaproszenia. Backend porównuje locator z hashem pobranym w tej samej transakcji co zużycie invite. Regeneracja kodu zmienia hash i automatycznie unieważnia poprzedni `startapp`, bez dodatkowej kolumny/migracji. Locator nie ujawnia kodu ani jego hasha.
