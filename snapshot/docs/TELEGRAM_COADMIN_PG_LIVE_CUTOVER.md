# Telegram co-admin PostgreSQL LIVE cutover (#161)

Target: PostgreSQL is the authoritative database for all co-admin authorization, invite creation, approval, rejection, and revocation. No SQLite fallback.

Separate role: bvp_telegram_coadmin_live, limited to SELECT/INSERT/UPDATE/DELETE on six live tables; deleted rows are copied by SECURITY DEFINER trigger into private deleted_audit. No direct rights to backup, telemetry, shadow or other schemas.

Authentication: only Unix socket with SCRAM. Add an exact pg_hba rule for this database and role before general local peer. Create a random role password on VPS and keep it in a root-owned 0600 file outside Git. Pass it to existing bot via systemd LoadCredential and CREDENTIALS_DIRECTORY; do not print it or copy to chat.

Cutover gate: git branch/PR main; real QA database with invite/join/approve/revoke and duplicate callback tests; systemd dynamic-user credential test; PostgreSQL snapshot and private SQLite backup; stop old mirror timer, pause only existing bot, final SQLite snapshot into PG stage, verify SHA/count/payload against PostgreSQL mirror, insert six tables into empty live schema in one transaction; set identity sequence values.

Deployment: replace only coadmin.py and add coadmin_pg_connection.py from merged main, with private rollback copy. Restart one existing bot and verify webhook, owner menu, permissions, passkey, services, and zero poller duplication. Keep SQLite intact but offline and disable SQLite shadow timer after cutover.

Rollback safety: before first PG writes, old SQLite can be used when fully quiesced. AFTER first PG mutation, do not restore old SQLite without explicit live-to-SQLite reconciliation, since stale privileges could be re-granted. Fail closed rather than revoking rollback safeguards.

Real two-device Android end-to-end invitations remain mandatory before closing issue #161. A synthetic QA test does not prove the phone workflow.

## Mini App invitee endpoint — dodatkowy release gate (#516)

Po scaleniu Draft PR #520 (Issue #516) nie wolno wdrażać wyłącznie `bot.py` i `coadmin.py`. Zestaw zgodny musi zawierać także `webapp_init_data.py` oraz zaktualizowany `deploy/telegram/runtime_files.txt`. `deploy/telegram_static_identity.py` wymaga tego modułu jako części kompletnego release. Przed restartem istniejącego pollera/webhooka obowiązkowe są testy offline, QA PostgreSQL, potwierdzenie dokładnego URL Main Mini App w BotFather, jawna konfiguracja `BVP_TELEGRAM_MAIN_MINI_APP_URL`, weryfikacja `getMe.has_main_web_app` i test na dwóch kontach Telegram. Nie tworzyć drugiego procesu bota, nie zmieniać owner-only gate i nie wdrażać tego Draft PR bez odrębnego GO.


## Deep-link invite locator (#516)
Mini App `start_param` zawiera wyłącznie `i1_<invite_id>_<32-hex HMAC tag>`, nie bearer kod zaproszenia. Backend weryfikuje tag z tokenem istniejącego bota, a następnie pobiera invite po ID i atomowo zużywa hash kodu zapisany w PostgreSQL. Kod fallback `/join_admin KOD` pozostaje obsługiwany. Brak migracji DB: wykorzystano istniejący `invitations.id` i `hash`.


Regeneracja invite zmienia kod/hash, więc zmienia się także HMAC locator `startapp`. Backend weryfikuje tag względem aktualnego hasha z tego samego rekordu w transakcji zużycia; stare linki stają się nieważne bez migracji DB.
