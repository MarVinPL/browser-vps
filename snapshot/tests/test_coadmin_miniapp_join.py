"""Shared invitation-consumption tests for Bot API and Mini App entry points."""
import hashlib
import sqlite3
import unittest
from pathlib import Path
from unittest.mock import patch

from src.telegram import coadmin


OWNER = 123
USER = 456
CODE = "SyntheticInviteCode1234567890"
NOW = 1_800_000_000


class MiniAppInviteSubmissionTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript("""
            CREATE TABLE members(uid INTEGER PRIMARY KEY, joined_at INTEGER);
            CREATE TABLE attempts(uid INTEGER PRIMARY KEY, count INTEGER, started INTEGER);
            CREATE TABLE invitations(id INTEGER PRIMARY KEY, hash TEXT UNIQUE,
                expires INTEGER, pending_uid INTEGER, pending_name TEXT,
                pending_until INTEGER, nonce TEXT UNIQUE, created_at INTEGER,
                issued_seconds INTEGER);
            CREATE TABLE denied_alerts(uid INTEGER PRIMARY KEY, last_at INTEGER);
            CREATE TABLE invite_history(
                id INTEGER PRIMARY KEY AUTOINCREMENT, invite_id INTEGER,
                action TEXT, actor_id INTEGER, subject_id INTEGER, at INTEGER,
                decision_nonce_hash TEXT
            );
            INSERT INTO invitations VALUES(
                7, '"""+hashlib.sha256(CODE.encode()).hexdigest()+"""',
                1800000600, NULL, NULL, NULL, NULL, 1799999900, 600
            );
        """)
        self.calls = []
        self.patches = [
            patch.object(coadmin, "connect", return_value=self.db),
            patch.object(coadmin, "trace"),
            patch.object(coadmin, "failed_code_alert"),
            patch.object(coadmin.time, "time", return_value=NOW),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def tearDown(self):
        self.db.close()

    def request(self, token, method, payload):
        self.assertEqual(token, "fixture-token")
        self.calls.append((method, payload))
        return True

    def submit(self, code=CODE, *, notify_applicant=False, uid=USER,
               invite_id=None, invite_tag=None):
        return coadmin.submit_invitation(
            uid, None if invite_id is not None else code, {}, OWNER,
            self.request, "fixture-token", now=NOW,
            notify_applicant=notify_applicant, source="Mini App",
            invite_id=invite_id, invite_tag=invite_tag,
        )


    def test_consumed_invite_does_not_disclose_already_pending_without_valid_mac(self):
        invite_hash = hashlib.sha256(CODE.encode()).hexdigest()
        locator = coadmin.miniapp_invite_start_param(7, "fixture-token", invite_hash)
        _, tag = coadmin.parse_miniapp_invite_start_param(locator)
        self.db.execute(
            "UPDATE invitations SET hash=NULL,pending_uid=?,pending_name=?,pending_until=?,nonce=? WHERE id=7",
            (USER, "@existing_user", NOW + 600, "existing-pending-nonce"),
        )
        self.db.commit()
        result = self.submit(invite_id=7, invite_tag=tag)
        self.assertEqual(result["status"], "invalid")

    def test_owner_alert_includes_verified_sender_username(self):
        result = coadmin.submit_invitation(
            USER, CODE, {"username": "invitee_user"}, OWNER,
            self.request, "fixture-token", now=NOW, source="Bot API",
        )
        self.assertEqual(result["status"], "pending_owner_approval")
        owner_alerts = [
            p for method, p in self.calls
            if method == "sendMessage" and p["chat_id"] == OWNER
        ]
        self.assertEqual(len(owner_alerts), 1)
        self.assertIn("👤 Nazwa: @invitee_user", owner_alerts[0]["text"])

    def test_invite_admin_command_delivers_created_code_without_nameerror(self):
        generated_code = "Z" * 32  # Distinct from the fixture invitation inserted in setUp.
        with (
            patch.object(coadmin, "generate_invite_code", return_value=generated_code),
            patch.object(coadmin, "miniapp_invite_url", return_value=None),
        ):
            handled = coadmin.handle(
                "fixture-token", OWNER,
                {"message": {
                    "from": {"id": OWNER, "username": "owner"},
                    "chat": {"id": OWNER, "type": "private"},
                    "date": NOW, "text": "/invite_admin",
                }},
                self.request,
            )
        self.assertTrue(handled)
        sent = [
            p for method, p in self.calls
            if method == "sendMessage" and p["chat_id"] == OWNER
        ]
        self.assertEqual(len(sent), 1)
        self.assertIn(generated_code, sent[0]["text"])
        row = self.db.execute(
            "SELECT hash,expires FROM invitations ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(row[0], hashlib.sha256(generated_code.encode()).hexdigest())
        self.assertEqual(row[1], NOW + coadmin.TTL)

    def test_miniapp_uses_same_single_use_invite_and_owner_approval(self):
        locator = coadmin.miniapp_invite_start_param(
            7, "fixture-token", hashlib.sha256(CODE.encode()).hexdigest()
        )
        invite_id, invite_tag = coadmin.parse_miniapp_invite_start_param(locator)
        result = self.submit(invite_id=invite_id, invite_tag=invite_tag)
        self.assertEqual(result, {"status": "pending_owner_approval"})
        row = self.db.execute(
            "SELECT hash,pending_uid,pending_name,pending_until,nonce "
            "FROM invitations WHERE id=7"
        ).fetchone()
        self.assertIsNone(row[0])
        self.assertEqual(row[1], USER)
        self.assertEqual(row[2], "Mini App (Telegram)")
        self.assertEqual(row[3], NOW + 600)
        self.assertTrue(row[4])
        owner_alerts = [
            p for method, p in self.calls
            if method == "sendMessage" and p["chat_id"] == OWNER
        ]
        self.assertEqual(len(owner_alerts), 1)
        self.assertIn("Telegram Mini App", owner_alerts[0]["text"])
        self.assertIn("admin:approve:", str(owner_alerts[0]["reply_markup"]))
        self.assertFalse(any(
            method == "sendMessage" and p["chat_id"] == USER
            for method, p in self.calls
        ))

    def test_replay_cannot_consume_or_create_second_pending_request(self):
        first = self.submit()
        self.calls.clear()
        second = self.submit()
        self.assertEqual(first["status"], "pending_owner_approval")
        self.assertEqual(second["status"], "invalid")
        self.assertFalse(any(
            method == "sendMessage" and p["chat_id"] == OWNER
            for method, p in self.calls
        ))
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM invitations WHERE pending_uid=?", (USER,)).fetchone()[0],
            1,
        )

    def test_legacy_bot_api_path_can_still_notify_applicant(self):
        result = self.submit(notify_applicant=True)
        self.assertEqual(result["status"], "pending_owner_approval")
        destinations = [
            p["chat_id"] for method, p in self.calls if method == "sendMessage"
        ]
        self.assertEqual(destinations, [OWNER, USER])

    def test_expired_invitation_is_rejected(self):
        self.db.execute("UPDATE invitations SET expires=? WHERE id=7", (NOW - 1,))
        result = self.submit()
        self.assertEqual(result["status"], "expired")
        self.assertIsNone(
            self.db.execute("SELECT pending_uid FROM invitations WHERE id=7").fetchone()[0]
        )

    def test_rate_limit_is_shared_by_verified_telegram_user(self):
        self.db.execute("INSERT INTO attempts VALUES(?,?,?)", (USER, 5, NOW - 10))
        result = self.submit()
        self.assertEqual(result["status"], "rate_limited")
        self.assertIsNone(
            self.db.execute("SELECT pending_uid FROM invitations WHERE id=7").fetchone()[0]
        )

    def test_existing_member_does_not_consume_invitation(self):
        self.db.execute("INSERT INTO members VALUES(?,?)", (USER, NOW - 10))
        result = self.submit()
        self.assertEqual(result["status"], "already_admin")
        self.assertIsNotNone(
            self.db.execute("SELECT hash FROM invitations WHERE id=7").fetchone()[0]
        )

    def test_owner_cannot_use_an_invitation(self):
        result = self.submit(uid=OWNER)
        self.assertEqual(result["status"], "owner")
        self.assertIsNotNone(
            self.db.execute("SELECT hash FROM invitations WHERE id=7").fetchone()[0]
        )


    def test_production_deep_links_remain_disabled_until_separate_release(self):
        def unexpected_request(*args):
            self.fail("Production bot API must not be queried for a Mini App invite link.")
        with patch.dict(coadmin.os.environ, {
            "BVP_TELEGRAM_TEST_MODE": "",
            "BVP_TELEGRAM_MAIN_MINI_APP_URL": "https://148-113-182-137.sslip.io/vps-telegram/mini",
            "BVP_TELEGRAM_TEST_MINI_APP_URL": "https://148-113-182-137.sslip.io/vps-telegram-test/mini",
        }):
            self.assertIsNone(
                coadmin.miniapp_invite_url(unexpected_request, "fixture-token", 7, CODE)
            )

    def test_production_bot_does_not_expose_mini_join_http_route(self):
        source = (Path(__file__).parents[1] / "src" / "telegram" / "bot.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('self.path=="/mini-join"', source)
        self.assertNotIn('fetch("./mini-join"', source)
        self.assertNotIn("webapp_init_data", source)

    def test_no_deep_link_when_main_mini_app_is_not_configured(self):
        def not_configured(token, method, payload):
            return {"username": "BrowserVpsBot", "has_main_web_app": False}
        with patch.dict(coadmin.os.environ, {
            "BVP_TELEGRAM_TEST_MODE": "1",
            "BVP_TELEGRAM_TEST_MINI_APP_URL": "",
        }):
            self.assertIsNone(coadmin.miniapp_invite_url(not_configured, "fixture-token", 7, CODE))

    def test_invalid_bot_username_never_becomes_a_link(self):
        def invalid_username(token, method, payload):
            return {"username": "bad/name", "has_main_web_app": True}
        with patch.dict(coadmin.os.environ, {
            "BVP_TELEGRAM_TEST_MODE": "1",
            "BVP_TELEGRAM_TEST_MINI_APP_URL": "https://148-113-182-137.sslip.io/vps-telegram-test/mini"
        }):
            self.assertIsNone(coadmin.miniapp_invite_url(invalid_username, "fixture-token", 7, CODE))


    def test_signed_public_locator_rejects_tampering_and_wrong_bot(self):
        invite_hash = hashlib.sha256(CODE.encode()).hexdigest()
        locator = coadmin.miniapp_invite_start_param(7, "fixture-token", invite_hash)
        self.assertEqual(
            coadmin.verify_miniapp_invite_start_param(locator, "fixture-token", invite_hash), 7
        )
        tampered = locator[:-1] + ("0" if locator[-1] != "0" else "1")
        self.assertIsNone(
            coadmin.verify_miniapp_invite_start_param(tampered, "fixture-token", invite_hash)
        )
        self.assertIsNone(
            coadmin.verify_miniapp_invite_start_param(locator, "other-bot-token", invite_hash)
        )
        self.assertIsNone(
            coadmin.verify_miniapp_invite_start_param(
                "i1_7_00000000000000000000000000000000", "fixture-token", invite_hash
            )
        )
        self.assertIsNone(coadmin.parse_miniapp_invite_start_param("7"))
        rotated_hash = hashlib.sha256(b"rotated-invite-code").hexdigest()
        self.assertIsNone(
            coadmin.verify_miniapp_invite_start_param(locator, "fixture-token", rotated_hash)
        )
        rotated_locator = coadmin.miniapp_invite_start_param(7, "fixture-token", rotated_hash)
        self.assertNotEqual(locator, rotated_locator)
        self.assertEqual(
            coadmin.verify_miniapp_invite_start_param(
                rotated_locator, "fixture-token", rotated_hash
            ), 7
        )

    def test_rotated_invite_invalidates_previous_miniapp_locator(self):
        old_hash = hashlib.sha256(CODE.encode()).hexdigest()
        old_locator = coadmin.miniapp_invite_start_param(7, "fixture-token", old_hash)
        _, old_tag = coadmin.parse_miniapp_invite_start_param(old_locator)
        new_code = "SyntheticRotatedInviteCode987654"
        new_hash = hashlib.sha256(new_code.encode()).hexdigest()
        self.db.execute("UPDATE invitations SET hash=? WHERE id=7", (new_hash,))
        old_result = self.submit(invite_id=7, invite_tag=old_tag)
        self.assertEqual(old_result["status"], "invalid")
        self.assertIsNone(
            self.db.execute("SELECT pending_uid FROM invitations WHERE id=7").fetchone()[0]
        )
        new_locator = coadmin.miniapp_invite_start_param(7, "fixture-token", new_hash)
        _, new_tag = coadmin.parse_miniapp_invite_start_param(new_locator)
        new_result = self.submit(invite_id=7, invite_tag=new_tag)
        self.assertEqual(new_result["status"], "pending_owner_approval")

    def test_miniapp_locator_for_unknown_invite_does_not_consume_anything(self):
        invite_hash = hashlib.sha256(CODE.encode()).hexdigest()
        locator = coadmin.miniapp_invite_start_param(999, "fixture-token", invite_hash)
        invite_id, invite_tag = coadmin.parse_miniapp_invite_start_param(locator)
        result = self.submit(invite_id=invite_id, invite_tag=invite_tag)
        self.assertEqual(result["status"], "invalid")
        self.assertIsNotNone(
            self.db.execute("SELECT hash FROM invitations WHERE id=7").fetchone()[0]
        )

    def test_link_stays_disabled_until_operator_confirms_exact_main_app_url(self):
        def configured(token, method, payload):
            return {"username": "BrowserVpsBot", "has_main_web_app": True}
        with patch.dict(coadmin.os.environ, {"BVP_TELEGRAM_MAIN_MINI_APP_URL": ""}):
            self.assertIsNone(coadmin.miniapp_invite_url(configured, "fixture-token", 7, CODE))

    def test_invalid_format_does_not_consume_invitation(self):
        result = self.submit(code="not valid")
        self.assertEqual(result["status"], "invalid_format")
        self.assertIsNotNone(
            self.db.execute("SELECT hash FROM invitations WHERE id=7").fetchone()[0]
        )


    def test_rotate_invite_builds_miniapp_link_from_new_code(self):
        rotated_code = "SyntheticRotatedInviteCode987654"
        link = "https://t.me/BrowserVpsBot?startapp=i1_7_fixture"
        with (
            patch.object(coadmin, "generate_invite_code", return_value=rotated_code),
            patch.object(coadmin, "miniapp_invite_url", return_value=link) as make_link,
            patch.object(coadmin, "send") as send,
            patch.object(coadmin, "audit"),
        ):
            coadmin.rotate_invite(
                "fixture-token", OWNER, self.request, 7, NOW
            )
        make_link.assert_called_once_with(
            self.request, "fixture-token", 7, rotated_code
        )
        sent_message = send.call_args.args[3]
        self.assertIn(link, sent_message)
        self.assertEqual(
            self.db.execute("SELECT hash FROM invitations WHERE id=7").fetchone()[0],
            hashlib.sha256(rotated_code.encode()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
