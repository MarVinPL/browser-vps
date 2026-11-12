"""Offline tests for Telegram Mini App initData HMAC verification."""
import hashlib
import hmac
import json
import unittest
from urllib.parse import urlencode

from src.telegram.webapp_init_data import (
    TelegramInitDataError,
    verify_telegram_webapp_init_data,
)


TOKEN = "123456:fixture-token-never-used-outside-tests"
NOW = 1_800_000_000


def make_init_data(*, user=None, auth_date=NOW, extra=None, token=TOKEN):
    fields = {
        "auth_date": str(auth_date),
        "user": json.dumps(user or {"id": 123456, "first_name": "Fixture"}),
    }
    fields.update(extra or {})
    check = "\n".join(f"{key}={value}" for key, value in sorted(fields.items()))
    secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    fields["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    return urlencode(fields)


class TelegramWebAppInitDataTests(unittest.TestCase):
    def verify(self, raw, **kwargs):
        return verify_telegram_webapp_init_data(raw, TOKEN, now=NOW, **kwargs)

    def test_valid_data_returns_only_signed_user_id_and_auth_date(self):
        result = self.verify(make_init_data())
        self.assertEqual(result.telegram_user_id, 123456)
        self.assertEqual(result.auth_date, NOW)
        self.assertEqual(set(result.__dataclass_fields__), {"telegram_user_id", "auth_date", "start_param"})
        self.assertIsNone(result.start_param)


    def test_signed_start_param_is_returned(self):
        raw = make_init_data(extra={"start_param": "invite_Abc123_-"})
        self.assertEqual(self.verify(raw).start_param, "invite_Abc123_-")

    def test_tampered_start_param_is_rejected(self):
        raw = make_init_data(extra={"start_param": "invite_Abc123"})
        raw = raw.replace("invite_Abc123", "invite_Xbc123")
        with self.assertRaises(TelegramInitDataError):
            self.verify(raw)

    def test_invalid_start_param_is_rejected(self):
        for value in ("", "contains.dot", "x" * 513):
            with self.subTest(value=value):
                raw = make_init_data(extra={"start_param": value})
                with self.assertRaises(TelegramInitDataError):
                    self.verify(raw)

    def test_tampered_user_is_rejected(self):
        raw = make_init_data().replace("123456", "654321")
        with self.assertRaises(TelegramInitDataError):
            self.verify(raw)

    def test_wrong_bot_token_is_rejected(self):
        with self.assertRaises(TelegramInitDataError):
            verify_telegram_webapp_init_data(
                make_init_data(), "123456:other-token", now=NOW
            )

    def test_expired_auth_date_is_rejected(self):
        with self.assertRaises(TelegramInitDataError):
            self.verify(make_init_data(auth_date=NOW - 301))

    def test_future_auth_date_outside_skew_is_rejected(self):
        with self.assertRaises(TelegramInitDataError):
            self.verify(make_init_data(auth_date=NOW + 31))

    def test_future_auth_date_within_skew_is_accepted(self):
        self.assertEqual(
            self.verify(make_init_data(auth_date=NOW + 30)).telegram_user_id,
            123456,
        )

    def test_duplicate_query_parameter_is_rejected(self):
        raw = make_init_data() + "&auth_date=" + str(NOW)
        with self.assertRaises(TelegramInitDataError):
            self.verify(raw)

    def test_missing_required_field_is_rejected(self):
        raw = urlencode({"user": json.dumps({"id": 123456}), "hash": "0" * 64})
        with self.assertRaises(TelegramInitDataError):
            self.verify(raw)

    def test_malformed_query_is_rejected(self):
        with self.assertRaises(TelegramInitDataError):
            self.verify("auth_date")

    def test_invalid_hash_format_is_rejected(self):
        raw = make_init_data().replace("hash=", "hash=XYZ")
        with self.assertRaises(TelegramInitDataError):
            self.verify(raw)

    def test_boolean_user_id_is_rejected(self):
        with self.assertRaises(TelegramInitDataError):
            self.verify(make_init_data(user={"id": True}))

    def test_non_positive_user_id_is_rejected(self):
        for user_id in (0, -1):
            with self.subTest(user_id=user_id):
                with self.assertRaises(TelegramInitDataError):
                    self.verify(make_init_data(user={"id": user_id}))

    def test_duplicate_json_user_key_is_rejected(self):
        user = '{"id":123456,"id":654321}'
        raw = make_init_data()
        fields = {
            "auth_date": str(NOW),
            "user": user,
        }
        check = "\n".join(f"{key}={value}" for key, value in sorted(fields.items()))
        secret = hmac.new(b"WebAppData", TOKEN.encode(), hashlib.sha256).digest()
        fields["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        with self.assertRaises(TelegramInitDataError):
            self.verify(urlencode(fields))

    def test_oversized_payload_is_rejected(self):
        with self.assertRaises(TelegramInitDataError):
            self.verify("x" * 16_385)

    def test_invalid_clock_and_policy_values_are_rejected(self):
        for kwargs in (
            {"now": True},
            {"max_age_seconds": 0},
            {"max_age_seconds": 601},
            {"future_skew_seconds": -1},
            {"future_skew_seconds": 61},
        ):
            with self.subTest(kwargs=kwargs):
                params = {"now": NOW}
                params.update(kwargs)
                with self.assertRaises(TelegramInitDataError):
                    verify_telegram_webapp_init_data(
                        make_init_data(), TOKEN, **params
                    )


if __name__ == "__main__":
    unittest.main()
