"""Offline-verifiable Telegram Mini App initData authentication primitive.

Verifies Telegram's HMAC signature using a server-held bot token. It does not
create sessions, consume invite challenges, grant roles, or call Telegram.
Callers must bind the returned principal to a server-side invite and one-use
challenge before any authorization decision.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from urllib.parse import parse_qsl


class TelegramInitDataError(ValueError):
    """Generic failure; never include initData or the bot token in the message."""


@dataclass(frozen=True)
class TelegramWebAppIdentity:
    telegram_user_id: int
    auth_date: int
    start_param: str | None = None


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError("invalid JSON constant")


def verify_telegram_webapp_init_data(
    raw_init_data: str,
    bot_token: str,
    *,
    now: int,
    max_age_seconds: int = 300,
    future_skew_seconds: int = 30,
) -> TelegramWebAppIdentity:
    """Verify raw Telegram.WebApp.initData and return the signed user ID and optional signed start_param.

    The bot token must come from a server-side secret store, never a request.
    The injected Unix timestamp makes freshness checks deterministic.
    """
    if (
        not isinstance(raw_init_data, str)
        or not raw_init_data
        or len(raw_init_data) > 16_384
        or not isinstance(bot_token, str)
        or not bot_token
        or type(now) is not int
        or now < 0
        or type(max_age_seconds) is not int
        or not 1 <= max_age_seconds <= 600
        or type(future_skew_seconds) is not int
        or not 0 <= future_skew_seconds <= 60
    ):
        raise TelegramInitDataError()

    try:
        fields = parse_qsl(
            raw_init_data,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=32,
            encoding="utf-8",
            errors="strict",
        )
        values: dict[str, str] = {}
        for key, value in fields:
            if not key or key in values:
                raise ValueError("duplicate or empty field")
            values[key] = value

        supplied_hash = values.pop("hash")
        auth_date_text = values["auth_date"]
        user_text = values["user"]
        start_param = values.get("start_param")
        if start_param is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", start_param):
            raise ValueError("invalid start_param")
        if not re.fullmatch(r"[0-9a-f]{64}", supplied_hash):
            raise ValueError("invalid hash")
        if not re.fullmatch(r"[0-9]{1,12}", auth_date_text):
            raise ValueError("invalid auth_date")

        auth_date = int(auth_date_text)
        if auth_date > now + future_skew_seconds:
            raise ValueError("future auth_date")
        if now - auth_date > max_age_seconds:
            raise ValueError("expired auth_date")

        data_check_string = "\n".join(
            f"{key}={value}" for key, value in sorted(values.items())
        )
        secret_key = hmac.new(
            b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256
        ).digest()
        expected_hash = hmac.new(
            secret_key, data_check_string.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_hash, supplied_hash):
            raise ValueError("signature mismatch")

        user = json.loads(
            user_text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(user, dict):
            raise ValueError("invalid user")
        user_id = user.get("id")
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("invalid user id")

        return TelegramWebAppIdentity(
            telegram_user_id=user_id,
            auth_date=auth_date,
            start_param=start_param,
        )
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        raise TelegramInitDataError() from None
