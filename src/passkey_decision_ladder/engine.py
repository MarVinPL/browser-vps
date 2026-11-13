"""Deterministic advisory decision ladder for Passkey workflows.

This module consumes *results* produced by a trusted WebAuthn backend. It does
not parse authenticator responses, verify signatures/attestation, authenticate
users, grant permissions, or replace the backend's final validation.
"""
from __future__ import annotations

from typing import Any

_ALLOWED_OPERATIONS = {"login", "registration", "backup_restore", "revoke"}
_LOGIN_CHECKS = (
    "rp_id_valid",
    "origin_valid",
    "signature_valid",
    "credential_id_valid",
    "user_handle_valid",
)
_REGISTRATION_CHECKS = (
    "rp_id_valid",
    "origin_valid",
    "attestation_valid",
    "credential_id_unique",
    "account_binding_valid",
    "registration_allowed",
)
_FORBIDDEN_KEY_PARTS = (
    "private_key",
    "privatekey",
    "raw_private",
    "secret",
    "password",
    "token",
    "biometric",
)


def _contains_forbidden_material(value: Any) -> bool:
    """Reject input objects with field names reserved for sensitive material."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(part in normalized for part in _FORBIDDEN_KEY_PARTS):
                return True
            if _contains_forbidden_material(child):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_forbidden_material(item) for item in value)
    return False


def _result(decision: str, *reasons: str) -> dict[str, Any]:
    return {
        "decision": decision,
        "reason_codes": list(dict.fromkeys(reasons)),
        "requires_human_review": decision in {"NEEDS_REVIEW", "UNKNOWN"},
        "backend_must_revalidate": decision == "ALLOW_FOR_BACKEND_VALIDATION",
        "advisory_only": True,
    }


def _check_registry(payload: dict[str, Any]) -> dict[str, Any] | None:
    registry = payload.get("revocation_registry")
    if not isinstance(registry, dict):
        return _result("BLOCK", "REVOCATION_REGISTRY_MISSING")
    for field, reason in (
        ("available", "REVOCATION_REGISTRY_UNAVAILABLE"),
        ("integrity_verified", "REVOCATION_REGISTRY_INTEGRITY_UNVERIFIED"),
        ("reconciled", "REVOCATION_REGISTRY_NOT_RECONCILED"),
    ):
        if registry.get(field) is not True:
            return _result("BLOCK", reason)
    return None


def _check_challenge(payload: dict[str, Any]) -> dict[str, Any] | None:
    challenge = payload.get("challenge")
    if not isinstance(challenge, dict):
        return _result("NEEDS_REVIEW", "CHALLENGE_DATA_MISSING")
    for field, blocked_reason, unknown_reason in (
        ("valid", "CHALLENGE_INVALID", "CHALLENGE_VALIDITY_UNKNOWN"),
        ("unused", "CHALLENGE_REUSED", "CHALLENGE_USAGE_UNKNOWN"),
    ):
        value = challenge.get(field)
        if value is False:
            return _result("BLOCK", blocked_reason)
        if value is not True:
            return _result("NEEDS_REVIEW", unknown_reason)
    return None


def _check_boolean_results(
    payload: dict[str, Any], fields: tuple[str, ...], prefix: str
) -> dict[str, Any] | None:
    results = payload.get("webauthn")
    if not isinstance(results, dict):
        return _result("NEEDS_REVIEW", "WEBAUTHN_RESULTS_MISSING")
    for field in fields:
        value = results.get(field)
        if value is False:
            return _result("BLOCK", f"{prefix}_{field.upper()}_FAILED")
        if value is not True:
            return _result("NEEDS_REVIEW", f"{prefix}_{field.upper()}_UNKNOWN")
    return None


def evaluate(payload: Any) -> dict[str, Any]:
    """Evaluate backend-produced facts and return an advisory outcome.

    Missing/ambiguous facts never result in an allow outcome. The sole positive
    outcome is ALLOW_FOR_BACKEND_VALIDATION; the application backend must still
    independently validate the complete WebAuthn ceremony and authorize access.
    """
    if not isinstance(payload, dict):
        return _result("UNKNOWN", "INPUT_NOT_OBJECT")
    if _contains_forbidden_material(payload):
        return _result("BLOCK", "FORBIDDEN_SENSITIVE_INPUT_FIELD")

    operation = payload.get("operation")
    if not isinstance(operation, str) or operation not in _ALLOWED_OPERATIONS:
        return _result("UNKNOWN", "UNSUPPORTED_OR_MISSING_OPERATION")

    registry_error = _check_registry(payload)
    if registry_error is not None:
        return registry_error

    if operation == "backup_restore":
        return _result("NEEDS_REVIEW", "BACKUP_RESTORE_REQUIRES_POST_RESTORE_REVIEW")
    if operation == "revoke":
        return _result("NEEDS_REVIEW", "REVOCATION_REQUIRES_BACKEND_CONFIRMATION")

    challenge_error = _check_challenge(payload)
    if challenge_error is not None:
        return challenge_error

    if operation == "login":
        credential = payload.get("credential")
        if not isinstance(credential, dict) or "status" not in credential:
            return _result("NEEDS_REVIEW", "CREDENTIAL_STATUS_MISSING")
        status = credential.get("status")
        if isinstance(status, str) and status in {"revoked", "suspended", "disabled"}:
            return _result("BLOCK", "CREDENTIAL_NOT_ACTIVE")
        if status != "active":
            return _result("NEEDS_REVIEW", "CREDENTIAL_STATUS_UNKNOWN")
        checks_error = _check_boolean_results(payload, _LOGIN_CHECKS, "WEBAUTHN")
        if checks_error is not None:
            return checks_error
    elif operation == "registration":
        checks_error = _check_boolean_results(
            payload, _REGISTRATION_CHECKS, "WEBAUTHN_REGISTRATION"
        )
        if checks_error is not None:
            return checks_error

    return _result(
        "ALLOW_FOR_BACKEND_VALIDATION",
        "PRECHECKS_PASSED_BACKEND_REVALIDATION_REQUIRED",
    )
