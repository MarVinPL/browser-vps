import copy
import unittest

from passkey_decision_ladder import evaluate


def valid_login():
    return {
        "operation": "login",
        "challenge": {"valid": True, "unused": True},
        "webauthn": {
            "rp_id_valid": True,
            "origin_valid": True,
            "signature_valid": True,
            "credential_id_valid": True,
            "user_handle_valid": True,
        },
        "credential": {"status": "active"},
        "revocation_registry": {
            "available": True,
            "integrity_verified": True,
            "reconciled": True,
        },
    }


def valid_registration():
    return {
        "operation": "registration",
        "challenge": {"valid": True, "unused": True},
        "webauthn": {
            "rp_id_valid": True,
            "origin_valid": True,
            "attestation_valid": True,
            "credential_id_unique": True,
            "account_binding_valid": True,
            "registration_allowed": True,
        },
        "revocation_registry": {
            "available": True,
            "integrity_verified": True,
            "reconciled": True,
        },
    }


class DecisionLadderTests(unittest.TestCase):
    def test_login_happy_path_is_only_advisory(self):
        result = evaluate(valid_login())
        self.assertEqual(result["decision"], "ALLOW_FOR_BACKEND_VALIDATION")
        self.assertTrue(result["backend_must_revalidate"])
        self.assertTrue(result["advisory_only"])

    def test_registration_happy_path_is_only_advisory(self):
        result = evaluate(valid_registration())
        self.assertEqual(result["decision"], "ALLOW_FOR_BACKEND_VALIDATION")
        self.assertTrue(result["backend_must_revalidate"])

    def test_non_object_is_unknown(self):
        self.assertEqual(evaluate(None)["decision"], "UNKNOWN")

    def test_unknown_operation_is_unknown(self):
        data = valid_login()
        data["operation"] = "unlock_everything"
        self.assertEqual(evaluate(data)["decision"], "UNKNOWN")

    def test_non_string_operation_is_unknown_without_exception(self):
        data = valid_login()
        data["operation"] = ["login"]
        self.assertEqual(evaluate(data)["decision"], "UNKNOWN")

    def test_missing_registry_blocks(self):
        data = valid_login()
        del data["revocation_registry"]
        self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_unavailable_registry_blocks(self):
        data = valid_login()
        data["revocation_registry"]["available"] = False
        self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_unverified_registry_integrity_blocks(self):
        data = valid_login()
        data["revocation_registry"]["integrity_verified"] = False
        self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_unreconciled_registry_blocks(self):
        data = valid_login()
        data["revocation_registry"]["reconciled"] = False
        self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_missing_reconciliation_field_blocks(self):
        data = valid_login()
        del data["revocation_registry"]["reconciled"]
        self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_backup_restore_needs_review(self):
        data = {
            "operation": "backup_restore",
            "revocation_registry": {
                "available": True,
                "integrity_verified": True,
                "reconciled": True,
            },
        }
        self.assertEqual(evaluate(data)["decision"], "NEEDS_REVIEW")

    def test_revocation_needs_backend_confirmation(self):
        data = {
            "operation": "revoke",
            "revocation_registry": {
                "available": True,
                "integrity_verified": True,
                "reconciled": True,
            },
        }
        self.assertEqual(evaluate(data)["decision"], "NEEDS_REVIEW")

    def test_missing_credential_status_needs_review(self):
        data = valid_login()
        data["credential"] = {}
        self.assertEqual(evaluate(data)["decision"], "NEEDS_REVIEW")

    def test_revoked_credential_blocks(self):
        data = valid_login()
        data["credential"]["status"] = "revoked"
        self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_unknown_credential_status_needs_review(self):
        data = valid_login()
        data["credential"]["status"] = "mystery"
        self.assertEqual(evaluate(data)["decision"], "NEEDS_REVIEW")

    def test_non_string_credential_status_needs_review_without_exception(self):
        data = valid_login()
        data["credential"]["status"] = ["active"]
        self.assertEqual(evaluate(data)["decision"], "NEEDS_REVIEW")

    def test_explicitly_invalid_challenge_blocks(self):
        data = valid_login()
        data["challenge"]["valid"] = False
        self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_missing_challenge_fact_needs_review(self):
        data = valid_login()
        del data["challenge"]["valid"]
        self.assertEqual(evaluate(data)["decision"], "NEEDS_REVIEW")

    def test_reused_challenge_blocks(self):
        data = valid_login()
        data["challenge"]["unused"] = False
        self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_each_failed_login_check_blocks(self):
        for field in (
            "rp_id_valid", "origin_valid", "signature_valid",
            "credential_id_valid", "user_handle_valid",
        ):
            with self.subTest(field=field):
                data = valid_login()
                data["webauthn"][field] = False
                self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_each_missing_login_check_needs_review(self):
        for field in (
            "rp_id_valid", "origin_valid", "signature_valid",
            "credential_id_valid", "user_handle_valid",
        ):
            with self.subTest(field=field):
                data = valid_login()
                del data["webauthn"][field]
                self.assertEqual(evaluate(data)["decision"], "NEEDS_REVIEW")

    def test_each_failed_registration_check_blocks(self):
        for field in (
            "rp_id_valid", "origin_valid", "attestation_valid",
            "credential_id_unique", "account_binding_valid", "registration_allowed",
        ):
            with self.subTest(field=field):
                data = valid_registration()
                data["webauthn"][field] = False
                self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_sensitive_private_key_field_is_rejected(self):
        data = valid_login()
        data["debug_private_key"] = "must-never-be-accepted"
        result = evaluate(data)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("FORBIDDEN_SENSITIVE_INPUT_FIELD", result["reason_codes"])

    def test_nested_secret_field_is_rejected(self):
        data = valid_login()
        data["webauthn"]["access_token"] = "x"
        result = evaluate(data)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("FORBIDDEN_SENSITIVE_INPUT_FIELD", result["reason_codes"])

    def test_unexpected_top_level_field_is_rejected(self):
        data = valid_login()
        data["metadata"] = {"note": "not part of the contract"}
        result = evaluate(data)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("UNEXPECTED_INPUT_FIELD", result["reason_codes"])

    def test_wrong_ceremony_fields_are_rejected(self):
        data = valid_login()
        data["webauthn"]["attestation_valid"] = True
        self.assertEqual(evaluate(data)["decision"], "BLOCK")

    def test_input_is_not_mutated(self):
        data = valid_login()
        before = copy.deepcopy(data)
        evaluate(data)
        self.assertEqual(data, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
