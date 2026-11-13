# Passkey decision ladder (advisory)

## Security boundary

This module is a deterministic **pre-check**, not an authenticator or an
authorization engine. It accepts only structured results produced by the
trusted WebAuthn backend. It does not accept raw authenticator responses,
credential material, private keys, passwords, tokens, or biometric data. It
does not perform cryptographic signature or attestation verification.

`ALLOW_FOR_BACKEND_VALIDATION` means only that the declared preconditions were
reported as successful. The application backend MUST independently validate
the complete WebAuthn ceremony, bind it to the correct account and session,
and make the final authentication/authorization decision.

## Operations

- `login`: requires an active credential, a valid unused challenge, a healthy
  revocation registry, and backend-confirmed RP ID, origin, signature,
  credential ID, and userHandle checks.
- `registration`: requires a valid unused challenge, a healthy revocation
  registry, and backend-confirmed RP ID, origin, attestation, credential ID
  uniqueness, userHandle, and registration eligibility checks.
- `backup_restore`: always returns `NEEDS_REVIEW`; restoration is not a signal
  that revocation state is trustworthy. A separate verified reconciliation
  workflow is required before any dependent operation can proceed.
- `revoke`: returns `NEEDS_REVIEW`; the backend must confirm durable revocation
  and update its authoritative state.

## Revocation registry

For login and registration, all three facts must be exactly `true`:

- `available`: registry can be read;
- `integrity_verified`: integrity checks passed;
- `reconciled`: state is reconciled with the authoritative revocation history.

Missing, false, or unknown registry facts return `BLOCK` (fail-closed).

## Outcomes

| Outcome | Meaning |
| --- | --- |
| `ALLOW_FOR_BACKEND_VALIDATION` | Pre-checks passed; backend revalidation remains mandatory |
| `BLOCK` | A required security condition failed or the revocation registry is unsafe |
| `NEEDS_REVIEW` | Required evidence is missing/ambiguous or an operation needs a separate workflow |
| `UNKNOWN` | Input or operation cannot be classified |

Missing/ambiguous challenge, credential, or WebAuthn facts never produce an
allow outcome. The engine returns stable reason codes for audit and tests.

## Run tests

From the repository root:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The module uses only the Python standard library. No production integration,
service installation, database access, or deployment is included in this issue.
