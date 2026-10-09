"""Environment composition for HMAC and Ed25519 enforcement receipts."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from safeharness.backends.asymmetric_receipts import (
    AsymmetricEnforcementReceiptIssuer,
    AsymmetricEnforcementReceiptVerifier,
    Ed25519ReceiptSigner,
    Ed25519ReceiptVerifier,
)
from safeharness.backends.receipts import SignedEnforcementReceiptAuthority
from safeharness.ports import (
    EnforcementReceiptIssuer,
    EnforcementReceiptReplayStore,
    EnforcementReceiptVerifier,
)


_MODE = "SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE"
_HMAC_KEY = "SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY"
_KEY_ID = "SAFEHARNESS_ENFORCEMENT_RECEIPT_KEY_ID"
_PRIVATE_KEY_FILE = "SAFEHARNESS_ENFORCEMENT_RECEIPT_PRIVATE_KEY_FILE"
_PUBLIC_KEY_FILE = "SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILE"
_PUBLIC_KEY_FILES = "SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILES"
_ISSUER = "SAFEHARNESS_ENFORCEMENT_RECEIPT_ISSUER"
_DEFAULT_ISSUER = "safeharness-control-plane"
_MAX_PUBLIC_KEY_CONFIGURATION = 16 * 1024
_MAX_VERIFICATION_KEYS = 32


def build_enforcement_receipt_issuer_from_environment(
    environ: Mapping[str, str] | None = None,
) -> EnforcementReceiptIssuer | None:
    """Build the Agent-side issuer without loading gateway public-key settings."""

    values = os.environ if environ is None else environ
    mode = _receipt_mode(values)
    issuer = _value(values, _ISSUER) or _DEFAULT_ISSUER
    if mode == "hmac":
        _reject_set(values, (_PRIVATE_KEY_FILE,), expected_mode="ed25519")
        key = _value(values, _HMAC_KEY)
        return SignedEnforcementReceiptAuthority(key, issuer=issuer) if key else None
    if mode == "ed25519":
        _reject_set(values, (_HMAC_KEY,), expected_mode="hmac")
        key_id = _required(values, _KEY_ID, mode=mode)
        private_key_file = _required(values, _PRIVATE_KEY_FILE, mode=mode)
        try:
            signer = Ed25519ReceiptSigner.from_private_key_file(
                private_key_file,
                key_id=key_id,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("the Ed25519 receipt private key could not be loaded") from exc
        return AsymmetricEnforcementReceiptIssuer(signer, issuer=issuer)
    raise ValueError(
        f"{_MODE}='kms' requires a provider-specific ExternalEnforcementReceiptSigner"
    )


def build_enforcement_receipt_verifier_from_environment(
    *,
    replay_store: EnforcementReceiptReplayStore | None = None,
    environ: Mapping[str, str] | None = None,
) -> EnforcementReceiptVerifier | None:
    """Build a gateway verifier and reject any Ed25519 private-key configuration."""

    values = os.environ if environ is None else environ
    mode = _receipt_mode(values)
    issuer = _value(values, _ISSUER) or _DEFAULT_ISSUER
    if mode == "hmac":
        _reject_set(
            values,
            (_PRIVATE_KEY_FILE, _PUBLIC_KEY_FILE, _PUBLIC_KEY_FILES),
            expected_mode="ed25519",
        )
        key = _value(values, _HMAC_KEY)
        return (
            SignedEnforcementReceiptAuthority(
                key,
                issuer=issuer,
                replay_store=replay_store,
            )
            if key
            else None
        )
    if mode == "ed25519":
        _reject_set(values, (_HMAC_KEY,), expected_mode="hmac")
        if _value(values, _PRIVATE_KEY_FILE):
            raise ValueError("the Tool Security Gateway must not receive a receipt private key")
        public_key_files = _public_key_files(values)
        verifiers = []
        try:
            for key_id, path in public_key_files.items():
                verifiers.append(
                    Ed25519ReceiptVerifier.from_public_key_file(path, key_id=key_id)
                )
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("an Ed25519 receipt public key could not be loaded") from exc
        return AsymmetricEnforcementReceiptVerifier(
            verifiers,
            issuer=issuer,
            replay_store=replay_store,
        )
    raise ValueError(
        f"{_MODE}='kms' configures signing in code; the gateway still needs a public-key verifier"
    )


def _receipt_mode(values: Mapping[str, str]) -> str:
    mode = (_value(values, _MODE) or "hmac").lower()
    if mode not in {"hmac", "ed25519", "kms"}:
        raise ValueError(f"{_MODE} must be 'hmac', 'ed25519', or 'kms'")
    return mode


def _public_key_files(values: Mapping[str, str]) -> Mapping[str, str]:
    encoded = _value(values, _PUBLIC_KEY_FILES)
    single_path = _value(values, _PUBLIC_KEY_FILE)
    key_id = _value(values, _KEY_ID)
    if encoded and (single_path or key_id):
        raise ValueError(
            f"{_PUBLIC_KEY_FILES} cannot be combined with {_PUBLIC_KEY_FILE} or {_KEY_ID}"
        )
    if encoded:
        if len(encoded) > _MAX_PUBLIC_KEY_CONFIGURATION:
            raise ValueError(f"{_PUBLIC_KEY_FILES} exceeds the size limit")
        try:
            decoded: Any = json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{_PUBLIC_KEY_FILES} must be a JSON object") from exc
        if not isinstance(decoded, dict) or not decoded:
            raise ValueError(f"{_PUBLIC_KEY_FILES} must be a non-empty JSON object")
        if len(decoded) > _MAX_VERIFICATION_KEYS:
            raise ValueError(f"{_PUBLIC_KEY_FILES} contains too many verification keys")
        if any(
            not isinstance(item_key, str)
            or not item_key.strip()
            or not isinstance(item_path, str)
            or not item_path.strip()
            for item_key, item_path in decoded.items()
        ):
            raise ValueError(f"{_PUBLIC_KEY_FILES} must map key IDs to file paths")
        return {item_key.strip(): item_path.strip() for item_key, item_path in decoded.items()}
    if not single_path or not key_id:
        raise ValueError(
            f"ed25519 mode requires {_PUBLIC_KEY_FILE} and {_KEY_ID}, or {_PUBLIC_KEY_FILES}"
        )
    return {key_id: single_path}


def _reject_set(
    values: Mapping[str, str],
    names: tuple[str, ...],
    *,
    expected_mode: str,
) -> None:
    configured = next((name for name in names if _value(values, name)), None)
    if configured is not None:
        raise ValueError(f"{configured} requires {_MODE}={expected_mode}")


def _required(values: Mapping[str, str], name: str, *, mode: str) -> str:
    value = _value(values, name)
    if not value:
        raise ValueError(f"{name} is required when {_MODE}={mode}")
    return value


def _value(values: Mapping[str, str], name: str) -> str:
    raw = values.get(name, "")
    if not isinstance(raw, str):
        raise TypeError(f"{name} must be a string")
    return raw.strip()
