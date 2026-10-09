"""Asymmetric enforcement receipts with verification-only gateway keys."""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from safeharness.api.context import SessionContext
from safeharness.api.tools import ToolDescriptor, ToolInvocation
from safeharness.backends.receipts import (
    _AUDIENCE,
    EnforcementReceiptClaims,
    InMemoryEnforcementReceiptReplayStore,
    _b64decode,
    _b64encode,
    _build_receipt_claims,
    _canonical_json,
    _invalid,
    _utc_now,
    _verify_receipt_claims,
)
from safeharness.ports import (
    EnforcementReceiptReplayStore,
    EnforcementReceiptSignatureSigner,
    EnforcementReceiptSignatureVerifier,
    EnforcementReceiptVerification,
)


_PREFIX = "shr2"
_TYPE = "safeharness-enforcement-receipt"
_HEADER_KEYS = frozenset({"v", "typ", "alg", "kid"})
_ALGORITHM_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
_KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_MAX_TOKEN_LENGTH = 64 * 1024
_MAX_SIGNATURE_LENGTH = 16 * 1024

SignatureResult = bytes | bytearray | memoryview
SignatureCallback = Callable[
    [bytes],
    SignatureResult | Awaitable[SignatureResult],
]


class ExternalEnforcementReceiptSigner:
    """Adapt an async or synchronous KMS/HSM signing callback.

    The callback receives the exact signed-envelope bytes. Provider-specific
    hashing, algorithm selection, authentication, and retry policy stay outside
    SafeHarness. The configured algorithm and key ID are signed into the token.
    """

    def __init__(
        self,
        *,
        algorithm: str,
        key_id: str,
        sign: SignatureCallback,
    ) -> None:
        _validate_signing_identity(algorithm, key_id)
        if not callable(sign):
            raise TypeError("sign must be callable")
        self.algorithm = algorithm
        self.key_id = key_id
        self._sign = sign

    async def sign(self, message: bytes) -> bytes:
        if not isinstance(message, bytes) or not message:
            raise ValueError("receipt signing input must be non-empty bytes")
        result = self._sign(message)
        if inspect.isawaitable(result):
            result = await result
        return _signature_bytes(result)


class Ed25519ReceiptSigner:
    """Local Ed25519 private-key signer for control-plane deployments."""

    algorithm = "EdDSA"

    def __init__(self, private_key: Any, *, key_id: str) -> None:
        _, _, private_key_type, _ = _ed25519_dependencies()
        _validate_signing_identity(self.algorithm, key_id)
        if not isinstance(private_key, private_key_type):
            raise TypeError("private_key must be an Ed25519 private key")
        self.key_id = key_id
        self._private_key = private_key

    @classmethod
    def from_private_key_pem(
        cls,
        pem: bytes | str,
        *,
        key_id: str,
        password: bytes | None = None,
    ) -> "Ed25519ReceiptSigner":
        serialization, _, _, _ = _ed25519_dependencies()
        private_key = serialization.load_pem_private_key(
            _pem_bytes(pem),
            password=password,
        )
        return cls(private_key, key_id=key_id)

    @classmethod
    def from_private_key_file(
        cls,
        path: str | Path,
        *,
        key_id: str,
        password: bytes | None = None,
    ) -> "Ed25519ReceiptSigner":
        return cls.from_private_key_pem(
            Path(path).read_bytes(),
            key_id=key_id,
            password=password,
        )

    async def sign(self, message: bytes) -> bytes:
        if not isinstance(message, bytes) or not message:
            raise ValueError("receipt signing input must be non-empty bytes")
        return _signature_bytes(self._private_key.sign(message))


class Ed25519ReceiptVerifier:
    """Ed25519 public-key verifier suitable for a Tool Security Gateway."""

    algorithm = "EdDSA"

    def __init__(self, public_key: Any, *, key_id: str) -> None:
        _, _, _, public_key_type = _ed25519_dependencies()
        _validate_signing_identity(self.algorithm, key_id)
        if not isinstance(public_key, public_key_type):
            raise TypeError("public_key must be an Ed25519 public key")
        self.key_id = key_id
        self._public_key = public_key

    @classmethod
    def from_public_key_pem(
        cls,
        pem: bytes | str,
        *,
        key_id: str,
    ) -> "Ed25519ReceiptVerifier":
        serialization, _, _, _ = _ed25519_dependencies()
        public_key = serialization.load_pem_public_key(_pem_bytes(pem))
        return cls(public_key, key_id=key_id)

    @classmethod
    def from_public_key_file(
        cls,
        path: str | Path,
        *,
        key_id: str,
    ) -> "Ed25519ReceiptVerifier":
        return cls.from_public_key_pem(Path(path).read_bytes(), key_id=key_id)

    async def verify(self, message: bytes, signature: bytes) -> bool:
        _, invalid_signature, _, _ = _ed25519_dependencies()
        if not isinstance(message, bytes) or not message:
            return False
        try:
            self._public_key.verify(_signature_bytes(signature), message)
        except (invalid_signature, ValueError):
            return False
        return True


class AsymmetricEnforcementReceiptIssuer:
    """Issue ``shr2`` receipts without exposing verification as signing."""

    def __init__(
        self,
        signer: EnforcementReceiptSignatureSigner,
        *,
        issuer: str = "safeharness-control-plane",
        audience: str = _AUDIENCE,
        default_ttl: timedelta = timedelta(minutes=2),
        max_ttl: timedelta = timedelta(minutes=5),
        now: Callable[[], datetime] | None = None,
    ) -> None:
        algorithm = getattr(signer, "algorithm", None)
        key_id = getattr(signer, "key_id", None)
        _validate_authority_configuration(
            issuer=issuer,
            audience=audience,
            default_ttl=default_ttl,
            max_ttl=max_ttl,
        )
        _validate_signing_identity(algorithm, key_id)
        if not callable(getattr(signer, "sign", None)):
            raise TypeError("signer must implement the receipt signature signer port")
        self.signer = signer
        self.issuer = issuer
        self.audience = audience
        self._default_ttl = default_ttl
        self._max_ttl = max_ttl
        self._now = now or _utc_now

    async def issue(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
        *,
        decision_id: str,
        event_id: str,
        policy_version: str,
        expires_at: datetime | None = None,
        workload_id: str = "",
    ) -> str:
        claims = _build_receipt_claims(
            context,
            descriptor,
            invocation,
            issuer=self.issuer,
            audience=self.audience,
            decision_id=decision_id,
            event_id=event_id,
            policy_version=policy_version,
            expires_at=expires_at,
            workload_id=workload_id,
            default_ttl=self._default_ttl,
            max_ttl=self._max_ttl,
            now=self._now(),
        )
        header = {
            "v": 2,
            "typ": _TYPE,
            "alg": self.signer.algorithm,
            "kid": self.signer.key_id,
        }
        encoded_header = _b64encode(_canonical_json(header))
        encoded_claims = _b64encode(_canonical_json(claims.to_claims()))
        message = f"{_PREFIX}.{encoded_header}.{encoded_claims}".encode("ascii")
        signature = _signature_bytes(await self.signer.sign(message))
        token = f"{message.decode('ascii')}.{_b64encode(signature)}"
        if len(token) > _MAX_TOKEN_LENGTH:
            raise ValueError("signed enforcement receipt exceeds the size limit")
        return token


class AsymmetricEnforcementReceiptVerifier:
    """Verify ``shr2`` receipts using a rotation set of public keys."""

    def __init__(
        self,
        verifiers: Iterable[EnforcementReceiptSignatureVerifier],
        *,
        issuer: str = "safeharness-control-plane",
        audience: str = _AUDIENCE,
        replay_store: EnforcementReceiptReplayStore | None = None,
        default_ttl: timedelta = timedelta(minutes=2),
        max_ttl: timedelta = timedelta(minutes=5),
        now: Callable[[], datetime] | None = None,
    ) -> None:
        _validate_authority_configuration(
            issuer=issuer,
            audience=audience,
            default_ttl=default_ttl,
            max_ttl=max_ttl,
        )
        verifier_by_key_id: dict[str, EnforcementReceiptSignatureVerifier] = {}
        for verifier in verifiers:
            algorithm = getattr(verifier, "algorithm", None)
            key_id = getattr(verifier, "key_id", None)
            _validate_signing_identity(algorithm, key_id)
            if not callable(getattr(verifier, "verify", None)):
                raise TypeError("verifier must implement the receipt signature verifier port")
            if key_id in verifier_by_key_id:
                raise ValueError("receipt verification key IDs must be unique")
            verifier_by_key_id[key_id] = verifier
        if not verifier_by_key_id:
            raise ValueError("at least one receipt verification key is required")
        self._verifiers = verifier_by_key_id
        self.issuer = issuer
        self.audience = audience
        self._max_ttl = max_ttl
        self._now = now or _utc_now
        self._replay_store = replay_store or InMemoryEnforcementReceiptReplayStore(
            now=self._now
        )

    async def verify(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
        receipt: str | None,
        *,
        consume: bool = False,
        expected_decision_id: str | None = None,
        expected_event_id: str | None = None,
        expected_policy_version: str | None = None,
        workload_id: str | None = None,
    ) -> EnforcementReceiptVerification:
        if not receipt:
            return _invalid("enforcement_receipt_missing", "An enforcement receipt is required.")
        if not isinstance(receipt, str) or len(receipt) > _MAX_TOKEN_LENGTH:
            return _invalid("enforcement_receipt_invalid", "The enforcement receipt is invalid.")
        try:
            prefix, encoded_header, encoded_claims, encoded_signature = receipt.split(".")
            if prefix != _PREFIX:
                raise ValueError("unsupported enforcement receipt version")
            header = _decode_header(encoded_header)
            verifier = self._verifiers.get(header["kid"])
            if verifier is None or verifier.algorithm != header["alg"]:
                raise ValueError("unknown enforcement receipt verification key")
            signature = _signature_bytes(_b64decode(encoded_signature))
            message = f"{prefix}.{encoded_header}.{encoded_claims}".encode("ascii")
        except (KeyError, TypeError, UnicodeError, ValueError):
            return _invalid("enforcement_receipt_invalid", "The enforcement receipt is invalid.")

        if not await verifier.verify(message, signature):
            return _invalid("enforcement_receipt_invalid", "The enforcement receipt is invalid.")
        try:
            decoded_claims = json.loads(_b64decode(encoded_claims).decode("utf-8"))
            if not isinstance(decoded_claims, dict):
                raise ValueError("unexpected enforcement receipt claims")
            if _b64encode(_canonical_json(decoded_claims)) != encoded_claims:
                raise ValueError("non-canonical enforcement receipt claims")
            claims = EnforcementReceiptClaims.from_claims(decoded_claims)
        except (OverflowError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
            return _invalid("enforcement_receipt_invalid", "The enforcement receipt is invalid.")
        return await _verify_receipt_claims(
            claims,
            context,
            descriptor,
            invocation,
            issuer=self.issuer,
            audience=self.audience,
            replay_store=self._replay_store,
            max_ttl=self._max_ttl,
            now=self._now(),
            consume=consume,
            expected_decision_id=expected_decision_id,
            expected_event_id=expected_event_id,
            expected_policy_version=expected_policy_version,
            workload_id=workload_id,
        )

    async def inspect(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
        receipt: str | None,
        **kwargs: Any,
    ) -> EnforcementReceiptVerification:
        return await self.verify(
            context,
            descriptor,
            invocation,
            receipt,
            consume=False,
            **kwargs,
        )

    def fingerprint(self, receipt: str) -> str:
        return hashlib.sha256(receipt.encode("utf-8")).hexdigest()


def _decode_header(encoded_header: str) -> Mapping[str, Any]:
    header = json.loads(_b64decode(encoded_header).decode("utf-8"))
    if not isinstance(header, dict) or set(header) != _HEADER_KEYS:
        raise ValueError("unexpected enforcement receipt header")
    if header.get("v") != 2 or header.get("typ") != _TYPE:
        raise ValueError("unsupported enforcement receipt header")
    _validate_signing_identity(header.get("alg"), header.get("kid"))
    if _b64encode(_canonical_json(header)) != encoded_header:
        raise ValueError("non-canonical enforcement receipt header")
    return header


def _validate_authority_configuration(
    *,
    issuer: str,
    audience: str,
    default_ttl: timedelta,
    max_ttl: timedelta,
) -> None:
    if not issuer or audience != _AUDIENCE:
        raise ValueError("issuer must be non-empty and audience must be the gateway")
    if default_ttl <= timedelta(0) or max_ttl <= timedelta(0) or default_ttl > max_ttl:
        raise ValueError("receipt TTLs must be positive and ordered")


def _validate_signing_identity(algorithm: Any, key_id: Any) -> None:
    if not isinstance(algorithm, str) or _ALGORITHM_PATTERN.fullmatch(algorithm) is None:
        raise ValueError("receipt signature algorithm is invalid")
    if not isinstance(key_id, str) or _KEY_ID_PATTERN.fullmatch(key_id) is None:
        raise ValueError("receipt signature key ID is invalid")


def _signature_bytes(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("receipt signature must be bytes")
    signature = bytes(value)
    if not signature or len(signature) > _MAX_SIGNATURE_LENGTH:
        raise ValueError("receipt signature length is invalid")
    return signature


def _pem_bytes(value: bytes | str) -> bytes:
    if isinstance(value, str):
        value = value.encode("ascii")
    if not isinstance(value, bytes) or not value:
        raise ValueError("PEM key material must be non-empty bytes or ASCII text")
    return value


def _ed25519_dependencies() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography import exceptions
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Ed25519 receipts require cryptography; install safeharness[production]"
        ) from exc
    return serialization, exceptions.InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey
