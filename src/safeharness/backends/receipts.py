"""Signed control-plane enforcement receipts.

The receipt is an authorization proof produced by a policy control plane and
consumed by the independent tool gateway.  It is intentionally bound to the
already-canonicalized invocation digest; the receipt itself is not part of
that digest, which avoids a signing cycle and prevents token substitution.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from safeharness.api.context import SessionContext
from safeharness.api.tools import ToolDescriptor, ToolInvocation
from safeharness.backends.gateway import invocation_digest
from safeharness.ports import (
    EnforcementReceiptReplayStore,
    EnforcementReceiptVerification,
)


_PREFIX = "shr1"
_AUDIENCE = "safeharness-tool-gateway"
_REQUIRED_CLAIMS = frozenset(
    {
        "v",
        "aud",
        "iss",
        "jti",
        "iat",
        "exp",
        "tenant_id",
        "agent_id",
        "session_id",
        "run_id",
        "tool_name",
        "tool_version",
        "tool_integrity_digest",
        "invocation_digest",
        "intent_digest",
        "policy_version",
        "decision_id",
        "event_id",
        "disposition",
        "workload_id",
    }
)


@dataclass(frozen=True, slots=True)
class EnforcementReceiptClaims:
    """Non-sensitive claims carried by a signed enforcement receipt."""

    audience: str
    issuer: str
    receipt_id: str
    tenant_id: str
    agent_id: str
    session_id: str
    run_id: str
    tool_name: str
    tool_version: str
    tool_integrity_digest: str
    invocation_digest: str
    intent_digest: str
    policy_version: str
    decision_id: str
    event_id: str
    issued_at: datetime
    expires_at: datetime
    disposition: str = "allow"
    workload_id: str = ""

    def __post_init__(self) -> None:
        if self.audience != _AUDIENCE:
            raise ValueError("unsupported enforcement receipt audience")
        if self.disposition != "allow":
            raise ValueError("only allow enforcement receipts are accepted")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("receipt timestamps must include a timezone")
        if self.expires_at <= self.issued_at:
            raise ValueError("receipt expiry must be after issuance")

    @property
    def jti(self) -> str:
        return self.receipt_id

    def to_claims(self) -> dict[str, Any]:
        return {
            "v": 1,
            "aud": self.audience,
            "iss": self.issuer,
            "jti": self.receipt_id,
            "iat": _timestamp(self.issued_at),
            "exp": _timestamp(self.expires_at),
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "tool_integrity_digest": self.tool_integrity_digest,
            "invocation_digest": self.invocation_digest,
            "intent_digest": self.intent_digest,
            "policy_version": self.policy_version,
            "decision_id": self.decision_id,
            "event_id": self.event_id,
            "disposition": self.disposition,
            "workload_id": self.workload_id,
        }

    @classmethod
    def from_claims(cls, claims: Mapping[str, Any]) -> "EnforcementReceiptClaims":
        _validate_claims(claims)
        return cls(
            audience=claims["aud"],
            issuer=claims["iss"],
            receipt_id=claims["jti"],
            tenant_id=claims["tenant_id"],
            agent_id=claims["agent_id"],
            session_id=claims["session_id"],
            run_id=claims["run_id"],
            tool_name=claims["tool_name"],
            tool_version=claims["tool_version"],
            tool_integrity_digest=claims["tool_integrity_digest"],
            invocation_digest=claims["invocation_digest"],
            intent_digest=claims["intent_digest"],
            policy_version=claims["policy_version"],
            decision_id=claims["decision_id"],
            event_id=claims["event_id"],
            issued_at=datetime.fromtimestamp(claims["iat"], timezone.utc),
            expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc),
            disposition=claims["disposition"],
            workload_id=claims["workload_id"],
        )


class InMemoryEnforcementReceiptReplayStore:
    """Atomic single-process receipt replay protection for tests and demos."""

    def __init__(self, *, now: Callable[[], datetime] | None = None) -> None:
        self._now = now or _utc_now
        self._used_until: dict[str, datetime] = {}
        self._lock = threading.Lock()

    async def consume(self, receipt_id: str, expires_at: datetime) -> bool:
        now = _normalize_time(self._now())
        expiry = _normalize_time(expires_at)
        if expiry <= now:
            return False
        with self._lock:
            self._used_until = {
                key: value for key, value in self._used_until.items() if value > now
            }
            if receipt_id in self._used_until:
                return False
            self._used_until[receipt_id] = expiry
            return True


class SignedEnforcementReceiptAuthority:
    """Reference HMAC issuer/verifier for control-plane receipts.

    Production deployments may replace this class with an asymmetric signer
    while retaining the claims and port contracts.  The gateway must receive
    only verification material in that arrangement.
    """

    def __init__(
        self,
        signing_key: bytes | str,
        *,
        issuer: str = "safeharness-control-plane",
        audience: str = _AUDIENCE,
        replay_store: EnforcementReceiptReplayStore | None = None,
        default_ttl: timedelta = timedelta(minutes=2),
        max_ttl: timedelta = timedelta(minutes=5),
        now: Callable[[], datetime] | None = None,
    ) -> None:
        key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")
        if not issuer or audience != _AUDIENCE:
            raise ValueError("issuer must be non-empty and audience must be the gateway")
        if default_ttl <= timedelta(0) or max_ttl <= timedelta(0) or default_ttl > max_ttl:
            raise ValueError("receipt TTLs must be positive and ordered")
        self._key = key
        self.issuer = issuer
        self.audience = audience
        self._default_ttl = default_ttl
        self._max_ttl = max_ttl
        self._now = now or _utc_now
        self._replay_store = replay_store or InMemoryEnforcementReceiptReplayStore(
            now=self._now
        )

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
        """Sign an allow proof for one exact, already-evaluated invocation."""

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
        return self._encode(claims.to_claims())

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
        if len(receipt) > 64 * 1024:
            return _invalid("enforcement_receipt_invalid", "The enforcement receipt is invalid.")
        try:
            claims = EnforcementReceiptClaims.from_claims(self._decode(receipt))
        except (OSError, OverflowError, TypeError, ValueError):
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
        """Alias for non-consuming verification used by policy enforcement points."""

        return await self.verify(context, descriptor, invocation, receipt, consume=False, **kwargs)

    def fingerprint(self, receipt: str) -> str:
        return hashlib.sha256(receipt.encode("utf-8")).hexdigest()

    def _encode(self, claims: Mapping[str, Any]) -> str:
        encoded = _b64encode(_canonical_json(claims))
        signed = f"{_PREFIX}.{encoded}".encode("ascii")
        signature = hmac.new(self._key, signed, hashlib.sha256).digest()
        return f"{_PREFIX}.{encoded}.{_b64encode(signature)}"

    def _decode(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str):
            raise ValueError("malformed enforcement receipt")
        try:
            prefix, encoded, signature = token.split(".")
            if prefix != _PREFIX:
                raise ValueError("unsupported enforcement receipt version")
            expected = hmac.new(
                self._key, f"{prefix}.{encoded}".encode("ascii"), hashlib.sha256
            ).digest()
            if not hmac.compare_digest(expected, _b64decode(signature)):
                raise ValueError("enforcement receipt signature mismatch")
            decoded = json.loads(_b64decode(encoded).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("malformed enforcement receipt") from exc
        if not isinstance(decoded, dict) or set(decoded) != _REQUIRED_CLAIMS:
            raise ValueError("unexpected enforcement receipt claims")
        return decoded


def _build_receipt_claims(
    context: SessionContext,
    descriptor: ToolDescriptor,
    invocation: ToolInvocation,
    *,
    issuer: str,
    audience: str,
    decision_id: str,
    event_id: str,
    policy_version: str,
    expires_at: datetime | None,
    workload_id: str,
    default_ttl: timedelta,
    max_ttl: timedelta,
    now: datetime,
) -> EnforcementReceiptClaims:
    if invocation.tool_name != descriptor.name or invocation.tool_version not in {
        None,
        descriptor.version,
    }:
        raise ValueError("invocation does not match the canonical tool descriptor")
    if not decision_id or not event_id or not policy_version:
        raise ValueError("decision_id, event_id, and policy_version are required")
    issued_at = _normalize_time(now)
    expiry = _normalize_time(expires_at or (issued_at + default_ttl))
    if expiry <= issued_at or expiry > issued_at + max_ttl:
        raise ValueError("receipt expiry is outside the configured lifetime")
    return EnforcementReceiptClaims(
        audience=audience,
        issuer=issuer,
        receipt_id=str(uuid4()),
        tenant_id=context.tenant_id,
        agent_id=context.agent_id,
        session_id=context.session_id,
        run_id=context.run_id,
        tool_name=descriptor.name,
        tool_version=descriptor.version,
        tool_integrity_digest=descriptor.integrity_digest,
        invocation_digest=invocation_digest(invocation),
        intent_digest=invocation.intent_digest or "",
        policy_version=policy_version,
        decision_id=decision_id,
        event_id=event_id,
        issued_at=issued_at,
        expires_at=expiry,
        workload_id=workload_id,
    )


async def _verify_receipt_claims(
    claims: EnforcementReceiptClaims,
    context: SessionContext,
    descriptor: ToolDescriptor,
    invocation: ToolInvocation,
    *,
    issuer: str,
    audience: str,
    replay_store: EnforcementReceiptReplayStore,
    max_ttl: timedelta,
    now: datetime,
    consume: bool,
    expected_decision_id: str | None,
    expected_event_id: str | None,
    expected_policy_version: str | None,
    workload_id: str | None,
) -> EnforcementReceiptVerification:
    current_time = _normalize_time(now)
    if claims.expires_at <= current_time:
        return _invalid("enforcement_receipt_expired", "The enforcement receipt has expired.")
    if claims.issued_at < current_time - max_ttl:
        return _invalid(
            "enforcement_receipt_invalid",
            "The enforcement receipt issuance time is outside the accepted window.",
        )
    if claims.issued_at > current_time + timedelta(minutes=1):
        return _invalid("enforcement_receipt_invalid", "The enforcement receipt is not yet valid.")
    if claims.expires_at - claims.issued_at > max_ttl:
        return _invalid("enforcement_receipt_invalid", "The enforcement receipt lifetime is invalid.")
    if claims.issuer != issuer or claims.audience != audience:
        return _invalid(
            "enforcement_receipt_identity_mismatch",
            "The enforcement receipt was issued for another trust domain.",
        )
    if not _matches_claims(claims, context, descriptor, invocation):
        return _invalid(
            "enforcement_receipt_identity_mismatch",
            "The enforcement receipt is not bound to this request.",
        )
    if expected_decision_id is not None and claims.decision_id != expected_decision_id:
        return _invalid("enforcement_receipt_identity_mismatch", "The decision proof does not match.")
    if expected_event_id is not None and claims.event_id != expected_event_id:
        return _invalid("enforcement_receipt_identity_mismatch", "The event proof does not match.")
    if expected_policy_version is not None and claims.policy_version != expected_policy_version:
        return _invalid("enforcement_receipt_identity_mismatch", "The policy proof does not match.")
    if workload_id is not None and claims.workload_id != workload_id:
        return _invalid("enforcement_receipt_identity_mismatch", "The workload proof does not match.")
    if consume:
        try:
            consumed = await replay_store.consume(claims.receipt_id, claims.expires_at)
        except Exception:
            return _invalid(
                "enforcement_receipt_store_unavailable",
                "Enforcement receipt replay protection is unavailable.",
            )
        if not consumed:
            return _invalid(
                "enforcement_receipt_replayed",
                "The enforcement receipt was already consumed.",
            )
    return EnforcementReceiptVerification(True, claims=claims.to_claims())


def _matches_claims(
    claims: EnforcementReceiptClaims,
    context: SessionContext,
    descriptor: ToolDescriptor,
    invocation: ToolInvocation,
) -> bool:
    return all(
        hmac.compare_digest(actual, expected)
        for actual, expected in (
            (claims.audience, _AUDIENCE),
            (claims.tenant_id, context.tenant_id),
            (claims.agent_id, context.agent_id),
            (claims.session_id, context.session_id),
            (claims.run_id, context.run_id),
            (claims.tool_name, descriptor.name),
            (claims.tool_version, descriptor.version),
            (claims.tool_integrity_digest, descriptor.integrity_digest),
            (claims.invocation_digest, invocation_digest(invocation)),
            (claims.intent_digest, invocation.intent_digest or ""),
        )
    )


def _validate_claims(claims: Mapping[str, Any]) -> None:
    if set(claims) != _REQUIRED_CLAIMS or claims.get("v") != 1:
        raise ValueError("invalid enforcement receipt claims")
    string_keys = _REQUIRED_CLAIMS - {"v", "iat", "exp"}
    if any(not isinstance(claims[key], str) for key in string_keys):
        raise ValueError("invalid enforcement receipt claim type")
    if any(not claims[key] for key in string_keys - {"workload_id", "intent_digest"}):
        raise ValueError("empty enforcement receipt claim")
    if claims["disposition"] != "allow":
        raise ValueError("enforcement receipt disposition must be allow")
    if any(
        not isinstance(claims[key], int) or isinstance(claims[key], bool)
        for key in ("iat", "exp")
    ) or claims["exp"] <= claims["iat"]:
        raise ValueError("invalid enforcement receipt lifetime")
    for key in ("tool_integrity_digest", "invocation_digest"):
        value = claims[key]
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("invalid enforcement receipt digest")
    intent_digest = claims["intent_digest"]
    if intent_digest and (
        len(intent_digest) != 64
        or any(char not in "0123456789abcdef" for char in intent_digest)
    ):
        raise ValueError("invalid enforcement receipt intent digest")


def _invalid(code: str, reason: str) -> EnforcementReceiptVerification:
    return EnforcementReceiptVerification(False, reason=reason, reason_code=code)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or not value.isascii():
        raise ValueError("invalid base64url value")
    padded = value + ("=" * (-len(value) % 4))
    decoded = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    if _b64encode(decoded) != value:
        raise ValueError("non-canonical base64url value")
    return decoded


def _timestamp(value: datetime) -> int:
    return int(_normalize_time(value).timestamp())


def _normalize_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("receipt times must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
