"""Reference signed-capability gateway with single-use invocation claims.

The gateway is deliberately independent from agent-framework adapters. In
production it should run behind a separate service boundary; this module is a
standard-library reference implementation and an in-memory conformance target.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import threading
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from safeharness.api.context import SessionContext
from safeharness.api.tools import ToolDescriptor, ToolInvocation
from safeharness.ports import (
    AuthorizationResult,
    CapabilityGrant,
    CapabilityReplayStore,
)


_TOKEN_PREFIX = "shc1"
_REQUIRED_CLAIMS = frozenset(
    {
        "v",
        "jti",
        "iat",
        "exp",
        "tenant_id",
        "subject",
        "session_id",
        "run_id",
        "tool_name",
        "tool_version",
        "tool_integrity_digest",
        "invocation_digest",
    }
)


class InMemoryCapabilityReplayStore:
    """Atomic single-process replay protection for local development and tests.

    A production gateway must replace this with an atomic shared store whose
    retention is at least the maximum token lifetime plus clock-skew allowance.
    """

    def __init__(self, *, now: Callable[[], datetime] | None = None) -> None:
        self._now = now or _utc_now
        self._used_until: dict[str, datetime] = {}
        self._lock = threading.Lock()

    async def consume(self, token_id: str, expires_at: datetime) -> bool:
        now = _normalize_time(self._now())
        expiry = _normalize_time(expires_at)
        if expiry <= now:
            return False
        # A thread lock keeps replay consumption atomic when the reference HTTP
        # gateway serves requests from multiple event loops and worker threads.
        with self._lock:
            self._used_until = {
                known_id: known_expiry
                for known_id, known_expiry in self._used_until.items()
                if known_expiry > now
            }
            if token_id in self._used_until:
                return False
            self._used_until[token_id] = expiry
            return True


class SignedCapabilityGateway:
    """Issue and verify HMAC-authenticated, session-bound, single-use claims.

    The signing key is gateway-only material. Agent processes receive only an
    opaque token and should call a remote gateway for verification in production.
    HMAC is used here to avoid a cryptographic runtime dependency; service
    deployments may use an asymmetric signer while preserving these claims.
    """

    def __init__(
        self,
        signing_key: bytes | str,
        grants: Mapping[str | tuple[str, str], Iterable[str]],
        *,
        replay_store: CapabilityReplayStore | None = None,
        default_ttl: timedelta = timedelta(minutes=5),
        max_ttl: timedelta = timedelta(minutes=5),
        now: Callable[[], datetime] | None = None,
    ) -> None:
        key = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")
        if default_ttl <= timedelta(0):
            raise ValueError("default_ttl must be positive")
        if max_ttl <= timedelta(0) or default_ttl > max_ttl:
            raise ValueError("max_ttl must be positive and cover default_ttl")
        self._key = key
        self._grants: dict[str, frozenset[str]] = {}
        self._tenant_grants: dict[tuple[str, str], frozenset[str]] = {}
        for principal, principal_grants in grants.items():
            normalized = frozenset(str(grant) for grant in principal_grants)
            if isinstance(principal, tuple):
                if len(principal) != 2 or not all(principal):
                    raise ValueError("tenant grant keys must be (tenant_id, agent_id)")
                self._tenant_grants[(str(principal[0]), str(principal[1]))] = normalized
            else:
                if not str(principal):
                    raise ValueError("agent grant keys must not be empty")
                self._grants[str(principal)] = normalized
        self._now = now or _utc_now
        self._default_ttl = default_ttl
        self._max_ttl = max_ttl
        self._replay_store = replay_store or InMemoryCapabilityReplayStore(now=self._now)

    async def issue(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
        *,
        expires_at: datetime | None = None,
    ) -> CapabilityGrant:
        """Authorize and sign a capability for one exact, future invocation."""

        if not self._is_granted(context, descriptor):
            raise PermissionError("The subject is not authorized to receive this capability.")
        if invocation.tool_name != descriptor.name or invocation.tool_version not in (
            None,
            descriptor.version,
        ):
            raise ValueError("invocation does not match the canonical tool descriptor")

        now = _normalize_time(self._now())
        expiry = _normalize_time(expires_at or (now + self._default_ttl))
        if expiry <= now:
            raise ValueError("capability expiry must be in the future")
        if expiry > now + self._max_ttl:
            raise ValueError("capability expiry exceeds the configured maximum lifetime")
        claims = {
            "v": 1,
            "jti": str(uuid4()),
            "iat": _timestamp(now),
            "exp": _timestamp(expiry),
            "tenant_id": context.tenant_id,
            "subject": context.agent_id,
            "session_id": context.session_id,
            "run_id": context.run_id,
            "tool_name": descriptor.name,
            "tool_version": descriptor.version,
            "tool_integrity_digest": descriptor.integrity_digest,
            "invocation_digest": invocation_digest(invocation),
        }
        token = self._encode(claims)
        return CapabilityGrant(
            token=token,
            token_id=claims["jti"],
            expires_at=expiry,
            subject=context.agent_id,
            tenant_id=context.tenant_id,
            session_id=context.session_id,
            run_id=context.run_id,
            tool_name=descriptor.name,
            tool_version=descriptor.version,
            tool_integrity_digest=descriptor.integrity_digest,
            invocation_digest=claims["invocation_digest"],
        )

    async def authorize(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
    ) -> AuthorizationResult:
        """Verify and atomically consume the claim before tool dispatch."""

        result, token_id, expiry = self._verify(context, descriptor, invocation)
        if not result.allowed or token_id is None or expiry is None:
            return result

        try:
            consumed = await self._replay_store.consume(token_id, expiry)
        except Exception:
            return _deny(
                "capability_token_replay_store_failed",
                "Replay protection is unavailable; denying the tool call.",
            )
        if not consumed:
            return _deny(
                "capability_token_replayed",
                "The capability token was already consumed or expired.",
            )
        return result

    async def inspect(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
    ) -> AuthorizationResult:
        """Verify a claim without consuming it.

        This is intended for a policy-enforcement point that must complete its
        remaining checks before a separate gateway atomically consumes the
        token and dispatches the tool.
        """

        result, _, _ = self._verify(context, descriptor, invocation)
        return result

    def _verify(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
    ) -> tuple[AuthorizationResult, str | None, datetime | None]:
        """Return verified claims and replay coordinates without consuming them."""

        if not invocation.capability_token:
            return (
                _deny(
                    "capability_token_missing",
                    "A signed capability token is required.",
                ),
                None,
                None,
            )
        try:
            claims = self._decode(invocation.capability_token)
        except ValueError:
            return (
                _deny("capability_token_invalid", "The capability token is invalid."),
                None,
                None,
            )

        try:
            expiry = datetime.fromtimestamp(claims["exp"], timezone.utc)
        except (KeyError, OSError, OverflowError, TypeError, ValueError):
            return (
                _deny(
                    "capability_token_invalid",
                    "The capability token has invalid expiry.",
                ),
                None,
                None,
            )
        if expiry <= _normalize_time(self._now()):
            return (
                _deny(
                    "capability_token_expired",
                    "The capability token has expired.",
                ),
                None,
                None,
            )
        if not _matches_context(claims, context):
            return (
                _deny(
                    "capability_token_context_mismatch",
                    "The capability token belongs to a different security session.",
                ),
                None,
                None,
            )
        if not _matches_descriptor(claims, descriptor):
            return (
                _deny(
                    "capability_token_tool_mismatch",
                    "The capability token does not authorize this canonical tool.",
                ),
                None,
                None,
            )
        try:
            matches_invocation = hmac.compare_digest(
                str(claims["invocation_digest"]), invocation_digest(invocation)
            )
        except (KeyError, TypeError, ValueError):
            return (
                _deny(
                    "capability_token_invocation_invalid",
                    "The invocation cannot be matched to the capability token.",
                ),
                None,
                None,
            )
        if not matches_invocation:
            return (
                _deny(
                    "capability_token_invocation_mismatch",
                    "The capability token is not valid for these tool arguments.",
                ),
                None,
                None,
            )

        return (
            AuthorizationResult(
                True,
                claims={
                    "capability_token_id": claims["jti"],
                    "subject": claims["subject"],
                    "tenant_id": claims["tenant_id"],
                    "tool_name": claims["tool_name"],
                    "tool_version": claims["tool_version"],
                    "tool_integrity_digest": claims["tool_integrity_digest"],
                    "session_id": claims["session_id"],
                    "run_id": claims["run_id"],
                    "invocation_digest": claims["invocation_digest"],
                    "expires_at": expiry.isoformat(),
                },
            ),
            str(claims["jti"]),
            expiry,
        )

    def _is_granted(self, context: SessionContext, descriptor: ToolDescriptor) -> bool:
        tenant_principal = (context.tenant_id, context.agent_id)
        granted = (
            self._tenant_grants[tenant_principal]
            if tenant_principal in self._tenant_grants
            else self._grants.get(context.agent_id, frozenset())
        )
        return (
            "*" in granted
            or f"tool:{descriptor.name}" in granted
            or (
                bool(descriptor.required_capabilities)
                and descriptor.required_capabilities <= granted
            )
        )

    def _encode(self, claims: Mapping[str, Any]) -> str:
        payload = _canonical_json(claims)
        encoded = _b64encode(payload)
        signed = f"{_TOKEN_PREFIX}.{encoded}".encode("ascii")
        signature = hmac.new(self._key, signed, hashlib.sha256).digest()
        return f"{_TOKEN_PREFIX}.{encoded}.{_b64encode(signature)}"

    def _decode(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str):
            raise ValueError("malformed capability token")
        try:
            prefix, encoded, signature = token.split(".")
        except ValueError as exc:
            raise ValueError("malformed capability token") from exc
        if prefix != _TOKEN_PREFIX:
            raise ValueError("unsupported capability token version")
        signed = f"{prefix}.{encoded}".encode("ascii")
        expected = hmac.new(self._key, signed, hashlib.sha256).digest()
        try:
            provided = _b64decode(signature)
        except ValueError as exc:
            raise ValueError("malformed capability signature") from exc
        if not hmac.compare_digest(expected, provided):
            raise ValueError("capability signature mismatch")
        try:
            parsed = json.loads(_b64decode(encoded).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("malformed capability claims") from exc
        if not isinstance(parsed, dict) or set(parsed) != _REQUIRED_CLAIMS:
            raise ValueError("unexpected capability claims")
        _validate_claims(parsed)
        return parsed


def invocation_digest(invocation: ToolInvocation) -> str:
    """Hash the exact call fields that a capability token is permitted to use."""

    payload = {
        "tool_name": invocation.tool_name,
        "arguments": _json_value(invocation.arguments),
        "call_id": invocation.call_id,
        "tool_version": invocation.tool_version,
        "resource": invocation.resource,
        "intent_digest": invocation.intent_digest,
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _deny(code: str, reason: str) -> AuthorizationResult:
    return AuthorizationResult(False, reason, code)


def _matches_context(claims: Mapping[str, Any], context: SessionContext) -> bool:
    return all(
        hmac.compare_digest(str(claims[key]), value)
        for key, value in (
            ("tenant_id", context.tenant_id),
            ("subject", context.agent_id),
            ("session_id", context.session_id),
            ("run_id", context.run_id),
        )
    )


def _matches_descriptor(claims: Mapping[str, Any], descriptor: ToolDescriptor) -> bool:
    return all(
        hmac.compare_digest(str(claims[key]), value)
        for key, value in (
            ("tool_name", descriptor.name),
            ("tool_version", descriptor.version),
            ("tool_integrity_digest", descriptor.integrity_digest),
        )
    )


def _validate_claims(claims: Mapping[str, Any]) -> None:
    if claims["v"] != 1 or any(
        not isinstance(claims[key], str)
        for key in _REQUIRED_CLAIMS - {"v", "iat", "exp"}
    ):
        raise ValueError("invalid capability claims")
    if any(not isinstance(claims[key], int) or isinstance(claims[key], bool) for key in ("iat", "exp")):
        raise ValueError("invalid capability timestamps")
    if claims["exp"] <= claims["iat"]:
        raise ValueError("invalid capability lifetime")
    if any(not claims[key] for key in _REQUIRED_CLAIMS - {"v", "iat", "exp"}):
        raise ValueError("empty capability claim")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        _json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("capability-bound values must be finite JSON numbers")
        return value
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or key in output:
                raise ValueError("capability-bound mappings require unique string keys")
            output[key] = _json_value(item)
        return output
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    raise ValueError(
        "capability-bound values must be JSON-compatible, "
        f"not {type(value).__module__}.{type(value).__qualname__}"
    )


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if not value or not value.isascii():
        raise ValueError("invalid base64url value")
    padded = value + ("=" * (-len(value) % 4))
    try:
        decoded = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("invalid base64url value") from exc
    if _b64encode(decoded) != value:
        raise ValueError("non-canonical base64url value")
    return decoded


def _timestamp(value: datetime) -> int:
    return int(_normalize_time(value).timestamp())


def _normalize_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("capability times must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
