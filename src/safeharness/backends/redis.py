"""Redis-backed atomic replay protection for distributed tool gateways."""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from safeharness.backends._audit import normalize_time


class RedisCapabilityReplayStore:
    """Consume capability IDs atomically across gateway replicas.

    Redis stores only a SHA-256 digest of the capability ID. The absolute token
    expiry is passed with ``PXAT`` so retention matches the signed claim even
    when gateway clocks or request latency differ slightly.
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        client: Any | None = None,
        key_prefix: str = "safeharness:capability-replay:",
        socket_timeout: float = 2.0,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if (url is None) == (client is None):
            raise ValueError("provide exactly one Redis URL or client")
        if not isinstance(key_prefix, str) or re.fullmatch(
            r"[A-Za-z0-9:_.-]{1,128}", key_prefix
        ) is None:
            raise ValueError("key_prefix contains unsupported characters")
        if socket_timeout <= 0:
            raise ValueError("socket_timeout must be positive")
        self.key_prefix = key_prefix
        self._now = now or _utc_now
        self._client = client or _redis_client(url or "", float(socket_timeout))

    async def consume(self, token_id: str, expires_at: datetime) -> bool:
        if not isinstance(token_id, str) or not token_id:
            raise ValueError("token_id must not be empty")
        expiry = normalize_time(expires_at)
        if expiry <= normalize_time(self._now()):
            return False
        key = self.key_prefix + hashlib.sha256(token_id.encode("utf-8")).hexdigest()
        expires_at_ms = int(expiry.timestamp() * 1000)
        return await asyncio.to_thread(self._consume, key, expires_at_ms)

    def _consume(self, key: str, expires_at_ms: int) -> bool:
        return bool(self._client.set(key, b"1", nx=True, pxat=expires_at_ms))

    async def health(self) -> bool:
        return await asyncio.to_thread(self._health)

    def _health(self) -> bool:
        try:
            result = self._client.set(
                self.key_prefix + "health",
                b"1",
                px=1000,
            )
        except Exception:
            return False
        return bool(result)

    async def close(self) -> None:
        closer = getattr(self._client, "aclose", None) or getattr(
            self._client, "close", None
        )
        if closer is None:
            return
        await asyncio.to_thread(closer)


def _redis_client(url: str, socket_timeout: float) -> Any:
    try:
        from redis import Redis
    except ImportError as exc:
        raise RuntimeError(
            "Redis replay protection requires: pip install 'safeharness[production]'"
        ) from exc
    return Redis.from_url(
        url,
        decode_responses=False,
        socket_connect_timeout=socket_timeout,
        socket_timeout=socket_timeout,
        retry_on_timeout=False,
        health_check_interval=30,
    )


class RedisEnforcementReceiptReplayStore(RedisCapabilityReplayStore):
    """Distributed receipt replay store with an isolated Redis namespace."""

    def __init__(self, url: str | None = None, **kwargs: Any) -> None:
        kwargs.setdefault("key_prefix", "safeharness:receipt-replay:")
        super().__init__(url, **kwargs)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
