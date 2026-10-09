"""Distributed fixed-window rate limiting for the communication gateway."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any, Protocol


class CommunicationRateLimiter(Protocol):
    def allow(self, bucket: str) -> bool:
        """Atomically consume one request from a low-cardinality bucket."""

    def close(self) -> None:
        """Release backend resources."""


class RedisFixedWindowRateLimiter:
    """Atomic Redis rate limit shared by all communication gateway replicas."""

    def __init__(
        self,
        url: str | None = None,
        *,
        client: Any | None = None,
        requests: int = 120,
        window_seconds: int = 60,
        key_prefix: str = "safeharness:communication-rate:",
        socket_timeout: float = 2.0,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if (url is None) == (client is None):
            raise ValueError("provide exactly one Redis URL or client")
        if not 1 <= requests <= 100_000:
            raise ValueError("requests must be between 1 and 100000")
        if not 1 <= window_seconds <= 3600:
            raise ValueError("window_seconds must be between 1 and 3600")
        if re.fullmatch(r"[A-Za-z0-9:_.-]{1,128}", key_prefix) is None:
            raise ValueError("key_prefix contains unsupported characters")
        if socket_timeout <= 0:
            raise ValueError("socket_timeout must be positive")
        self.requests = int(requests)
        self.window_seconds = int(window_seconds)
        self.key_prefix = key_prefix
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._client = client or _redis_client(url or "", float(socket_timeout))

    def allow(self, bucket: str) -> bool:
        if not isinstance(bucket, str) or not bucket:
            raise ValueError("rate-limit bucket must not be empty")
        current = self._now()
        if current.tzinfo is None:
            raise ValueError("rate-limit clock must be timezone-aware")
        window_ms = self.window_seconds * 1000
        now_ms = int(current.astimezone(timezone.utc).timestamp() * 1000)
        window_id = now_ms // window_ms
        digest = hashlib.sha256(bucket.encode("utf-8")).hexdigest()
        key = f"{self.key_prefix}{digest}:{window_id}"
        expires_at_ms = (window_id + 2) * window_ms
        pipeline = self._client.pipeline(transaction=True)
        pipeline.incr(key)
        pipeline.pexpireat(key, expires_at_ms)
        count, _ = pipeline.execute()
        return int(count) <= self.requests

    def close(self) -> None:
        closer = getattr(self._client, "close", None)
        if closer is not None:
            closer()


def communication_rate_limiter_from_environment(
    environ: Mapping[str, str] | None = None,
) -> RedisFixedWindowRateLimiter | None:
    values = os.environ if environ is None else environ
    url = values.get("SAFEHARNESS_COMMUNICATION_RATE_LIMIT_REDIS_URL", "").strip()
    if not url:
        return None
    try:
        requests = int(
            values.get("SAFEHARNESS_COMMUNICATION_RATE_LIMIT_REQUESTS", "120")
        )
        window_seconds = int(
            values.get("SAFEHARNESS_COMMUNICATION_RATE_LIMIT_WINDOW_SECONDS", "60")
        )
    except ValueError as exc:
        raise ValueError("communication rate-limit values must be integers") from exc
    return RedisFixedWindowRateLimiter(
        url,
        requests=requests,
        window_seconds=window_seconds,
    )


def _redis_client(url: str, socket_timeout: float) -> Any:
    try:
        from redis import Redis
    except ImportError as exc:
        raise RuntimeError(
            "Redis communication rate limiting requires: pip install 'safeharness[production]'"
        ) from exc
    return Redis.from_url(
        url,
        decode_responses=False,
        socket_connect_timeout=socket_timeout,
        socket_timeout=socket_timeout,
        retry_on_timeout=False,
        health_check_interval=30,
    )
