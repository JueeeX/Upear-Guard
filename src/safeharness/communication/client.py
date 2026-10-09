"""Async client for a separately deployed Agent Communication Gateway."""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
from uuid import uuid4

from safeharness.communication.models import InterAgentMessage, MessageLease
from safeharness.communication.protocol import (
    ack_request_to_wire,
    lease_from_wire,
    parse_response,
    receive_request_to_wire,
    send_request_to_wire,
    store_result_from_wire,
    strict_json_loads,
)
from safeharness.communication.store import CommunicationStoreResult


@dataclass(frozen=True, slots=True)
class CommunicationReceiveResult:
    leases: tuple[MessageLease, ...]
    blocked_count: int = 0


class CommunicationGatewayError(RuntimeError):
    """A structured and content-safe communication gateway error."""

    def __init__(self, code: str, message: str, *, status: int | None = None) -> None:
        self.code = code
        self.status = status
        super().__init__(message)


class RemoteAgentCommunicationClient:
    """Send, receive, and acknowledge messages for one authenticated Agent."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        tenant_id: str,
        agent_id: str,
        timeout: float = 10.0,
        max_response_bytes: int = 2 * 1024 * 1024,
        tls_context: ssl.SSLContext | None = None,
    ) -> None:
        normalized = base_url.rstrip("/")
        parsed = urlsplit(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain credentials, query, or fragment")
        if not isinstance(api_key, str) or len(api_key) < 32:
            raise ValueError("api_key must contain at least 32 characters")
        if not tenant_id or not agent_id:
            raise ValueError("tenant_id and agent_id are required")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if tls_context is not None and parsed.scheme != "https":
            raise ValueError("tls_context requires an HTTPS gateway URL")
        self.base_url = normalized
        self._api_key = api_key
        self.tenant_id = tenant_id
        self.agent_id = agent_id
        self.timeout = float(timeout)
        self.max_response_bytes = int(max_response_bytes)
        self._tls_context = tls_context

    async def health(self) -> dict[str, Any]:
        response = await asyncio.to_thread(self._request, "GET", "/health", None)
        self._expect_fields(response, {"service", "status"})
        return dict(response)

    async def send(self, message: InterAgentMessage) -> CommunicationStoreResult:
        if (message.tenant_id, message.sender_agent_id) != (
            self.tenant_id,
            self.agent_id,
        ):
            raise ValueError("the client may send only as its configured tenant/Agent")
        response = await asyncio.to_thread(
            self._request,
            "POST",
            "/v1/messages/send",
            send_request_to_wire(message),
        )
        self._expect_fields(response, {"result"})
        try:
            result = store_result_from_wire(response["result"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "The communication gateway returned an invalid send result.",
            ) from exc
        if not result.allowed:
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "A successful gateway response contained a denied send result.",
            )
        return result

    async def receive(
        self,
        *,
        limit: int = 10,
        lease_duration: timedelta = timedelta(seconds=30),
    ) -> CommunicationReceiveResult:
        response = await asyncio.to_thread(
            self._request,
            "POST",
            "/v1/messages/receive",
            receive_request_to_wire(limit=limit, lease_duration=lease_duration),
        )
        self._expect_fields(response, {"leases", "blocked_count"})
        raw_leases = response["leases"]
        blocked_count = response["blocked_count"]
        if not isinstance(raw_leases, list):
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "The communication gateway returned an invalid lease list.",
            )
        if (
            isinstance(blocked_count, bool)
            or not isinstance(blocked_count, int)
            or blocked_count < 0
            or blocked_count > limit
        ):
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "The communication gateway returned an invalid blocked count.",
            )
        try:
            leases = tuple(lease_from_wire(value) for value in raw_leases)
        except (TypeError, ValueError) as exc:
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "The communication gateway returned an invalid message lease.",
            ) from exc
        if len(leases) + blocked_count > limit:
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "The communication gateway exceeded the requested receive limit.",
            )
        if any(
            (lease.message.tenant_id, lease.message.recipient_agent_id)
            != (self.tenant_id, self.agent_id)
            for lease in leases
        ):
            raise CommunicationGatewayError(
                "communication_gateway_recipient_mismatch",
                "The communication gateway returned a lease for another tenant/Agent.",
            )
        return CommunicationReceiveResult(leases, blocked_count)

    async def acknowledge(self, lease: MessageLease) -> CommunicationStoreResult:
        if (lease.message.tenant_id, lease.message.recipient_agent_id) != (
            self.tenant_id,
            self.agent_id,
        ):
            raise ValueError(
                "the client may acknowledge only its configured tenant/Agent leases"
            )
        response = await asyncio.to_thread(
            self._request,
            "POST",
            "/v1/messages/ack",
            ack_request_to_wire(lease.message.message_id, lease.lease_id),
        )
        self._expect_fields(response, {"result"})
        try:
            result = store_result_from_wire(response["result"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "The communication gateway returned an invalid acknowledgement result.",
            ) from exc
        if not result.allowed:
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "A successful gateway response contained a denied acknowledgement.",
            )
        return result

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        body = None
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._api_key}",
            "X-Request-ID": str(uuid4()),
        }
        if payload is not None:
            body = json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            handlers = [_NoRedirectHandler()]
            if self._tls_context is not None:
                handlers.append(HTTPSHandler(context=self._tls_context))
            with build_opener(*handlers).open(request, timeout=self.timeout) as response:
                status = response.status
                raw = self._read_limited(response)
        except HTTPError as exc:
            status = exc.code
            try:
                raw = self._read_limited(exc)
            except CommunicationGatewayError:
                raw = b""
            finally:
                exc.close()
            self._raise_remote_error(status, raw)
        except (TimeoutError, socket.timeout, URLError, OSError) as exc:
            raise CommunicationGatewayError(
                "communication_gateway_unavailable",
                "The Agent Communication Gateway could not be reached.",
            ) from exc

        if status < 200 or status >= 300:
            self._raise_remote_error(status, raw)
        try:
            response_payload = parse_response(strict_json_loads(raw))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "The communication gateway returned invalid JSON.",
                status=status,
            ) from exc
        if not response_payload["ok"]:
            self._raise_payload_error(response_payload, status)
        return dict(response_payload)

    @staticmethod
    def _expect_fields(response: dict[str, Any], fields: set[str]) -> None:
        expected = {"protocol", "ok", *fields}
        if set(response) != expected:
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "The communication gateway response contained invalid fields.",
            )

    def _read_limited(self, response) -> bytes:
        raw = response.read(self.max_response_bytes + 1)
        if len(raw) > self.max_response_bytes:
            raise CommunicationGatewayError(
                "gateway_response_too_large",
                "The communication gateway response exceeded the configured limit.",
            )
        return raw

    def _raise_remote_error(self, status: int, raw: bytes) -> None:
        try:
            payload = parse_response(strict_json_loads(raw))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise CommunicationGatewayError(
                "communication_gateway_http_error",
                "The Agent Communication Gateway rejected the request.",
                status=status,
            )
        self._raise_payload_error(payload, status)

    @staticmethod
    def _raise_payload_error(payload: Any, status: int) -> None:
        error = payload.get("error") if isinstance(payload, Mapping) else None
        if not isinstance(error, dict):
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "The communication gateway returned an invalid error response.",
                status=status,
            )
        code = error.get("code")
        message = error.get("message")
        if not isinstance(code, str) or not isinstance(message, str):
            raise CommunicationGatewayError(
                "invalid_gateway_response",
                "The communication gateway returned an invalid error response.",
                status=status,
            )
        raise CommunicationGatewayError(code, message, status=status)


class _NoRedirectHandler(HTTPRedirectHandler):
    """Do not forward an Agent API key to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
