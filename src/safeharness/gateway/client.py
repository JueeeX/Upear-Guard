"""Async client for a separately deployed Tool Security Gateway."""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from safeharness.api.context import SessionContext
from safeharness.api.tools import ToolDescriptor, ToolInvocation
from safeharness.backends.gateway import invocation_digest
from safeharness.gateway.protocol import (
    authorization_from_wire,
    grant_from_wire,
    parse_response,
    request_to_wire,
    strict_json_loads,
)
from safeharness.ports import AuthorizationResult, CapabilityGrant


class ToolGatewayError(RuntimeError):
    """A safe, structured error returned by or while reaching the gateway."""

    def __init__(self, code: str, message: str, *, status: int | None = None) -> None:
        self.code = code
        self.status = status
        super().__init__(message)


class RemoteToolGatewayClient:
    """Issue, inspect, and execute exact invocations through the remote service."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
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
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.base_url = normalized
        self._api_key = api_key
        self.timeout = float(timeout)
        self.max_response_bytes = int(max_response_bytes)
        if tls_context is not None and parsed.scheme != "https":
            raise ValueError("tls_context requires an HTTPS gateway URL")
        self._tls_context = tls_context
        handlers = [_NoRedirectHandler()]
        if tls_context is not None:
            from urllib.request import HTTPSHandler

            handlers.append(HTTPSHandler(context=tls_context))
        self._opener = build_opener(*handlers)

    async def health(self) -> dict[str, Any]:
        response = await asyncio.to_thread(self._request, "GET", "/health", None)
        self._expect_fields(response, {"service", "status"})
        return dict(response)

    async def issue(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
        *,
        expires_at: datetime | None = None,
    ) -> CapabilityGrant:
        self._check_descriptor(descriptor, invocation)
        response = await asyncio.to_thread(
            self._request,
            "POST",
            "/v1/capabilities/issue",
            request_to_wire(context, invocation, expires_at=expires_at),
        )
        self._expect_fields(response, {"grant"})
        try:
            return self._validate_grant(
                grant_from_wire(response["grant"]), context, descriptor, invocation
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ToolGatewayError(
                "invalid_gateway_response",
                "The gateway returned an invalid capability grant.",
            ) from exc

    async def authorize(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
    ) -> AuthorizationResult:
        """Inspect without consuming; execution performs the atomic consume."""

        try:
            self._check_descriptor(descriptor, invocation)
            response = await asyncio.to_thread(
                self._request,
                "POST",
                "/v1/capabilities/inspect",
                request_to_wire(context, invocation),
            )
            self._expect_fields(response, {"authorization"})
            result = authorization_from_wire(response["authorization"])
            if result.allowed and not self._authorization_matches(
                result, context, descriptor, invocation
            ):
                return AuthorizationResult(
                    False,
                    "The remote authority returned claims for another request.",
                    "capability_gateway_claim_mismatch",
                )
            return result
        except ToolGatewayError as exc:
            return AuthorizationResult(
                False,
                "The remote capability authority is unavailable or rejected the request.",
                exc.code,
            )
        except (KeyError, TypeError, ValueError):
            return AuthorizationResult(
                False,
                "The remote capability authority returned an invalid response.",
                "capability_gateway_invalid_response",
            )

    async def execute(
        self,
        context: SessionContext,
        invocation: ToolInvocation,
    ) -> Any:
        response = await asyncio.to_thread(
            self._request,
            "POST",
            "/v1/tools/execute",
            request_to_wire(context, invocation),
        )
        self._expect_fields(response, {"result"})
        return response["result"]

    def executor_for(self, context: SessionContext):
        """Return an executor compatible with ``SecuritySession.around_tool``."""

        async def execute(invocation: ToolInvocation) -> Any:
            return await self.execute(context, invocation)

        return execute

    @staticmethod
    def _check_descriptor(
        descriptor: ToolDescriptor, invocation: ToolInvocation
    ) -> None:
        if invocation.tool_name != descriptor.name:
            raise ValueError("invocation does not match the local trusted descriptor")
        if invocation.tool_version not in {None, descriptor.version}:
            raise ValueError("invocation version does not match the local trusted descriptor")

    @staticmethod
    def _validate_grant(
        grant: CapabilityGrant,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
    ) -> CapabilityGrant:
        expected = (
            (grant.subject, context.agent_id),
            (grant.tenant_id, context.tenant_id),
            (grant.session_id, context.session_id),
            (grant.run_id, context.run_id),
            (grant.tool_name, descriptor.name),
            (grant.tool_version, descriptor.version),
            (grant.tool_integrity_digest, descriptor.integrity_digest),
        )
        if any(actual != wanted for actual, wanted in expected) or (
            grant.invocation_digest != invocation_digest(invocation)
        ):
            raise ToolGatewayError(
                "invalid_gateway_response",
                "The gateway returned a capability for a different request.",
            )
        return grant

    @staticmethod
    def _authorization_matches(
        result: AuthorizationResult,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
    ) -> bool:
        expected = {
            "subject": context.agent_id,
            "tenant_id": context.tenant_id,
            "session_id": context.session_id,
            "run_id": context.run_id,
            "tool_name": descriptor.name,
            "tool_version": descriptor.version,
            "tool_integrity_digest": descriptor.integrity_digest,
            "invocation_digest": invocation_digest(invocation),
        }
        return all(result.claims.get(key) == value for key, value in expected.items())

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
            with self._opener.open(request, timeout=self.timeout) as response:
                status = response.status
                raw = self._read_limited(response)
        except HTTPError as exc:
            status = exc.code
            try:
                raw = self._read_limited(exc)
            except ToolGatewayError:
                raw = b""
            finally:
                exc.close()
            self._raise_remote_error(status, raw)
        except (TimeoutError, socket.timeout, URLError, OSError) as exc:
            raise ToolGatewayError(
                "tool_gateway_unavailable",
                "The Tool Security Gateway could not be reached.",
            ) from exc

        if status < 200 or status >= 300:
            self._raise_remote_error(status, raw)
        try:
            decoded = strict_json_loads(raw)
            response_payload = parse_response(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ToolGatewayError(
                "invalid_gateway_response",
                "The gateway returned invalid JSON.",
                status=status,
            ) from exc
        if not response_payload["ok"]:
            self._raise_payload_error(response_payload, status)
        return dict(response_payload)

    @staticmethod
    def _expect_fields(response: dict[str, Any], fields: set[str]) -> None:
        expected = {"protocol", "ok", *fields}
        if set(response) != expected:
            raise ToolGatewayError(
                "invalid_gateway_response",
                "The gateway response contained invalid fields.",
            )

    def _read_limited(self, response) -> bytes:
        raw = response.read(self.max_response_bytes + 1)
        if len(raw) > self.max_response_bytes:
            raise ToolGatewayError(
                "gateway_response_too_large",
                "The gateway response exceeded the configured limit.",
            )
        return raw

    def _raise_remote_error(self, status: int, raw: bytes) -> None:
        try:
            payload = parse_response(strict_json_loads(raw))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ToolGatewayError(
                "tool_gateway_http_error",
                "The Tool Security Gateway rejected the request.",
                status=status,
            )
        self._raise_payload_error(payload, status)

    @staticmethod
    def _raise_payload_error(payload, status: int) -> None:
        error = payload.get("error")
        if not isinstance(error, dict):
            raise ToolGatewayError(
                "invalid_gateway_response",
                "The gateway returned an invalid error response.",
                status=status,
            )
        code = error.get("code")
        message = error.get("message")
        if not isinstance(code, str) or not isinstance(message, str):
            raise ToolGatewayError(
                "invalid_gateway_response",
                "The gateway returned an invalid error response.",
                status=status,
            )
        raise ToolGatewayError(code, message, status=status)


class _NoRedirectHandler(HTTPRedirectHandler):
    """Do not forward gateway credentials to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
