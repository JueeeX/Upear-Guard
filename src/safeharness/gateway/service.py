"""Standard-library reference service for isolated tool execution."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
import logging
import re
import ssl
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from safeharness.api._mapping import json_safe
from safeharness.api.tools import ToolDescriptor, ToolInvocation
from safeharness.backends.gateway import SignedCapabilityGateway, invocation_digest
from safeharness.gateway.protocol import (
    authorization_to_wire,
    error_response,
    grant_to_wire,
    parse_request,
    strict_json_loads,
    success_response,
)
from safeharness.gateway.telemetry import GatewayRequestObservation, GatewayTelemetry
from safeharness.policies._schema import validate_arguments
from safeharness.ports import (
    EnforcementReceiptVerification,
    EnforcementReceiptVerifier,
    GatewayAuditRecord,
    GatewayAuditSink,
)


logger = logging.getLogger(__name__)
_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")


@dataclass(frozen=True, slots=True)
class RegisteredTool:
    """Trusted server-side metadata plus an executor hidden from Agent hosts."""

    descriptor: ToolDescriptor
    executor: Callable[..., Any]
    resource_resolver: Callable[[Mapping[str, Any]], str | None] | None = None

    def __post_init__(self) -> None:
        if not callable(self.executor):
            raise TypeError("registered tool executor must be callable")
        if self.resource_resolver is not None and not callable(self.resource_resolver):
            raise TypeError("registered tool resource_resolver must be callable")


class ToolRegistry:
    """Versioned, fail-closed tool registry owned by the gateway service."""

    def __init__(self, tools: Iterable[RegisteredTool] = ()) -> None:
        self._tools: dict[tuple[str, str], RegisteredTool] = {}
        for tool in tools:
            key = (tool.descriptor.name, tool.descriptor.version)
            if key in self._tools:
                raise ValueError(f"duplicate gateway tool: {key[0]}@{key[1]}")
            self._tools[key] = tool

    def resolve(self, invocation: ToolInvocation) -> RegisteredTool | None:
        if invocation.tool_version is not None:
            return self._tools.get((invocation.tool_name, invocation.tool_version))
        matches = [
            tool
            for (name, _), tool in self._tools.items()
            if name == invocation.tool_name
        ]
        return matches[0] if len(matches) == 1 else None


class ToolGatewayApplication:
    """Protocol handler independent of the concrete HTTP server."""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        capability_gateway: SignedCapabilityGateway,
        audit_sink: GatewayAuditSink | None = None,
        readiness_checks: Iterable[Callable[[], Any]] = (),
        enforcement_receipt_verifier: EnforcementReceiptVerifier | None = None,
        require_enforcement_receipt: bool = False,
        workload_identity: str | None = None,
    ) -> None:
        self.registry = registry
        self.capability_gateway = capability_gateway
        self.audit_sink = audit_sink
        self.readiness_checks = tuple(readiness_checks)
        if require_enforcement_receipt and enforcement_receipt_verifier is None:
            raise ValueError(
                "a receipt verifier is required when enforcement receipts are mandatory"
            )
        self.enforcement_receipt_verifier = enforcement_receipt_verifier
        self.require_enforcement_receipt = bool(require_enforcement_receipt)
        self.workload_identity = workload_identity

    async def health(self) -> tuple[int, dict[str, Any]]:
        try:
            for check in self.readiness_checks:
                result = check()
                result = await result if inspect.isawaitable(result) else result
                if not result:
                    return _gateway_not_ready()
        except Exception as exc:
            _log_backend_failure("Gateway dependency readiness check failed", exc)
            return _gateway_not_ready()
        return HTTPStatus.OK, success_response(
            service="safeharness-tool-gateway",
            status="ready",
        )

    async def issue(
        self, payload: Any, *, request_id: str = ""
    ) -> tuple[int, dict[str, Any]]:
        context = invocation = tool = None
        try:
            context, invocation, expiry = parse_request(payload, allow_expiry=True)
            if invocation.capability_token is not None:
                raise ValueError("issuance requests must not contain a capability token")
            tool, invocation = self._canonicalize(invocation)
            grant = await self.capability_gateway.issue(
                context,
                tool.descriptor,
                invocation,
                expires_at=expiry,
            )
        except PermissionError:
            persisted = await self._audit_safely(
                "capability_issue",
                "denied",
                failure_log="Gateway audit persistence failed for capability denial",
                context=context,
                invocation=invocation,
                tool=tool,
                reason_code="capability_not_granted",
                request_id=request_id,
            )
            if not persisted:
                return _gateway_audit_unavailable()
            return _error(
                HTTPStatus.FORBIDDEN,
                "capability_not_granted",
                "The subject is not authorized for this tool.",
            )
        except ValueError:
            persisted = await self._audit_safely(
                "capability_issue",
                "rejected",
                failure_log="Gateway audit persistence failed for rejected capability",
                context=context,
                invocation=invocation,
                tool=tool,
                reason_code="invalid_request",
                request_id=request_id,
            )
            if not persisted:
                return _gateway_audit_unavailable()
            return _error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "The capability request is invalid.",
            )
        except Exception as exc:
            _log_backend_failure("Capability issuance failed", exc)
            persisted = await self._audit_safely(
                "capability_issue",
                "failed",
                failure_log="Gateway audit persistence failed for capability error",
                context=context,
                invocation=invocation,
                tool=tool,
                reason_code="capability_service_unavailable",
                request_id=request_id,
            )
            if not persisted:
                return _gateway_audit_unavailable()
            return _error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "capability_service_unavailable",
                "The capability service is unavailable.",
            )
        persisted = await self._audit_safely(
            "capability_issue",
            "issued",
            failure_log="Gateway audit persistence failed before capability response",
            context=context,
            invocation=invocation,
            tool=tool,
            capability_token_id=grant.token_id,
            request_id=request_id,
        )
        if not persisted:
            return _gateway_audit_unavailable()
        return HTTPStatus.OK, success_response(grant=grant_to_wire(grant))

    async def inspect(
        self, payload: Any, *, request_id: str = ""
    ) -> tuple[int, dict[str, Any]]:
        context = invocation = tool = None
        try:
            context, invocation, _ = parse_request(payload)
            tool, invocation = self._canonicalize(invocation)
            result = await self.capability_gateway.inspect(
                context, tool.descriptor, invocation
            )
        except ValueError:
            persisted = await self._audit_safely(
                "capability_inspect",
                "rejected",
                failure_log="Gateway audit persistence failed for rejected inspection",
                context=context,
                invocation=invocation,
                tool=tool,
                reason_code="invalid_request",
                request_id=request_id,
            )
            if not persisted:
                return _gateway_audit_unavailable()
            return _error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "The capability inspection request is invalid.",
            )
        except Exception as exc:
            _log_backend_failure("Capability inspection failed", exc)
            persisted = await self._audit_safely(
                "capability_inspect",
                "failed",
                failure_log="Gateway audit persistence failed for inspection error",
                context=context,
                invocation=invocation,
                tool=tool,
                reason_code="capability_service_unavailable",
                request_id=request_id,
            )
            if not persisted:
                return _gateway_audit_unavailable()
            return _error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "capability_service_unavailable",
                "The capability service is unavailable.",
            )
        persisted = await self._audit_safely(
            "capability_inspect",
            "allowed" if result.allowed else "denied",
            failure_log="Gateway audit persistence failed before inspection response",
            context=context,
            invocation=invocation,
            tool=tool,
            capability_token_id=str(result.claims.get("capability_token_id", "")),
            reason_code="" if result.allowed else result.reason_code,
            request_id=request_id,
        )
        if not persisted:
            return _gateway_audit_unavailable()
        return HTTPStatus.OK, success_response(
            authorization=authorization_to_wire(result)
        )

    async def execute(
        self, payload: Any, *, request_id: str = ""
    ) -> tuple[int, dict[str, Any]]:
        context = invocation = tool = None
        try:
            context, invocation, _ = parse_request(payload)
            tool, invocation = self._canonicalize(invocation)
        except ValueError:
            persisted = await self._audit_safely(
                "tool_execute",
                "rejected",
                failure_log="Gateway audit persistence failed for rejected execution",
                context=context,
                invocation=invocation,
                tool=tool,
                reason_code="invalid_request",
                request_id=request_id,
            )
            if not persisted:
                return _gateway_audit_unavailable()
            return _error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "The tool execution request is invalid.",
            )

        # Validate both proofs before consuming either one. This prevents an
        # otherwise invalid capability from burning a legitimate receipt.
        receipt_result = None
        if self.require_enforcement_receipt or invocation.enforcement_receipt:
            verifier = self.enforcement_receipt_verifier
            if verifier is None:
                receipt_result = _receipt_denial(
                    "enforcement_receipt_invalid",
                    "The gateway has no enforcement receipt verifier.",
                )
            else:
                try:
                    receipt_result = await verifier.verify(
                        context,
                        tool.descriptor,
                        invocation,
                        invocation.enforcement_receipt,
                        consume=False,
                        workload_id=self.workload_identity,
                    )
                except Exception as exc:
                    _log_backend_failure("Enforcement receipt verification failed", exc)
                    receipt_result = _receipt_denial(
                        "enforcement_receipt_invalid",
                        "The enforcement receipt could not be verified.",
                    )
            if not receipt_result.allowed:
                return await self._receipt_denied(
                    receipt_result,
                    context=context,
                    invocation=invocation,
                    tool=tool,
                    request_id=request_id,
                )

        try:
            authorization = await self.capability_gateway.inspect(
                context, tool.descriptor, invocation
            )
        except Exception as exc:
            _log_backend_failure("Capability verification failed", exc)
            persisted = await self._audit_safely(
                "tool_execute",
                "failed",
                failure_log="Gateway audit persistence failed for capability error",
                context=context,
                invocation=invocation,
                tool=tool,
                reason_code="capability_service_unavailable",
                request_id=request_id,
            )
            if not persisted:
                return _gateway_audit_unavailable()
            return _error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "capability_service_unavailable",
                "The capability service is unavailable.",
            )
        if not authorization.allowed:
            persisted = await self._audit_safely(
                "tool_execute",
                "denied",
                failure_log="Gateway audit persistence failed for denial",
                context=context,
                invocation=invocation,
                tool=tool,
                reason_code=authorization.reason_code,
                request_id=request_id,
            )
            if not persisted:
                return _gateway_audit_unavailable()
            if authorization.reason_code == "capability_token_replay_store_failed":
                return _error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "capability_replay_store_unavailable",
                    "Replay protection is unavailable; no tool was dispatched.",
                )
            return _error(
                HTTPStatus.FORBIDDEN,
                authorization.reason_code,
                authorization.reason or "The capability was denied.",
            )

        if receipt_result is not None:
            verifier = self.enforcement_receipt_verifier
            try:
                receipt_result = await verifier.verify(
                    context,
                    tool.descriptor,
                    invocation,
                    invocation.enforcement_receipt,
                    consume=True,
                    workload_id=self.workload_identity,
                )
            except Exception as exc:
                _log_backend_failure("Enforcement receipt consumption failed", exc)
                receipt_result = _receipt_denial(
                    "enforcement_receipt_store_unavailable",
                    "Enforcement receipt replay protection is unavailable.",
                )
            if not receipt_result.allowed:
                return await self._receipt_denied(
                    receipt_result,
                    context=context,
                    invocation=invocation,
                    tool=tool,
                    request_id=request_id,
                )

        try:
            authorization = await self.capability_gateway.authorize(
                context, tool.descriptor, invocation
            )
        except Exception as exc:
            _log_backend_failure("Capability consumption failed", exc)
            authorization = None
        if authorization is None:
            persisted = await self._audit_safely(
                "tool_execute",
                "failed",
                failure_log="Gateway audit persistence failed for capability error",
                context=context,
                invocation=invocation,
                tool=tool,
                reason_code="capability_service_unavailable",
                request_id=request_id,
            )
            if not persisted:
                return _gateway_audit_unavailable()
            return _error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "capability_service_unavailable",
                "The capability service is unavailable.",
            )
        if not authorization.allowed:
            persisted = await self._audit_safely(
                "tool_execute",
                "denied",
                failure_log="Gateway audit persistence failed for consumption denial",
                context=context,
                invocation=invocation,
                tool=tool,
                reason_code=authorization.reason_code,
                request_id=request_id,
            )
            if not persisted:
                return _gateway_audit_unavailable()
            if authorization.reason_code == "capability_token_replay_store_failed":
                return _error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "capability_replay_store_unavailable",
                    "Replay protection is unavailable; no tool was dispatched.",
                )
            return _error(
                HTTPStatus.FORBIDDEN,
                authorization.reason_code,
                authorization.reason or "The capability was denied.",
            )

        persisted = await self._audit_safely(
            "tool_execute",
            "dispatched",
            failure_log="Gateway audit persistence failed before tool dispatch",
            context=context,
            invocation=invocation,
            tool=tool,
            capability_token_id=str(
                authorization.claims.get("capability_token_id", "")
            ),
            request_id=request_id,
            details={
                "enforcement_receipt_fingerprint": _fingerprint(
                    invocation.enforcement_receipt or ""
                )
            },
        )
        if not persisted:
            return _gateway_audit_unavailable()

        try:
            value = tool.executor(**dict(invocation.arguments))
            result = await value if inspect.isawaitable(value) else value
            safe_result = json_safe(result)
            json.dumps(safe_result, ensure_ascii=True, allow_nan=False)
        except Exception as exc:
            logger.warning(
                "Gateway tool execution failed for %s (%s)",
                tool.descriptor.name,
                type(exc).__name__,
            )
            persisted = await self._audit_safely(
                "tool_execute",
                "failed",
                failure_log="Gateway audit persistence failed after tool failure",
                context=context,
                invocation=invocation,
                tool=tool,
                capability_token_id=str(
                    authorization.claims.get("capability_token_id", "")
                ),
                reason_code="tool_execution_failed",
                request_id=request_id,
                details={"exception_type": type(exc).__name__},
            )
            if not persisted:
                return _gateway_audit_commit_failed()
            return _error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "tool_execution_failed",
                "The registered tool failed during execution.",
            )
        persisted = await self._audit_safely(
            "tool_execute",
            "succeeded",
            failure_log="Gateway audit persistence failed after tool success",
            context=context,
            invocation=invocation,
            tool=tool,
            capability_token_id=str(
                authorization.claims.get("capability_token_id", "")
            ),
            request_id=request_id,
        )
        if not persisted:
            return _gateway_audit_commit_failed()
        return HTTPStatus.OK, success_response(result=safe_result)

    async def _receipt_denied(
        self,
        result: EnforcementReceiptVerification,
        *,
        context,
        invocation,
        tool,
        request_id: str,
    ) -> tuple[int, dict[str, Any]]:
        persisted = await self._audit_safely(
            "tool_execute",
            "denied",
            failure_log="Gateway audit persistence failed for receipt denial",
            context=context,
            invocation=invocation,
            tool=tool,
            reason_code=result.reason_code,
            request_id=request_id,
            details={
                "enforcement_receipt_fingerprint": _fingerprint(
                    invocation.enforcement_receipt or ""
                )
            },
        )
        if not persisted:
            return _gateway_audit_unavailable()
        status = (
            HTTPStatus.SERVICE_UNAVAILABLE
            if result.reason_code == "enforcement_receipt_store_unavailable"
            else HTTPStatus.FORBIDDEN
        )
        return _error(status, result.reason_code, result.reason)

    async def _audit_safely(
        self,
        action: str,
        outcome: str,
        *,
        failure_log: str,
        **fields: Any,
    ) -> bool:
        try:
            await self._audit(action, outcome, **fields)
        except Exception as exc:
            _log_backend_failure(failure_log, exc)
            return False
        return True

    async def _audit(
        self,
        action: str,
        outcome: str,
        *,
        context=None,
        invocation=None,
        tool=None,
        capability_token_id: str = "",
        reason_code: str = "",
        request_id: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        if self.audit_sink is None:
            return
        descriptor = tool.descriptor if tool is not None else None
        await self.audit_sink.write_gateway(
            GatewayAuditRecord(
                action=action,
                outcome=outcome,
                tenant_id=context.tenant_id if context is not None else "",
                agent_id=context.agent_id if context is not None else "",
                session_id=context.session_id if context is not None else "",
                run_id=context.run_id if context is not None else "",
                trace_id=context.trace_id if context is not None else "",
                tool_name=(
                    descriptor.name
                    if descriptor is not None
                    else invocation.tool_name if invocation is not None else ""
                ),
                tool_version=(
                    descriptor.version
                    if descriptor is not None
                    else (invocation.tool_version or "")
                    if invocation is not None
                    else ""
                ),
                tool_integrity_digest=(
                    descriptor.integrity_digest if descriptor is not None else ""
                ),
                invocation_digest=(
                    invocation_digest(invocation) if invocation is not None else ""
                ),
                capability_fingerprint=_fingerprint(capability_token_id),
                reason_code=reason_code,
                request_id=request_id,
                details=details or {},
            )
        )

    def _canonicalize(
        self, invocation: ToolInvocation
    ) -> tuple[RegisteredTool, ToolInvocation]:
        if invocation.tool_version is None:
            raise ValueError("gateway invocations require an exact tool version")
        tool = self.registry.resolve(invocation)
        if tool is None:
            raise ValueError("unknown or ambiguous tool")
        descriptor = tool.descriptor
        schema_errors = validate_arguments(invocation.arguments, descriptor.input_schema)
        if schema_errors:
            raise ValueError("arguments do not satisfy the server-side schema")
        resource = (
            tool.resource_resolver(invocation.arguments)
            if tool.resource_resolver is not None
            else None
        )
        canonical_resource = str(resource) if resource is not None else None
        if invocation.resource != canonical_resource:
            raise ValueError("resource does not match the server-side resolver")
        return tool, ToolInvocation(
            tool_name=descriptor.name,
            arguments=invocation.arguments,
            call_id=invocation.call_id,
            tool_version=descriptor.version,
            resource=canonical_resource,
                capability_token=invocation.capability_token,
                intent_digest=invocation.intent_digest,
                enforcement_receipt=invocation.enforcement_receipt,
            )


class ToolGatewayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        application: ToolGatewayApplication,
        *,
        api_keys: Mapping[tuple[str, str], str],
        max_request_bytes: int = 1024 * 1024,
        telemetry: GatewayTelemetry | None = None,
        require_mtls_identity: bool = False,
    ) -> None:
        normalized_keys = {
            (str(principal[0]), str(principal[1])): str(api_key)
            for principal, api_key in api_keys.items()
        }
        if not normalized_keys or any(
            not tenant_id or not agent_id or len(api_key) < 32
            for (tenant_id, agent_id), api_key in normalized_keys.items()
        ):
            raise ValueError(
                "api_keys must bind each tenant/Agent identity to at least "
                "32 characters"
            )
        if len(set(normalized_keys.values())) != len(normalized_keys):
            raise ValueError("each gateway principal must use a unique API key")
        if max_request_bytes <= 0:
            raise ValueError("max_request_bytes must be positive")
        self.application = application
        self.api_keys = normalized_keys
        self.max_request_bytes = int(max_request_bytes)
        self.telemetry = telemetry
        self.require_mtls_identity = bool(require_mtls_identity)
        super().__init__(server_address, ToolGatewayRequestHandler)

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            if self.telemetry is not None:
                try:
                    self.telemetry.shutdown()
                except Exception as exc:
                    _log_backend_failure("Gateway telemetry shutdown failed", exc)


class ToolGatewayRequestHandler(BaseHTTPRequestHandler):
    server: ToolGatewayHTTPServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._request_started_ns = time.time_ns()
        if self._route_path() != "/health":
            self._write(*_error(HTTPStatus.NOT_FOUND, "not_found", "Endpoint not found."))
            return
        if self._authenticated_principal() is None:
            self._write(
                *_error(
                    HTTPStatus.UNAUTHORIZED,
                    "unauthorized",
                    "A valid gateway API key is required.",
                )
            )
            return
        if self.server.require_mtls_identity and self._tls_workload_identity() is None:
            self._write(
                *_error(
                    HTTPStatus.UNAUTHORIZED,
                    "mtls_identity_required",
                    "A verified client certificate workload identity is required.",
                )
            )
            return
        try:
            status, response = asyncio.run(self.server.application.health())
        except Exception as exc:
            _log_backend_failure("Unhandled gateway readiness failure", exc)
            status, response = _gateway_not_ready()
        self._write(status, response)

    def do_POST(self) -> None:
        self._request_started_ns = time.time_ns()
        route_path = self._route_path()
        authenticated_principal = self._authenticated_principal()
        if authenticated_principal is None:
            self._write(
                *_error(
                    HTTPStatus.UNAUTHORIZED,
                    "unauthorized",
                    "A valid gateway API key is required.",
                )
            )
            return
        workload_identity = self._tls_workload_identity()
        if self.server.require_mtls_identity and workload_identity is None:
            self._write(
                *_error(
                    HTTPStatus.UNAUTHORIZED,
                    "mtls_identity_required",
                    "A verified client certificate workload identity is required.",
                )
            )
            return
        expected_workload = self.server.application.workload_identity
        if self.server.require_mtls_identity and not expected_workload:
            self._write(
                *_error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "mtls_identity_unconfigured",
                    "The gateway workload identity policy is not configured.",
                )
            )
            return
        routes = {
            "/v1/capabilities/issue": self.server.application.issue,
            "/v1/capabilities/inspect": self.server.application.inspect,
            "/v1/tools/execute": self.server.application.execute,
        }
        handler = routes.get(route_path)
        if handler is None:
            self._write(*_error(HTTPStatus.NOT_FOUND, "not_found", "Endpoint not found."))
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != (
            "application/json"
        ):
            self._write(
                *_error(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                    "content_type_required",
                    "Content-Type must be application/json.",
                )
            )
            return
        payload = self._read_json()
        if payload is None:
            return
        try:
            context, _, _ = parse_request(
                payload,
                allow_expiry=route_path == "/v1/capabilities/issue",
            )
        except ValueError:
            self._write(
                *_error(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    "The gateway request is invalid.",
                )
            )
            return
        if (context.tenant_id, context.agent_id) != authenticated_principal:
            self._write(
                *_error(
                    HTTPStatus.FORBIDDEN,
                    "authenticated_principal_mismatch",
                    "The authenticated identity cannot act as this tenant/Agent.",
                )
            )
            return
        try:
            if workload_identity is not None and route_path == "/v1/tools/execute":
                if not hmac.compare_digest(
                    expected_workload or "", workload_identity
                ):
                    self._write(
                        *_error(
                            HTTPStatus.FORBIDDEN,
                            "mtls_identity_mismatch",
                            "The client certificate is not authorized for this workload.",
                        )
                    )
                    return
            status, response = asyncio.run(handler(payload, request_id=self._request_id()))
        except Exception as exc:
            _log_backend_failure("Unhandled gateway request failure", exc)
            status, response = _error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "The gateway could not process the request.",
            )
        self._write(status, response)

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def log_message(self, format: str, *args: Any) -> None:
        logger.info(
            "Tool gateway HTTP: method=%s route=%s",
            self.command if self.command in {"GET", "POST"} else "OTHER",
            self._telemetry_route(),
        )

    def _authenticated_principal(self) -> tuple[str, str] | None:
        authorization = self.headers.get("Authorization", "")
        scheme, separator, supplied = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer":
            supplied = ""
        supplied_bytes = supplied.encode("utf-8")
        matched_principal = None
        for principal, api_key in self.server.api_keys.items():
            if hmac.compare_digest(supplied_bytes, api_key.encode("utf-8")):
                matched_principal = principal
        return matched_principal

    def _tls_workload_identity(self) -> str | None:
        """Return a SPIFFE URI SAN only from the verified TLS peer certificate."""

        peer = getattr(self.connection, "getpeercert", None)
        if peer is None:
            return None
        try:
            certificate = peer()
        except (OSError, ssl.SSLError):
            return None
        if not isinstance(certificate, Mapping):
            return None
        identities = [
            str(value)
            for kind, value in certificate.get("subjectAltName", ())
            if kind == "URI" and isinstance(value, str) and value.startswith("spiffe://")
        ]
        return identities[0] if len(identities) == 1 else None

    def _read_json(self) -> Any | None:
        transfer_encoding = self.headers.get("Transfer-Encoding")
        if transfer_encoding:
            self._write(
                *_error(
                    HTTPStatus.BAD_REQUEST,
                    "unsupported_transfer_encoding",
                    "Chunked request bodies are not accepted.",
                )
            )
            return None
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            self._write(
                *_error(
                    HTTPStatus.LENGTH_REQUIRED,
                    "content_length_required",
                    "A valid Content-Length header is required.",
                )
            )
            return None
        if length > self.server.max_request_bytes:
            self._write(
                *_error(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "request_too_large",
                    "The request body exceeds the configured limit.",
                )
            )
            return None
        raw = self.rfile.read(length)
        try:
            return strict_json_loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._write(
                *_error(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_json",
                    "The request body must contain valid UTF-8 JSON.",
                )
            )
            return None

    def _write(self, status: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True
        finally:
            self._record_telemetry(int(status), payload)

    def _method_not_allowed(self) -> None:
        self._request_started_ns = time.time_ns()
        self._write(
            *_error(
                HTTPStatus.METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "The HTTP method is not supported.",
            )
        )

    def _route_path(self) -> str:
        return self.path.split("?", 1)[0]

    def _request_id(self) -> str:
        supplied = self.headers.get("X-Request-ID", "")
        return supplied if _REQUEST_ID.fullmatch(supplied) else ""

    def _record_telemetry(self, status: int, payload: Mapping[str, Any]) -> None:
        telemetry = self.server.telemetry
        if telemetry is None:
            return
        error = payload.get("error")
        error_code = error.get("code", "") if isinstance(error, Mapping) else ""
        try:
            telemetry.record_request(
                GatewayRequestObservation(
                    method=self.command if self.command in {"GET", "POST"} else "OTHER",
                    route=self._telemetry_route(),
                    status_code=status,
                    error_code=str(error_code),
                    started_ns=getattr(self, "_request_started_ns", time.time_ns()),
                    ended_ns=time.time_ns(),
                )
            )
        except Exception as exc:
            _log_backend_failure("Gateway telemetry export failed", exc)

    def _telemetry_route(self) -> str:
        path = self._route_path()
        known = {
            "/health",
            "/v1/capabilities/issue",
            "/v1/capabilities/inspect",
            "/v1/tools/execute",
        }
        return path if path in known else "unmatched"


def create_gateway_server(
    application: ToolGatewayApplication,
    *,
    host: str = "127.0.0.1",
    port: int = 38100,
    api_key: str | None = None,
    api_keys: Mapping[tuple[str, str], str] | None = None,
    tenant_id: str = "tenant",
    agent_id: str = "agent",
    max_request_bytes: int = 1024 * 1024,
    telemetry: GatewayTelemetry | None = None,
    tls_context: ssl.SSLContext | None = None,
    require_mtls_identity: bool = False,
) -> ToolGatewayHTTPServer:
    if (api_key is None) == (api_keys is None):
        raise ValueError("provide exactly one api_key or api_keys mapping")
    key_mapping = (
        dict(api_keys)
        if api_keys is not None
        else {(tenant_id, agent_id): api_key or ""}
    )
    if require_mtls_identity and (
        tls_context is None or tls_context.verify_mode != ssl.CERT_REQUIRED
    ):
        raise ValueError("strict mTLS identity requires a CERT_REQUIRED TLS context")
    if require_mtls_identity and not application.workload_identity:
        raise ValueError("strict mTLS identity requires an expected workload identity")
    server = ToolGatewayHTTPServer(
        (host, port),
        application,
        api_keys=key_mapping,
        max_request_bytes=max_request_bytes,
        telemetry=telemetry,
        require_mtls_identity=require_mtls_identity,
    )
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server


def create_server_tls_context(
    *,
    certificate: str,
    private_key: str,
    client_ca: str | None = None,
    require_client_certificate: bool = False,
) -> ssl.SSLContext:
    """Build a TLS 1.2+ server context with optional mandatory client auth."""

    if require_client_certificate and not client_ca:
        raise ValueError("client_ca is required for mTLS client authentication")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    if client_ca:
        context.load_verify_locations(cafile=client_ca)
        context.verify_mode = (
            ssl.CERT_REQUIRED if require_client_certificate else ssl.CERT_OPTIONAL
        )
    else:
        context.verify_mode = ssl.CERT_NONE
    return context


def _error(status: int, code: str, message: str) -> tuple[int, dict[str, Any]]:
    return int(status), error_response(code, message)


def _gateway_audit_unavailable() -> tuple[int, dict[str, Any]]:
    return _error(
        HTTPStatus.SERVICE_UNAVAILABLE,
        "gateway_audit_unavailable",
        "The gateway audit service is unavailable; no tool was dispatched.",
    )


def _gateway_audit_commit_failed() -> tuple[int, dict[str, Any]]:
    return _error(
        HTTPStatus.INTERNAL_SERVER_ERROR,
        "gateway_audit_commit_failed",
        "The tool may have changed external state, but its terminal audit could not "
        "be persisted; the operation must not be retried automatically.",
    )


def _gateway_not_ready() -> tuple[int, dict[str, Any]]:
    return _error(
        HTTPStatus.SERVICE_UNAVAILABLE,
        "gateway_not_ready",
        "The Tool Security Gateway is not ready.",
    )


def _fingerprint(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _receipt_denial(code: str, reason: str) -> EnforcementReceiptVerification:
    return EnforcementReceiptVerification(False, reason=reason, reason_code=code)


def _log_backend_failure(message: str, exc: Exception) -> None:
    logger.error("%s (%s)", message, type(exc).__name__)
