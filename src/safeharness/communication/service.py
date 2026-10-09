"""Authenticated Agent Communication Gateway application and HTTP service."""

from __future__ import annotations

import asyncio
import hmac
import inspect
import json
import logging
import re
import ssl
import time
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from safeharness.communication.control import CoordinationControlPlane
from safeharness.communication.admin import CoordinationAdminApplication
from safeharness.communication.inspection import (
    InterAgentMessageInspector,
    SafeHarnessInterAgentInspector,
)
from safeharness.communication.models import (
    CommunicationAuditRecord,
    InterAgentMessage,
    MessageLease,
    fingerprint_identifier,
)
from safeharness.communication.protocol import (
    error_response,
    lease_to_wire,
    parse_ack_request,
    parse_receive_request,
    parse_send_request,
    store_result_to_wire,
    strict_json_loads,
    success_response,
)
from safeharness.communication.store import CommunicationStore
from safeharness.communication.persistence import PersistentCoordinationControlPlane
from safeharness.communication.rate_limit import CommunicationRateLimiter
from safeharness.gateway.telemetry import GatewayRequestObservation, GatewayTelemetry


logger = logging.getLogger(__name__)
_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_ADMIN_ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")


class AgentCommunicationApplication:
    """Protocol handler with identity, topology, inspection, and state enforcement."""

    def __init__(
        self,
        *,
        control_plane: CoordinationControlPlane,
        store: CommunicationStore,
        inspector: InterAgentMessageInspector | None = None,
        max_clock_skew: timedelta = timedelta(seconds=30),
        max_message_ttl: timedelta = timedelta(minutes=10),
        readiness_checks=(),
        now=None,
    ) -> None:
        if max_clock_skew < timedelta(0) or max_clock_skew > timedelta(minutes=5):
            raise ValueError("max_clock_skew must be between 0 and 300 seconds")
        if not timedelta(seconds=1) <= max_message_ttl <= timedelta(hours=24):
            raise ValueError("max_message_ttl must be between 1 second and 24 hours")
        self.control_plane = control_plane
        self.store = store
        self.inspector = inspector or SafeHarnessInterAgentInspector()
        self.admin = (
            CoordinationAdminApplication(control_plane)
            if isinstance(control_plane, PersistentCoordinationControlPlane)
            else None
        )
        self.max_clock_skew = max_clock_skew
        self.max_message_ttl = max_message_ttl
        self.readiness_checks = tuple(readiness_checks)
        self._now = now or (lambda: datetime.now(timezone.utc))

    async def health(self) -> tuple[int, dict[str, Any]]:
        try:
            if not await self.store.health():
                return _communication_not_ready()
            state_store = getattr(self.control_plane, "state_store", None)
            if state_store is not None and not state_store.health():
                return _communication_not_ready()
            for check in self.readiness_checks:
                result = check()
                result = await result if inspect.isawaitable(result) else result
                if not result:
                    return _communication_not_ready()
        except Exception as exc:
            _log_failure("Communication gateway readiness check failed", exc)
            return _communication_not_ready()
        return HTTPStatus.OK, success_response(
            service="safeharness-agent-communication-gateway",
            status="ready",
        )

    async def send(
        self,
        payload: Any,
        *,
        principal: tuple[str, str],
        request_id: str = "",
    ) -> tuple[int, dict[str, Any]]:
        tenant_id, agent_id = _principal(principal)
        try:
            message = parse_send_request(payload)
        except (TypeError, ValueError):
            return await self._audited_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "The communication request is invalid.",
                self._generic_audit(
                    action="message_send",
                    outcome="rejected",
                    tenant_id=tenant_id,
                    sender_agent_id=agent_id,
                    reason_code="invalid_request",
                    request_id=request_id,
                ),
            )

        if (message.tenant_id, message.sender_agent_id) != principal:
            return await self._audited_error(
                HTTPStatus.FORBIDDEN,
                "authenticated_principal_mismatch",
                "The authenticated identity cannot send as this tenant/Agent.",
                self._message_audit(
                    message,
                    action="message_send",
                    outcome="denied",
                    reason_code="authenticated_principal_mismatch",
                    request_id=request_id,
                    principal=principal,
                ),
            )

        timing_error = self._validate_message_time(message)
        if timing_error is not None:
            code, reason = timing_error
            return await self._audited_error(
                HTTPStatus.BAD_REQUEST,
                code,
                reason,
                self._message_audit(
                    message,
                    action="message_send",
                    outcome="rejected",
                    reason_code=code,
                    request_id=request_id,
                    principal=principal,
                ),
            )

        try:
            authorization = self.control_plane.authorize_sender(message)
        except Exception as exc:
            _log_failure("Communication authorization failed", exc)
            return await self._audited_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "communication_policy_unavailable",
                "The communication policy service is unavailable.",
                self._message_audit(
                    message,
                    action="message_send",
                    outcome="failed",
                    reason_code="communication_policy_unavailable",
                    request_id=request_id,
                    principal=principal,
                ),
            )
        if not authorization.allowed:
            return await self._audited_error(
                HTTPStatus.FORBIDDEN,
                authorization.reason_code,
                authorization.reason,
                self._message_audit(
                    message,
                    action="message_send",
                    outcome="denied",
                    reason_code=authorization.reason_code,
                    request_id=request_id,
                    principal=principal,
                ),
            )

        try:
            inspection = await self.inspector.inspect(message)
        except Exception as exc:
            _log_failure("Inter-Agent message inspection failed", exc)
            return await self._audited_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "communication_inspection_unavailable",
                "The communication inspection service is unavailable.",
                self._message_audit(
                    message,
                    action="message_send",
                    outcome="failed",
                    reason_code="communication_inspection_unavailable",
                    request_id=request_id,
                    principal=principal,
                ),
            )
        if not inspection.allowed:
            reason_code = inspection.reason_code or "communication_content_denied"
            return await self._audited_error(
                HTTPStatus.FORBIDDEN,
                reason_code,
                "The inter-Agent message content was denied by policy.",
                self._message_audit(
                    message,
                    action="message_send",
                    outcome="denied",
                    reason_code=reason_code,
                    request_id=request_id,
                    principal=principal,
                    details={"inspection_modified": inspection.modified},
                ),
            )

        inspected_message = message.with_inspected_content(
            inspection.content,
            provenance=inspection.provenance,
        )
        audit = self._message_audit(
            inspected_message,
            action="message_send",
            outcome="enqueued",
            reason_code="",
            request_id=request_id,
            principal=principal,
            details={
                "inspected": True,
                "inspection_modified": inspection.modified,
            },
        )
        try:
            result = await self.store.enqueue(
                inspected_message,
                audit,
                delegation_max_messages=authorization.delegation_max_messages,
            )
        except Exception as exc:
            _log_failure("Communication state transaction failed", exc)
            return _communication_state_unavailable()
        if not result.allowed:
            status = (
                HTTPStatus.CONFLICT
                if result.reason_code
                in {
                    "communication_message_replayed",
                    "delegation_message_limit_exceeded",
                }
                else HTTPStatus.FORBIDDEN
            )
            return _error(status, result.reason_code, result.reason)
        return HTTPStatus.ACCEPTED, success_response(
            result=store_result_to_wire(result)
        )

    async def receive(
        self,
        payload: Any,
        *,
        principal: tuple[str, str],
        request_id: str = "",
    ) -> tuple[int, dict[str, Any]]:
        tenant_id, agent_id = _principal(principal)
        try:
            limit, lease_duration = parse_receive_request(payload)
        except (TypeError, ValueError):
            return await self._audited_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "The message receive request is invalid.",
                self._generic_audit(
                    action="message_receive",
                    outcome="rejected",
                    tenant_id=tenant_id,
                    recipient_agent_id=agent_id,
                    reason_code="invalid_request",
                    request_id=request_id,
                ),
            )

        try:
            authorization = self.control_plane.authorize_recipient(tenant_id, agent_id)
        except Exception as exc:
            _log_failure("Communication recipient authorization failed", exc)
            return _communication_state_unavailable()
        if not authorization.allowed:
            return await self._audited_error(
                HTTPStatus.FORBIDDEN,
                authorization.reason_code,
                authorization.reason,
                self._generic_audit(
                    action="message_receive",
                    outcome="denied",
                    tenant_id=tenant_id,
                    recipient_agent_id=agent_id,
                    reason_code=authorization.reason_code,
                    request_id=request_id,
                ),
            )

        try:
            leases = await self.store.lease_messages(
                tenant_id,
                agent_id,
                limit=limit,
                lease_duration=lease_duration,
                request_id=request_id,
            )
        except Exception as exc:
            _log_failure("Communication mailbox lease failed", exc)
            return _communication_state_unavailable()

        deliverable: list[MessageLease] = []
        blocked_count = 0
        for lease in leases:
            try:
                inspection = await self.inspector.inspect(lease.message)
            except Exception as exc:
                _log_failure("Leased message inspection failed", exc)
                return _error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "communication_inspection_unavailable",
                    "The communication inspection service is unavailable.",
                )
            if not inspection.allowed:
                reason_code = inspection.reason_code or "communication_content_denied"
                persisted = await self._append_audit(
                    self._message_audit(
                        lease.message,
                        action="message_receive_inspection",
                        outcome="denied",
                        reason_code=reason_code,
                        request_id=request_id,
                        details={"delivery_attempt": lease.delivery_attempt},
                    )
                )
                if not persisted:
                    return _communication_state_unavailable()
                try:
                    acknowledged = await self.store.acknowledge(
                        tenant_id,
                        agent_id,
                        lease.message.message_id,
                        lease.lease_id,
                        request_id=request_id,
                    )
                except Exception as exc:
                    _log_failure("Blocked message acknowledgement failed", exc)
                    return _communication_state_unavailable()
                if not acknowledged.allowed:
                    return _communication_state_unavailable()
                blocked_count += 1
                continue
            inspected_message = lease.message.with_inspected_content(
                inspection.content,
                provenance=inspection.provenance,
            )
            deliverable.append(replace(lease, message=inspected_message))

        return HTTPStatus.OK, success_response(
            leases=[lease_to_wire(lease) for lease in deliverable],
            blocked_count=blocked_count,
        )

    async def acknowledge(
        self,
        payload: Any,
        *,
        principal: tuple[str, str],
        request_id: str = "",
    ) -> tuple[int, dict[str, Any]]:
        tenant_id, agent_id = _principal(principal)
        try:
            message_id, lease_id = parse_ack_request(payload)
        except (TypeError, ValueError):
            return await self._audited_error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "The message acknowledgement request is invalid.",
                self._generic_audit(
                    action="message_acknowledge",
                    outcome="rejected",
                    tenant_id=tenant_id,
                    recipient_agent_id=agent_id,
                    reason_code="invalid_request",
                    request_id=request_id,
                ),
            )

        try:
            authorization = self.control_plane.authorize_recipient(tenant_id, agent_id)
        except Exception as exc:
            _log_failure("Communication recipient authorization failed", exc)
            return _communication_state_unavailable()
        if not authorization.allowed:
            return await self._audited_error(
                HTTPStatus.FORBIDDEN,
                authorization.reason_code,
                authorization.reason,
                self._generic_audit(
                    action="message_acknowledge",
                    outcome="denied",
                    tenant_id=tenant_id,
                    recipient_agent_id=agent_id,
                    reason_code=authorization.reason_code,
                    request_id=request_id,
                ),
            )

        try:
            result = await self.store.acknowledge(
                tenant_id,
                agent_id,
                message_id,
                lease_id,
                request_id=request_id,
            )
        except Exception as exc:
            _log_failure("Communication acknowledgement transaction failed", exc)
            return _communication_state_unavailable()
        if not result.allowed:
            status = (
                HTTPStatus.NOT_FOUND
                if result.reason_code == "communication_message_not_found"
                else HTTPStatus.CONFLICT
            )
            return _error(status, result.reason_code, result.reason)
        return HTTPStatus.OK, success_response(result=store_result_to_wire(result))

    def _validate_message_time(
        self,
        message: InterAgentMessage,
    ) -> tuple[str, str] | None:
        now = self._utc_now()
        created_at = message.created_at.astimezone(timezone.utc)
        expires_at = message.expires_at.astimezone(timezone.utc)
        if created_at < now - self.max_clock_skew or created_at > now + self.max_clock_skew:
            return (
                "communication_timestamp_out_of_window",
                "The message creation time is outside the accepted clock window.",
            )
        if expires_at <= now:
            return (
                "communication_message_expired",
                "The communication message has expired.",
            )
        if expires_at - created_at < timedelta(seconds=1):
            return (
                "communication_ttl_too_short",
                "The communication message TTL must be at least one second.",
            )
        if (
            expires_at - created_at > self.max_message_ttl
            or expires_at > now + self.max_message_ttl
        ):
            return (
                "communication_ttl_exceeded",
                "The communication message TTL exceeds the configured maximum.",
            )
        return None

    async def _audited_error(
        self,
        status: int,
        code: str,
        message: str,
        audit: CommunicationAuditRecord,
    ) -> tuple[int, dict[str, Any]]:
        if not await self._append_audit(audit):
            return _communication_state_unavailable()
        return _error(status, code, message)

    async def _append_audit(self, audit: CommunicationAuditRecord) -> bool:
        try:
            await self.store.append_audit(audit)
        except Exception as exc:
            _log_failure("Communication audit append failed", exc)
            return False
        return True

    async def audit_gateway_rejection(
        self,
        *,
        principal: tuple[str, str],
        route: str,
        reason_code: str,
        request_id: str,
    ) -> bool:
        tenant_id, agent_id = _principal(principal)
        return await self._append_audit(
            self._generic_audit(
                action="gateway_request",
                outcome="rejected",
                tenant_id=tenant_id,
                sender_agent_id=agent_id,
                reason_code=reason_code,
                request_id=request_id,
                details={"route": route},
            )
        )

    def _message_audit(
        self,
        message: InterAgentMessage,
        *,
        action: str,
        outcome: str,
        reason_code: str,
        request_id: str,
        principal: tuple[str, str] | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> CommunicationAuditRecord:
        tenant_id = principal[0] if principal is not None else message.tenant_id
        sender_agent_id = (
            principal[1] if principal is not None else message.sender_agent_id
        )
        return CommunicationAuditRecord(
            action=action,
            outcome=outcome,
            tenant_id=tenant_id,
            sender_agent_id=sender_agent_id,
            recipient_agent_id=message.recipient_agent_id,
            message_fingerprint=message.message_fingerprint,
            message_kind=message.kind.value,
            content_sha256=message.content_sha256,
            content_length=len(message.content),
            delegation_fingerprint=fingerprint_identifier(message.delegation_id),
            reason_code=reason_code,
            request_id=request_id,
            details=details or {},
            occurred_at=self._utc_now(),
        )

    def _generic_audit(
        self,
        *,
        action: str,
        outcome: str,
        tenant_id: str,
        sender_agent_id: str = "",
        recipient_agent_id: str = "",
        reason_code: str,
        request_id: str,
        details: Mapping[str, Any] | None = None,
    ) -> CommunicationAuditRecord:
        return CommunicationAuditRecord(
            action=action,
            outcome=outcome,
            tenant_id=tenant_id,
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            reason_code=reason_code,
            request_id=request_id,
            details=details or {},
            occurred_at=self._utc_now(),
        )

    def _utc_now(self) -> datetime:
        value = self._now()
        if value.tzinfo is None:
            raise ValueError("communication gateway clock must be timezone-aware")
        return value.astimezone(timezone.utc)


class AgentCommunicationHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        application: AgentCommunicationApplication,
        *,
        api_keys: Mapping[tuple[str, str], str | tuple[str, ...]],
        admin_api_keys: Mapping[str, str | tuple[str, ...]] | None = None,
        max_request_bytes: int = 256 * 1024,
        rate_limiter: CommunicationRateLimiter | None = None,
        telemetry: GatewayTelemetry | None = None,
    ) -> None:
        normalized: dict[tuple[str, str], tuple[str, ...]] = {}
        for principal, configured_keys in api_keys.items():
            if not isinstance(principal, tuple) or len(principal) != 2:
                raise ValueError("each API key principal must be a tenant/Agent tuple")
            tenant_id, agent_id = str(principal[0]), str(principal[1])
            keys = _api_key_ring(configured_keys, "api_keys")
            if not tenant_id or not agent_id:
                raise ValueError("API key principals require tenant and Agent IDs")
            if application.control_plane.registration(tenant_id, agent_id) is None:
                raise ValueError("API keys may be configured only for registered Agents")
            normalized[(tenant_id, agent_id)] = keys
        if not normalized:
            raise ValueError("at least one Agent API key is required")
        normalized_admin: dict[str, tuple[str, ...]] = {}
        for actor, configured_keys in (admin_api_keys or {}).items():
            actor_id = str(actor)
            keys = _api_key_ring(configured_keys, "admin_api_keys")
            if _ADMIN_ACTOR.fullmatch(actor_id) is None:
                raise ValueError("admin_api_keys require a valid actor ID")
            if application.admin is None:
                raise ValueError(
                    "administrative API keys require a persistent coordination control plane"
                )
            normalized_admin[actor_id] = keys
        all_keys = [
            key
            for key_ring in (*normalized.values(), *normalized_admin.values())
            for key in key_ring
        ]
        if len(set(all_keys)) != len(all_keys):
            raise ValueError(
                "a unique API key is required for every Agent/admin identity and rotation slot"
            )
        if max_request_bytes <= 0:
            raise ValueError("max_request_bytes must be positive")
        self.application = application
        self.api_keys = normalized
        self.admin_api_keys = normalized_admin
        self.max_request_bytes = int(max_request_bytes)
        self.rate_limiter = rate_limiter
        self.telemetry = telemetry
        super().__init__(server_address, AgentCommunicationRequestHandler)

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            if self.rate_limiter is not None:
                try:
                    self.rate_limiter.close()
                except Exception as exc:
                    _log_failure("Communication rate limiter shutdown failed", exc)
            if self.telemetry is not None:
                try:
                    self.telemetry.shutdown()
                except Exception as exc:
                    _log_failure("Communication telemetry shutdown failed", exc)


class AgentCommunicationRequestHandler(BaseHTTPRequestHandler):
    server: AgentCommunicationHTTPServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._request_started_ns = time.time_ns()
        route = self._route_path()
        if route == "/v1/admin/coordination":
            actor = self._authenticated_admin()
            if actor is None:
                self._write(*_admin_unauthorized())
                return
            if self.server.application.admin is None:
                self._write(
                    *_error(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "coordination_admin_unavailable",
                        "The coordination administration service is unavailable.",
                    )
                )
                return
            try:
                response = self.server.application.admin.snapshot()
            except Exception as exc:
                _log_failure("Coordination administration read failed", exc)
                self._write(*_admin_exception(exc))
                return
            self._write(HTTPStatus.OK, success_response(**response))
            return
        if route != "/health":
            self._write(*_error(HTTPStatus.NOT_FOUND, "not_found", "Endpoint not found."))
            return
        if self._authenticated_principal() is None:
            self._write(*_unauthorized())
            return
        try:
            status, response = asyncio.run(self.server.application.health())
        except Exception as exc:
            _log_failure("Unhandled communication readiness failure", exc)
            status, response = _communication_not_ready()
        self._write(status, response)

    def do_POST(self) -> None:
        self._request_started_ns = time.time_ns()
        route = self._route_path()
        if route.startswith("/v1/admin/"):
            self._do_admin_post(route)
            return
        principal = self._authenticated_principal()
        if principal is None:
            self._write(*_unauthorized())
            return
        routes = {
            "/v1/messages/send": self.server.application.send,
            "/v1/messages/receive": self.server.application.receive,
            "/v1/messages/ack": self.server.application.acknowledge,
        }
        handler = routes.get(route)
        if handler is None:
            self._write(*_error(HTTPStatus.NOT_FOUND, "not_found", "Endpoint not found."))
            return
        rate_limit_error = self._rate_limit(principal, route)
        if rate_limit_error is not None:
            self._write(*rate_limit_error)
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
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
            status, response = asyncio.run(
                handler(
                    payload,
                    principal=principal,
                    request_id=self._request_id(),
                )
            )
        except Exception as exc:
            _log_failure("Unhandled communication gateway request failure", exc)
            status, response = _error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "The communication gateway could not process the request.",
            )
        self._write(status, response)

    def _do_admin_post(self, route: str) -> None:
        actor = self._authenticated_admin()
        if actor is None:
            self._write(*_admin_unauthorized())
            return
        if self.server.application.admin is None:
            self._write(
                *_error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "coordination_admin_unavailable",
                    "The coordination administration service is unavailable.",
                )
            )
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0]
        if content_type.strip().lower() != "application/json":
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
            response = self.server.application.admin.mutate(route, payload, actor=actor)
        except LookupError:
            self._write(*_error(HTTPStatus.NOT_FOUND, "not_found", "Endpoint not found."))
            return
        except Exception as exc:
            _log_failure("Coordination administration mutation failed", exc)
            self._write(*_admin_exception(exc))
            return
        self._write(HTTPStatus.OK, success_response(**response))

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()

    def log_message(self, format: str, *args: Any) -> None:
        logger.info(
            "Agent communication HTTP: method=%s route=%s",
            self.command if self.command in {"GET", "POST"} else "OTHER",
            self._route_path() if self._route_path() in _KNOWN_ROUTES else "unmatched",
        )

    def _authenticated_principal(self) -> tuple[str, str] | None:
        authorization = self.headers.get("Authorization", "")
        scheme, separator, supplied = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer":
            supplied = ""
        supplied_bytes = supplied.encode("utf-8")
        matched = None
        for principal, api_keys in self.server.api_keys.items():
            for api_key in api_keys:
                if hmac.compare_digest(supplied_bytes, api_key.encode("utf-8")):
                    matched = principal
        return matched

    def _authenticated_admin(self) -> str | None:
        authorization = self.headers.get("Authorization", "")
        scheme, separator, supplied = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer":
            supplied = ""
        supplied_bytes = supplied.encode("utf-8")
        matched = None
        for actor, api_keys in self.server.admin_api_keys.items():
            for api_key in api_keys:
                if hmac.compare_digest(supplied_bytes, api_key.encode("utf-8")):
                    matched = actor
        return matched

    def _read_json(self) -> Any | None:
        if self.headers.get("Transfer-Encoding"):
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

    def _rate_limit(
        self,
        principal: tuple[str, str],
        route: str,
    ) -> tuple[int, dict[str, Any]] | None:
        rate_limiter = self.server.rate_limiter
        if rate_limiter is None:
            return None
        try:
            allowed = rate_limiter.allow(f"agent:{principal[0]}:{principal[1]}")
        except Exception as exc:
            _log_failure("Communication rate limiter failed", exc)
            status = HTTPStatus.SERVICE_UNAVAILABLE
            reason_code = "communication_rate_limit_unavailable"
            message = "The communication request limiter is unavailable."
        else:
            if allowed:
                return None
            status = HTTPStatus.TOO_MANY_REQUESTS
            reason_code = "communication_rate_limit_exceeded"
            message = "The authenticated Agent request limit was exceeded."
        try:
            persisted = asyncio.run(
                self.server.application.audit_gateway_rejection(
                    principal=principal,
                    route=route,
                    reason_code=reason_code,
                    request_id=self._request_id(),
                )
            )
        except Exception as exc:
            _log_failure("Communication rate-limit audit failed", exc)
            persisted = False
        if not persisted:
            return _communication_state_unavailable()
        return _error(status, reason_code, message)

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
            _log_failure("Communication telemetry export failed", exc)

    def _telemetry_route(self) -> str:
        path = self._route_path()
        return path if path in _KNOWN_ROUTES else "unmatched"


_KNOWN_ROUTES = frozenset(
    {
        "/health",
        "/v1/messages/send",
        "/v1/messages/receive",
        "/v1/messages/ack",
        "/v1/admin/coordination",
        "/v1/admin/agents/register",
        "/v1/admin/agents/active",
        "/v1/admin/agents/quarantine",
        "/v1/admin/agents/restore",
        "/v1/admin/topology",
        "/v1/admin/topology/remove",
        "/v1/admin/delegations",
        "/v1/admin/delegations/revoke",
    }
)


def create_communication_server(
    application: AgentCommunicationApplication,
    *,
    api_keys: Mapping[tuple[str, str], str | tuple[str, ...]],
    admin_api_keys: Mapping[str, str | tuple[str, ...]] | None = None,
    host: str = "127.0.0.1",
    port: int = 38200,
    max_request_bytes: int = 256 * 1024,
    rate_limiter: CommunicationRateLimiter | None = None,
    telemetry: GatewayTelemetry | None = None,
    tls_context: ssl.SSLContext | None = None,
) -> AgentCommunicationHTTPServer:
    server = AgentCommunicationHTTPServer(
        (host, port),
        application,
        api_keys=api_keys,
        admin_api_keys=admin_api_keys,
        max_request_bytes=max_request_bytes,
        rate_limiter=rate_limiter,
        telemetry=telemetry,
    )
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server


def create_communication_tls_context(
    *,
    certificate: str,
    private_key: str,
    client_ca: str | None = None,
    require_client_certificate: bool = False,
) -> ssl.SSLContext:
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
    return context


def _principal(value: tuple[str, str]) -> tuple[str, str]:
    if not isinstance(value, tuple) or len(value) != 2 or not all(value):
        raise ValueError("an authenticated tenant/Agent principal is required")
    return str(value[0]), str(value[1])


def _api_key_ring(
    value: str | tuple[str, ...],
    field_name: str,
) -> tuple[str, ...]:
    keys = (value,) if isinstance(value, str) else value
    if not isinstance(keys, tuple) or not keys or any(
        not isinstance(key, str) or len(key) < 32 for key in keys
    ):
        raise ValueError(
            f"{field_name} must bind each identity to one or more keys of at least 32 characters"
        )
    if len(set(keys)) != len(keys):
        raise ValueError(f"{field_name} must contain unique API keys")
    return keys


def _error(status: int, code: str, message: str) -> tuple[int, dict[str, Any]]:
    return int(status), error_response(code, message)


def _unauthorized() -> tuple[int, dict[str, Any]]:
    return _error(
        HTTPStatus.UNAUTHORIZED,
        "unauthorized",
        "A valid Agent communication API key is required.",
    )


def _admin_unauthorized() -> tuple[int, dict[str, Any]]:
    return _error(
        HTTPStatus.UNAUTHORIZED,
        "admin_unauthorized",
        "A valid coordination administration API key is required.",
    )


def _admin_exception(exc: Exception) -> tuple[int, dict[str, Any]]:
    from safeharness.communication.admin import CoordinationAdminApplication

    status = CoordinationAdminApplication.error_status(exc)
    if status == HTTPStatus.BAD_REQUEST:
        code = "invalid_admin_request"
        message = "The coordination administration request is invalid."
    elif status == HTTPStatus.NOT_FOUND:
        code = "admin_target_not_found"
        message = "The requested coordination target does not exist."
    elif status == HTTPStatus.CONFLICT:
        code = "coordination_state_conflict"
        message = "The coordination state changed; refresh and retry."
    elif status == HTTPStatus.SERVICE_UNAVAILABLE:
        code = "coordination_state_unavailable"
        message = "The authoritative coordination state is unavailable."
    else:
        code = "internal_error"
        message = "The coordination administration request could not be processed."
    return _error(status, code, message)


def _communication_state_unavailable() -> tuple[int, dict[str, Any]]:
    return _error(
        HTTPStatus.SERVICE_UNAVAILABLE,
        "communication_state_unavailable",
        "The authoritative communication state or audit service is unavailable.",
    )


def _communication_not_ready() -> tuple[int, dict[str, Any]]:
    return _error(
        HTTPStatus.SERVICE_UNAVAILABLE,
        "communication_gateway_not_ready",
        "The Agent Communication Gateway is not ready.",
    )


def _log_failure(message: str, exc: Exception) -> None:
    logger.error("%s (%s)", message, type(exc).__name__)
