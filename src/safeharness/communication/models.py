"""Canonical identities, topology rules, delegations, and Agent messages."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

from safeharness.api._mapping import frozen_mapping, json_safe


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_CAPABILITY = re.compile(r"[A-Za-z0-9*][A-Za-z0-9*._:/@-]{0,255}\Z")
_MAX_CONTENT_BYTES = 64 * 1024
_MAX_METADATA_BYTES = 16 * 1024


class MessageKind(str, Enum):
    INFORM = "inform"
    QUERY = "query"
    RESPONSE = "response"
    DELEGATE = "delegate"
    RESULT = "result"
    ALERT = "alert"


@dataclass(frozen=True, slots=True)
class AgentRegistration:
    tenant_id: str
    agent_id: str
    roles: frozenset[str] = frozenset()
    delegable_capabilities: frozenset[str] = frozenset()
    accepted_capabilities: frozenset[str] = frozenset()
    active: bool = True

    def __post_init__(self) -> None:
        _validate_identifier(self.tenant_id, "tenant_id")
        _validate_identifier(self.agent_id, "agent_id")
        _validate_capabilities(self.roles, "roles")
        _validate_capabilities(
            self.delegable_capabilities,
            "delegable_capabilities",
        )
        _validate_capabilities(
            self.accepted_capabilities,
            "accepted_capabilities",
        )


@dataclass(frozen=True, slots=True)
class TopologyRule:
    tenant_id: str
    source_agent_id: str
    target_agent_id: str
    allowed_kinds: frozenset[MessageKind]

    def __post_init__(self) -> None:
        _validate_identifier(self.tenant_id, "tenant_id")
        _validate_identifier(self.source_agent_id, "source_agent_id")
        _validate_identifier(self.target_agent_id, "target_agent_id")
        if self.source_agent_id == self.target_agent_id:
            raise ValueError("communication topology rules must connect different Agents")
        if not self.allowed_kinds or any(
            not isinstance(kind, MessageKind) for kind in self.allowed_kinds
        ):
            raise ValueError("allowed_kinds must contain MessageKind values")


@dataclass(frozen=True, slots=True)
class DelegationGrant:
    tenant_id: str
    grantor_agent_id: str
    grantee_agent_id: str
    capabilities: frozenset[str]
    expires_at: datetime
    session_id: str = ""
    run_id: str = ""
    max_messages: int = 1
    delegation_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        _validate_identifier(self.tenant_id, "tenant_id")
        _validate_identifier(self.grantor_agent_id, "grantor_agent_id")
        _validate_identifier(self.grantee_agent_id, "grantee_agent_id")
        _validate_identifier(self.delegation_id, "delegation_id")
        if self.grantor_agent_id == self.grantee_agent_id:
            raise ValueError("delegation grantor and grantee must be different Agents")
        if not self.capabilities:
            raise ValueError("a delegation grant must contain at least one capability")
        _validate_capabilities(self.capabilities, "capabilities")
        _validate_optional_identifier(self.session_id, "session_id")
        _validate_optional_identifier(self.run_id, "run_id")
        if self.expires_at.tzinfo is None:
            raise ValueError("delegation expiry must be timezone-aware")
        if not 1 <= self.max_messages <= 10_000:
            raise ValueError("delegation max_messages must be between 1 and 10000")


@dataclass(frozen=True, slots=True)
class InterAgentMessage:
    tenant_id: str
    sender_agent_id: str
    recipient_agent_id: str
    session_id: str
    run_id: str
    kind: MessageKind
    content: str
    expires_at: datetime
    trace_id: str = ""
    correlation_id: str = ""
    parent_message_id: str = ""
    delegation_id: str = ""
    requested_capabilities: frozenset[str] = frozenset()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    message_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        for value, name in (
            (self.tenant_id, "tenant_id"),
            (self.sender_agent_id, "sender_agent_id"),
            (self.recipient_agent_id, "recipient_agent_id"),
            (self.session_id, "session_id"),
            (self.run_id, "run_id"),
            (self.message_id, "message_id"),
        ):
            _validate_identifier(value, name)
        for value, name in (
            (self.trace_id, "trace_id"),
            (self.correlation_id, "correlation_id"),
            (self.parent_message_id, "parent_message_id"),
            (self.delegation_id, "delegation_id"),
        ):
            _validate_optional_identifier(value, name)
        if self.sender_agent_id == self.recipient_agent_id:
            raise ValueError("sender and recipient must be different Agents")
        if not isinstance(self.kind, MessageKind):
            raise ValueError("kind must be a MessageKind")
        if not isinstance(self.content, str) or not self.content:
            raise ValueError("message content must be a non-empty string")
        if len(self.content.encode("utf-8")) > _MAX_CONTENT_BYTES:
            raise ValueError("message content exceeds the size limit")
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("message timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("message expiry must be after creation")
        if self.expires_at - self.created_at < timedelta(seconds=1):
            raise ValueError("message TTL must be at least one second")
        _validate_capabilities(self.requested_capabilities, "requested_capabilities")
        if self.kind is MessageKind.DELEGATE:
            if not self.delegation_id or not self.requested_capabilities:
                raise ValueError(
                    "delegate messages require a delegation ID and requested capabilities"
                )
        elif self.delegation_id or self.requested_capabilities:
            raise ValueError(
                "only delegate messages may contain delegation authority"
            )
        safe_metadata = json_safe(self.metadata)
        if not isinstance(safe_metadata, Mapping):
            raise ValueError("message metadata must be a mapping")
        encoded_metadata = json.dumps(
            safe_metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded_metadata) > _MAX_METADATA_BYTES:
            raise ValueError("message metadata exceeds the size limit")
        object.__setattr__(self, "metadata", frozen_mapping(safe_metadata))

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    @property
    def message_fingerprint(self) -> str:
        return hashlib.sha256(self.message_id.encode("utf-8")).hexdigest()

    def with_inspected_content(
        self,
        content: str,
        *,
        provenance: Mapping[str, Any],
    ) -> "InterAgentMessage":
        metadata = dict(self.metadata)
        metadata["safeharness_provenance"] = json_safe(provenance)
        return replace(self, content=content, metadata=metadata)


@dataclass(frozen=True, slots=True)
class MessageLease:
    message: InterAgentMessage
    lease_id: str
    lease_until: datetime
    delivery_attempt: int

    def __post_init__(self) -> None:
        _validate_identifier(self.lease_id, "lease_id")
        if self.lease_until.tzinfo is None:
            raise ValueError("lease expiry must be timezone-aware")
        if self.delivery_attempt < 1:
            raise ValueError("delivery_attempt must be positive")


@dataclass(frozen=True, slots=True)
class CommunicationInspection:
    allowed: bool
    content: str
    modified: bool = False
    reason_code: str = ""
    reason: str = ""
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provenance", frozen_mapping(self.provenance))


@dataclass(frozen=True, slots=True)
class CommunicationAuthorization:
    allowed: bool
    reason_code: str = ""
    reason: str = ""
    delegation_max_messages: int | None = None


@dataclass(frozen=True, slots=True)
class CommunicationAuditRecord:
    action: str
    outcome: str
    tenant_id: str
    sender_agent_id: str = ""
    recipient_agent_id: str = ""
    message_fingerprint: str = ""
    message_kind: str = ""
    content_sha256: str = ""
    content_length: int = 0
    delegation_fingerprint: str = ""
    reason_code: str = ""
    request_id: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)
    record_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.action or not self.outcome or not self.tenant_id:
            raise ValueError("communication audit action, outcome, and tenant are required")
        if self.occurred_at.tzinfo is None:
            raise ValueError("communication audit timestamp must be timezone-aware")
        object.__setattr__(self, "details", frozen_mapping(json_safe(self.details)))


def fingerprint_identifier(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""


def _validate_identifier(value: str, name: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")


def _validate_optional_identifier(value: str, name: str) -> None:
    if value:
        _validate_identifier(value, name)


def _validate_capabilities(values: frozenset[str], name: str) -> None:
    if not isinstance(values, frozenset) or any(
        not isinstance(value, str) or _CAPABILITY.fullmatch(value) is None
        for value in values
    ):
        raise ValueError(f"{name} contains an invalid capability")
