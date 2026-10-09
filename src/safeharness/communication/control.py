"""Default-deny coordination control plane for Agent communication."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from safeharness.communication.models import (
    AgentRegistration,
    CommunicationAuthorization,
    DelegationGrant,
    InterAgentMessage,
    MessageKind,
    TopologyRule,
)


@dataclass(frozen=True, slots=True)
class CoordinationSnapshot:
    """Serializable coordination state without credentials or message bodies."""

    agents: tuple[AgentRegistration, ...]
    topology: tuple[TopologyRule, ...]
    delegations: tuple[DelegationGrant, ...] = ()
    quarantined: frozenset[tuple[str, str]] = frozenset()
    revoked_delegations: frozenset[tuple[str, str]] = frozenset()


class CoordinationControlPlane:
    """Trusted Agent registry, topology, delegation, revocation, and isolation state."""

    def __init__(
        self,
        agents: Iterable[AgentRegistration],
        topology: Iterable[TopologyRule],
        delegations: Iterable[DelegationGrant] = (),
        *,
        revoked_delegations: Iterable[tuple[str, str]] = (),
        now=None,
    ) -> None:
        self._lock = threading.RLock()
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._agents = {}
        for agent in agents:
            key = (agent.tenant_id, agent.agent_id)
            if key in self._agents:
                raise ValueError("Agent registrations must be unique")
            self._agents[key] = agent
        if not self._agents:
            raise ValueError("at least one Agent registration is required")
        self._topology = {}
        for rule in topology:
            source = (rule.tenant_id, rule.source_agent_id)
            target = (rule.tenant_id, rule.target_agent_id)
            if source not in self._agents or target not in self._agents:
                raise ValueError("topology rules may reference only registered Agents")
            key = (*source, rule.target_agent_id)
            if key in self._topology:
                raise ValueError("communication topology rules must be unique")
            self._topology[key] = rule.allowed_kinds
        self._delegations = {}
        self._revoked_delegations: set[tuple[str, str]] = set(revoked_delegations)
        for grant in delegations:
            key = (grant.tenant_id, grant.delegation_id)
            if key in self._delegations:
                raise ValueError("delegation IDs must be unique per tenant")
            self._validate_grant(
                grant,
                require_topology=(grant.tenant_id, grant.delegation_id)
                not in self._revoked_delegations,
            )
            self._delegations[key] = grant
        self._quarantined: set[tuple[str, str]] = set()

    @property
    def principals(self) -> frozenset[tuple[str, str]]:
        with self._lock:
            return frozenset(self._agents)

    def registration(self, tenant_id: str, agent_id: str) -> AgentRegistration | None:
        with self._lock:
            return self._agents.get((tenant_id, agent_id))

    def snapshot(self) -> CoordinationSnapshot:
        """Return a stable copy suitable for persistence or administration."""

        with self._lock:
            return CoordinationSnapshot(
                agents=tuple(
                    sorted(
                        self._agents.values(),
                        key=lambda item: (item.tenant_id, item.agent_id),
                    )
                ),
                topology=tuple(
                    sorted(
                        (
                            TopologyRule(
                                tenant_id=key[0],
                                source_agent_id=key[1],
                                target_agent_id=key[2],
                                allowed_kinds=allowed_kinds,
                            )
                            for key, allowed_kinds in self._topology.items()
                        ),
                        key=lambda item: (
                            item.tenant_id,
                            item.source_agent_id,
                            item.target_agent_id,
                        ),
                    )
                ),
                delegations=tuple(
                    sorted(
                        self._delegations.values(),
                        key=lambda item: (item.tenant_id, item.delegation_id),
                    )
                ),
                quarantined=frozenset(self._quarantined),
                revoked_delegations=frozenset(self._revoked_delegations),
            )

    def _replace_snapshot(self, snapshot: CoordinationSnapshot) -> None:
        """Install a validated snapshot (used by durable control-plane adapters)."""

        candidate = CoordinationControlPlane(
            snapshot.agents,
            snapshot.topology,
            snapshot.delegations,
            revoked_delegations=snapshot.revoked_delegations,
            now=self._now,
        )
        principals = candidate.principals
        if not snapshot.quarantined <= principals:
            raise ValueError("quarantine state may reference only registered Agents")
        delegation_keys = {
            (item.tenant_id, item.delegation_id) for item in snapshot.delegations
        }
        if not snapshot.revoked_delegations <= delegation_keys:
            raise ValueError("revocation state may reference only registered delegations")
        with self._lock:
            self._agents = candidate._agents
            self._topology = candidate._topology
            self._delegations = candidate._delegations
            self._quarantined = set(snapshot.quarantined)
            self._revoked_delegations = set(snapshot.revoked_delegations)

    def register_agent(self, agent: AgentRegistration) -> None:
        """Add a trusted Agent registration to the in-memory control plane."""

        key = (agent.tenant_id, agent.agent_id)
        with self._lock:
            if key in self._agents:
                raise ValueError("Agent registration already exists")
            self._agents[key] = agent

    def set_agent_active(self, tenant_id: str, agent_id: str, active: bool) -> None:
        """Enable or disable a registered Agent without deleting its history."""

        if not isinstance(active, bool):
            raise ValueError("active must be a boolean")
        with self._lock:
            key = (tenant_id, agent_id)
            agent = self._agents.get(key)
            if agent is None:
                raise KeyError("unknown Agent")
            self._agents[key] = replace(agent, active=active)

    def upsert_topology(self, rule: TopologyRule) -> None:
        """Create or replace one explicit source-to-target message edge."""

        source = (rule.tenant_id, rule.source_agent_id)
        target = (rule.tenant_id, rule.target_agent_id)
        with self._lock:
            if source not in self._agents or target not in self._agents:
                raise ValueError("topology rules may reference only registered Agents")
            self._topology[(*source, rule.target_agent_id)] = rule.allowed_kinds

    def remove_topology(
        self,
        tenant_id: str,
        source_agent_id: str,
        target_agent_id: str,
    ) -> bool:
        with self._lock:
            return (
                self._topology.pop((tenant_id, source_agent_id, target_agent_id), None)
                is not None
            )

    def add_delegation(self, grant: DelegationGrant) -> None:
        """Add a bounded delegation after validating both Agent capabilities."""

        with self._lock:
            key = (grant.tenant_id, grant.delegation_id)
            if key in self._delegations:
                raise ValueError("delegation ID already exists")
            self._validate_grant(grant)
            self._delegations[key] = grant

    def quarantine_agent(self, tenant_id: str, agent_id: str) -> None:
        with self._lock:
            self._require_agent(tenant_id, agent_id)
            self._quarantined.add((tenant_id, agent_id))

    def restore_agent(self, tenant_id: str, agent_id: str) -> None:
        with self._lock:
            self._require_agent(tenant_id, agent_id)
            self._quarantined.discard((tenant_id, agent_id))

    def revoke_delegation(self, tenant_id: str, delegation_id: str) -> None:
        with self._lock:
            if (tenant_id, delegation_id) not in self._delegations:
                raise KeyError("unknown delegation")
            self._revoked_delegations.add((tenant_id, delegation_id))

    def authorize_sender(self, message: InterAgentMessage) -> CommunicationAuthorization:
        with self._lock:
            sender = self._agents.get((message.tenant_id, message.sender_agent_id))
            recipient = self._agents.get((message.tenant_id, message.recipient_agent_id))
            if sender is None or recipient is None:
                return _deny(
                    "agent_not_registered",
                    "Both communication principals must be registered.",
                )
            quarantined = set(self._quarantined)
            revoked = set(self._revoked_delegations)
            allowed_kinds = self._topology.get(
                (
                    message.tenant_id,
                    message.sender_agent_id,
                    message.recipient_agent_id,
                ),
                frozenset(),
            )
            grant = self._delegations.get((message.tenant_id, message.delegation_id))
        if not sender.active or not recipient.active:
            return _deny("agent_inactive", "An inactive Agent cannot exchange messages.")
        if (message.tenant_id, message.sender_agent_id) in quarantined:
            return _deny("sender_quarantined", "The sending Agent is quarantined.")
        if (message.tenant_id, message.recipient_agent_id) in quarantined:
            return _deny("recipient_quarantined", "The receiving Agent is quarantined.")
        if message.kind not in allowed_kinds:
            return _deny(
                "communication_topology_denied",
                "The communication topology does not allow this route and message kind.",
            )
        if message.kind is not MessageKind.DELEGATE:
            return CommunicationAuthorization(True)
        if grant is None:
            return _deny("delegation_not_found", "The delegation grant does not exist.")
        if (message.tenant_id, message.delegation_id) in revoked:
            return _deny("delegation_revoked", "The delegation grant has been revoked.")
        now = self._now().astimezone(timezone.utc)
        if grant.expires_at.astimezone(timezone.utc) <= now:
            return _deny("delegation_expired", "The delegation grant has expired.")
        if (
            grant.grantor_agent_id != message.sender_agent_id
            or grant.grantee_agent_id != message.recipient_agent_id
        ):
            return _deny(
                "delegation_identity_mismatch",
                "The delegation grant is bound to different Agents.",
            )
        if grant.session_id and grant.session_id != message.session_id:
            return _deny(
                "delegation_scope_mismatch",
                "The delegation grant is bound to another session.",
            )
        if grant.run_id and grant.run_id != message.run_id:
            return _deny(
                "delegation_scope_mismatch",
                "The delegation grant is bound to another run.",
            )
        if not message.requested_capabilities <= grant.capabilities:
            return _deny(
                "delegation_capability_escalation",
                "The message requests capabilities outside the delegation grant.",
            )
        if not message.requested_capabilities <= sender.delegable_capabilities:
            return _deny(
                "delegation_capability_escalation",
                "The grantor cannot delegate the requested capabilities.",
            )
        if not message.requested_capabilities <= recipient.accepted_capabilities:
            return _deny(
                "delegation_capability_rejected",
                "The recipient is not registered to accept the requested capabilities.",
            )
        return CommunicationAuthorization(
            True,
            delegation_max_messages=grant.max_messages,
        )

    def authorize_recipient(
        self,
        tenant_id: str,
        recipient_agent_id: str,
    ) -> CommunicationAuthorization:
        with self._lock:
            recipient = self._agents.get((tenant_id, recipient_agent_id))
            quarantined = (tenant_id, recipient_agent_id) in self._quarantined
        if recipient is None:
            return _deny("agent_not_registered", "The receiving Agent is not registered.")
        if not recipient.active:
            return _deny("agent_inactive", "The receiving Agent is inactive.")
        if quarantined:
            return _deny("recipient_quarantined", "The receiving Agent is quarantined.")
        return CommunicationAuthorization(True)

    def _validate_grant(
        self,
        grant: DelegationGrant,
        *,
        require_topology: bool = True,
    ) -> None:
        grantor = self.registration(grant.tenant_id, grant.grantor_agent_id)
        grantee = self.registration(grant.tenant_id, grant.grantee_agent_id)
        if grantor is None or grantee is None:
            raise ValueError("delegations may reference only registered Agents")
        if not grant.capabilities <= grantor.delegable_capabilities:
            raise ValueError("a delegation exceeds the grantor's delegable capabilities")
        if not grant.capabilities <= grantee.accepted_capabilities:
            raise ValueError("a delegation exceeds the grantee's accepted capabilities")
        allowed_kinds = self._topology.get(
            (grant.tenant_id, grant.grantor_agent_id, grant.grantee_agent_id),
            frozenset(),
        )
        if require_topology and MessageKind.DELEGATE not in allowed_kinds:
            raise ValueError("a delegation requires an allowed delegate topology edge")

    def _require_agent(self, tenant_id: str, agent_id: str) -> None:
        if (tenant_id, agent_id) not in self._agents:
            raise KeyError("unknown Agent")


def _deny(code: str, reason: str) -> CommunicationAuthorization:
    return CommunicationAuthorization(False, reason_code=code, reason=reason)
