from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
import threading
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from safeharness.communication import (
    AgentCommunicationApplication,
    AgentRegistration,
    CoordinationControlPlane,
    DelegationGrant,
    MessageKind,
    SQLiteCommunicationStore,
    SQLiteCoordinationControlPlane,
    TopologyRule,
    create_communication_server,
)


NOW = datetime(2026, 7, 22, 8, 0, tzinfo=timezone.utc)
AGENT_KEY = "a" * 32
DIAGNOSIS_KEY = "d" * 32
ADMIN_KEY = "z" * 32
PREVIOUS_ADMIN_KEY = "y" * 32


def _mutation_envelope(action="agent.quarantine"):
    tenant_id = "fiberhome"
    target_field = "delegation_id" if action == "delegation.revoke" else "agent_id"
    target_id = "delegation-1" if target_field == "delegation_id" else "diagnosis"
    resource_kind = "delegation" if target_field == "delegation_id" else "agent"
    return {
        "schema_version": "1.0",
        "action": action,
        "tenant_id": tenant_id,
        target_field: target_id,
        "resource": f"tenant/{tenant_id}/{resource_kind}/{target_id}",
        "effect": {
            "agent.quarantine": "deny_agent_communication",
            "agent.restore": "restore_agent_communication",
            "delegation.revoke": "revoke_delegated_authority",
        }[action],
        "operator_id": "user-1",
        "reason": "Incident containment",
        "decision_id": "decision-1",
        "approval_id": "approval-1",
        "policy_version": "safeharness.mutations.v1",
        "idempotency_key": "mutation-key-0001",
    }


def _agents():
    return (
        AgentRegistration(
            "fiberhome",
            "supervisor",
            delegable_capabilities=frozenset({"nms:alarm:read"}),
        ),
        AgentRegistration(
            "fiberhome",
            "diagnosis",
            accepted_capabilities=frozenset({"nms:alarm:read"}),
        ),
    )


def _topology():
    return (
        TopologyRule(
            "fiberhome",
            "supervisor",
            "diagnosis",
            frozenset({MessageKind.QUERY, MessageKind.DELEGATE}),
        ),
        TopologyRule(
            "fiberhome",
            "diagnosis",
            "supervisor",
            frozenset({MessageKind.RESULT}),
        ),
    )


def _grant():
    return DelegationGrant(
        tenant_id="fiberhome",
        grantor_agent_id="supervisor",
        grantee_agent_id="diagnosis",
        capabilities=frozenset({"nms:alarm:read"}),
        expires_at=NOW + timedelta(minutes=10),
        delegation_id="delegation-1",
    )


@contextmanager
def _server():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "coordination.sqlite3"
        control = SQLiteCoordinationControlPlane(
            path,
            b"coordination-admin-signing-key-012345"[:32],
            agents=_agents(),
            topology=_topology(),
            delegations=(_grant(),),
            now=lambda: NOW,
        )
        store = SQLiteCommunicationStore(path, now=lambda: NOW)
        application = AgentCommunicationApplication(
            control_plane=control,
            store=store,
            now=lambda: NOW,
        )
        server = create_communication_server(
            application,
            api_keys={
                ("fiberhome", "supervisor"): AGENT_KEY,
                ("fiberhome", "diagnosis"): DIAGNOSIS_KEY,
            },
            admin_api_keys={"operator-1": (ADMIN_KEY, PREVIOUS_ADMIN_KEY)},
            host="127.0.0.1",
            port=0,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        try:
            yield f"http://{host}:{port}", control
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


def _request(base_url, path, key, *, method="GET", payload=None):
    body = None
    headers = {"Authorization": f"Bearer {key}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(f"{base_url}{path}", data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        finally:
            exc.close()


class CoordinationAdminHTTPTests(unittest.TestCase):
    def test_admin_key_is_separate_and_mutations_are_effective(self) -> None:
        with _server() as (url, control):
            status, denied = _request(url, "/v1/admin/coordination", AGENT_KEY)
            self.assertEqual(status, 401)
            self.assertEqual(denied["error"]["code"], "admin_unauthorized")

            status, snapshot = _request(url, "/v1/admin/coordination", ADMIN_KEY)
            self.assertEqual(status, 200)
            self.assertEqual(snapshot["ok"], True)
            self.assertEqual(snapshot["version"], 1)
            self.assertNotIn("api_key", json.dumps(snapshot).lower())

            status, previous_snapshot = _request(
                url,
                "/v1/admin/coordination",
                PREVIOUS_ADMIN_KEY,
            )
            self.assertEqual(status, 200)
            self.assertEqual(previous_snapshot["version"], 1)

            status, changed = _request(
                url,
                "/v1/admin/agents/quarantine",
                ADMIN_KEY,
                method="POST",
                payload=_mutation_envelope(),
            )
            self.assertEqual(status, 200)
            self.assertEqual(changed["version"], 2)
            self.assertEqual(changed["actor"], "user-1")
            self.assertEqual(
                control.authorize_recipient("fiberhome", "diagnosis").reason_code,
                "recipient_quarantined",
            )

            status, changed = _request(
                url,
                "/v1/admin/delegations/revoke",
                ADMIN_KEY,
                method="POST",
                payload=_mutation_envelope("delegation.revoke"),
            )
            self.assertEqual(status, 200)
            self.assertEqual(changed["version"], 3)
            self.assertEqual(changed["actor"], "user-1")
            self.assertIn(["fiberhome", "delegation-1"], changed["state"]["revoked_delegations"])

    def test_admin_payload_is_strict_and_admin_key_cannot_be_reused_as_agent(self) -> None:
        with _server() as (url, _):
            status, response = _request(
                url,
                "/v1/admin/agents/quarantine",
                ADMIN_KEY,
                method="POST",
                payload={
                    "tenant_id": "fiberhome",
                    "agent_id": "diagnosis",
                    "unexpected": True,
                },
            )
            self.assertEqual(status, 400)
            self.assertEqual(response["error"]["code"], "invalid_admin_request")

            status, response = _request(
                url,
                "/v1/messages/receive",
                ADMIN_KEY,
                method="POST",
                payload={
                    "protocol": "safeharness-agent-communication.v1",
                    "limit": 1,
                    "lease_duration_seconds": 1,
                },
            )
            self.assertEqual(status, 401)
            self.assertEqual(response["error"]["code"], "unauthorized")

    def test_admin_duplicate_registration_is_a_client_error_not_policy_outage(self) -> None:
        with _server() as (url, _):
            status, response = _request(
                url,
                "/v1/admin/agents/register",
                ADMIN_KEY,
                method="POST",
                payload={
                    "tenant_id": "fiberhome",
                    "agent_id": "diagnosis",
                    "roles": [],
                    "delegable_capabilities": [],
                    "accepted_capabilities": [],
                    "active": True,
                },
            )
            self.assertEqual(status, 400)
            self.assertEqual(response["error"]["code"], "invalid_admin_request")

    def test_admin_keys_require_persistent_control_plane(self) -> None:
        control = CoordinationControlPlane(_agents(), _topology(), (_grant(),), now=lambda: NOW)
        with tempfile.TemporaryDirectory() as directory:
            application = AgentCommunicationApplication(
                control_plane=control,
                store=SQLiteCommunicationStore(Path(directory) / "messages.sqlite", now=lambda: NOW),
                now=lambda: NOW,
            )
            with self.assertRaisesRegex(ValueError, "persistent coordination"):
                create_communication_server(
                    application,
                    api_keys={("fiberhome", "supervisor"): AGENT_KEY},
                    admin_api_keys={"operator": ADMIN_KEY},
                    port=0,
                )

    def test_corrupted_coordination_state_makes_health_and_admin_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite3"
            control = SQLiteCoordinationControlPlane(
                path,
                b"coordination-admin-signing-key-012345"[:32],
                agents=_agents(),
                topology=_topology(),
                delegations=(_grant(),),
                now=lambda: NOW,
            )
            store = SQLiteCommunicationStore(path, now=lambda: NOW)
            application = AgentCommunicationApplication(
                control_plane=control,
                store=store,
                now=lambda: NOW,
            )
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE safeharness_coordination_state SET actor = 'tampered'"
                )
                connection.commit()
            finally:
                connection.close()
            status, response = asyncio.run(application.health())
            self.assertEqual(status, 503)
            self.assertEqual(response["error"]["code"], "communication_gateway_not_ready")


if __name__ == "__main__":
    unittest.main()
