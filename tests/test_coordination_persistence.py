from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from examples.langgraph_noc.communication_gateway import build_communication_gateway

from safeharness.communication import (
    AgentRegistration,
    CoordinationConflict,
    CoordinationIntegrityError,
    CoordinationSnapshot,
    DelegationGrant,
    InterAgentMessage,
    MessageKind,
    SQLiteCoordinationControlPlane,
    SQLiteCoordinationStore,
    PostgreSQLCoordinationStore,
    TopologyRule,
    snapshot_from_payload,
    snapshot_to_payload,
)


NOW = datetime(2026, 7, 22, 8, 0, tzinfo=timezone.utc)
KEY = b"coordination-signing-key-0123456789"


def _agents() -> tuple[AgentRegistration, ...]:
    return (
        AgentRegistration(
            "fiberhome",
            "supervisor",
            roles=frozenset({"supervisor"}),
            delegable_capabilities=frozenset({"nms:alarm:read"}),
        ),
        AgentRegistration(
            "fiberhome",
            "diagnosis",
            roles=frozenset({"diagnosis"}),
            accepted_capabilities=frozenset({"nms:alarm:read"}),
        ),
    )


def _topology() -> tuple[TopologyRule, ...]:
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


def _grant() -> DelegationGrant:
    return DelegationGrant(
        tenant_id="fiberhome",
        grantor_agent_id="supervisor",
        grantee_agent_id="diagnosis",
        capabilities=frozenset({"nms:alarm:read"}),
        expires_at=NOW + timedelta(minutes=10),
        session_id="session-1",
        run_id="run-1",
        max_messages=2,
        delegation_id="delegation-1",
    )


def _snapshot() -> CoordinationSnapshot:
    return CoordinationSnapshot(_agents(), _topology(), (_grant(),))


def _message(*, kind=MessageKind.QUERY, delegation_id="") -> InterAgentMessage:
    capabilities = (
        frozenset({"nms:alarm:read"}) if kind is MessageKind.DELEGATE else frozenset()
    )
    return InterAgentMessage(
        tenant_id="fiberhome",
        sender_agent_id="supervisor",
        recipient_agent_id="diagnosis",
        session_id="session-1",
        run_id="run-1",
        kind=kind,
        content="Inspect the active alarm.",
        delegation_id=delegation_id,
        requested_capabilities=capabilities,
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


class SQLiteCoordinationPersistenceTests(unittest.TestCase):
    def test_restart_and_cross_instance_refresh_preserve_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite3"
            first = SQLiteCoordinationControlPlane(
                path,
                KEY,
                agents=_agents(),
                topology=_topology(),
                delegations=(_grant(),),
                now=lambda: NOW,
            )
            second = SQLiteCoordinationControlPlane(
                path,
                KEY,
                now=lambda: NOW,
            )

            self.assertTrue(first.authorize_sender(_message()).allowed)
            first.quarantine_agent("fiberhome", "diagnosis", actor="operator-1")
            self.assertEqual(
                second.authorize_sender(_message()).reason_code,
                "recipient_quarantined",
            )
            first.restore_agent("fiberhome", "diagnosis", actor="operator-1")
            first.revoke_delegation(
                "fiberhome",
                "delegation-1",
                actor="operator-1",
            )
            restarted = SQLiteCoordinationControlPlane(path, KEY, now=lambda: NOW)
            result = restarted.authorize_sender(
                _message(kind=MessageKind.DELEGATE, delegation_id="delegation-1")
            )
            self.assertEqual(result.reason_code, "delegation_revoked")
            self.assertEqual(restarted.coordination_version, 4)

    def test_management_mutations_are_validated_and_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite3"
            control = SQLiteCoordinationControlPlane(
                path,
                KEY,
                agents=_agents(),
                topology=_topology(),
                now=lambda: NOW,
            )
            control.set_agent_active("fiberhome", "diagnosis", False)
            self.assertEqual(
                control.authorize_recipient("fiberhome", "diagnosis").reason_code,
                "agent_inactive",
            )
            control.set_agent_active("fiberhome", "diagnosis", True)
            control.remove_topology(
                "fiberhome",
                "supervisor",
                "diagnosis",
            )
            self.assertEqual(
                control.authorize_sender(_message()).reason_code,
                "communication_topology_denied",
            )
            with self.assertRaises(ValueError):
                control.add_delegation(_grant())

    def test_revoked_delegation_survives_removing_its_topology_edge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite3"
            control = SQLiteCoordinationControlPlane(
                path,
                KEY,
                agents=_agents(),
                topology=_topology(),
                delegations=(_grant(),),
                now=lambda: NOW,
            )
            control.revoke_delegation(
                "fiberhome",
                "delegation-1",
                actor="operator-1",
            )
            self.assertTrue(
                control.remove_topology(
                    "fiberhome",
                    "supervisor",
                    "diagnosis",
                    actor="operator-1",
                )
            )

            restarted = SQLiteCoordinationControlPlane(path, KEY, now=lambda: NOW)
            self.assertEqual(
                restarted.state_store.load().snapshot.revoked_delegations,
                {("fiberhome", "delegation-1")},
            )
            self.assertEqual(
                restarted.authorize_sender(
                    _message(
                        kind=MessageKind.DELEGATE,
                        delegation_id="delegation-1",
                    )
                ).reason_code,
                "communication_topology_denied",
            )

    def test_optimistic_concurrency_does_not_overwrite_newer_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite3"
            first = SQLiteCoordinationStore(path, KEY, now=lambda: NOW)
            first.initialize(_snapshot())
            second = SQLiteCoordinationStore(path, KEY, now=lambda: NOW)
            first_state = first.load()
            second_state = second.load()
            assert first_state is not None and second_state is not None
            first.commit(
                first_state.version,
                CoordinationSnapshot(
                    _agents(),
                    _topology(),
                    (_grant(),),
                    quarantined=frozenset({("fiberhome", "diagnosis")}),
                ),
                operation="quarantine_agent",
                actor="operator-1",
            )
            with self.assertRaises(CoordinationConflict):
                second.commit(
                    second_state.version,
                    _snapshot(),
                    operation="restore_agent",
                    actor="operator-2",
                )
            loaded = first.load()
            assert loaded is not None
            self.assertEqual(loaded.version, 2)
            self.assertEqual(loaded.snapshot.quarantined, {("fiberhome", "diagnosis")})

    def test_signature_tampering_and_metadata_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite3"
            store = SQLiteCoordinationStore(path, KEY, now=lambda: NOW)
            store.initialize(_snapshot())
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE safeharness_coordination_state SET payload_json = ?",
                    (json.dumps({"tampered": True}),),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(CoordinationIntegrityError):
                store.load()
            self.assertFalse(store.health())

    def test_schema_version_tampering_fails_closed_on_every_load(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite3"
            store = SQLiteCoordinationStore(path, KEY, now=lambda: NOW)
            store.initialize(_snapshot())
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE safeharness_coordination_schema SET version = 999"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(CoordinationIntegrityError):
                store.load()

    def test_mutation_log_is_append_only_at_sql_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite3"
            store = SQLiteCoordinationStore(path, KEY, now=lambda: NOW)
            store.initialize(_snapshot())
            connection = sqlite3.connect(path)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "DELETE FROM safeharness_coordination_mutations"
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "UPDATE safeharness_coordination_mutations SET actor = 'x'"
                    )
            finally:
                connection.close()

    def test_snapshot_wire_shape_is_strict_and_deterministic(self) -> None:
        payload = snapshot_to_payload(_snapshot())
        self.assertEqual(payload, snapshot_to_payload(snapshot_from_payload(payload)))
        with self.assertRaises(CoordinationIntegrityError):
            snapshot_from_payload({**payload, "unexpected": []})
        duplicate = dict(payload)
        duplicate["quarantined"] = [["fiberhome", "diagnosis"], ["fiberhome", "diagnosis"]]
        with self.assertRaises(CoordinationIntegrityError):
            snapshot_from_payload(duplicate)

    def test_signing_key_is_required_and_not_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "coordination.sqlite3"
            with self.assertRaises(ValueError):
                SQLiteCoordinationStore(path, b"short")
            store = SQLiteCoordinationStore(path, KEY, now=lambda: NOW)
            store.initialize(_snapshot())
            connection = sqlite3.connect(path)
            try:
                serialized = " ".join(
                    str(row[0])
                    for row in connection.execute(
                        "SELECT payload_json FROM safeharness_coordination_mutations"
                    )
                )
            finally:
                connection.close()
            self.assertNotIn(KEY.decode("ascii"), serialized)


class PostgreSQLCoordinationConfigurationTests(unittest.TestCase):
    def test_schema_installs_append_only_mutation_trigger_and_roles(self) -> None:
        factory = _FakePostgresFactory()
        store = PostgreSQLCoordinationStore(KEY, connect=factory)
        store.initialize_schema(
            runtime_role="safeharness_coordination_writer",
            reader_role="safeharness_coordination_reader",
        )
        sql = "\n".join(query for query, _ in factory.connection.executions)
        self.assertIn("CREATE TABLE IF NOT EXISTS safeharness_coordination_state", sql)
        self.assertIn("BEFORE UPDATE OR DELETE", sql)
        self.assertIn(
            "GRANT SELECT, INSERT, UPDATE ON TABLE safeharness_coordination_state "
            "TO safeharness_coordination_writer",
            sql,
        )
        self.assertIn(
            "GRANT SELECT, INSERT ON TABLE safeharness_coordination_mutations "
            "TO safeharness_coordination_writer",
            sql,
        )
        self.assertIn(
            "GRANT SELECT ON TABLE safeharness_coordination_schema, "
            "safeharness_coordination_state, safeharness_coordination_mutations "
            "TO safeharness_coordination_reader",
            sql,
        )

    def test_postgres_role_names_are_validated_before_sql(self) -> None:
        store = PostgreSQLCoordinationStore(KEY, connect=_FakePostgresFactory())
        with self.assertRaises(ValueError):
            store.initialize_schema(runtime_role="writer; DROP ROLE postgres")
        with self.assertRaises(ValueError):
            store.initialize_schema(
                runtime_role="safeharness_writer",
                reader_role="safeharness_writer",
            )

    def test_noc_builder_rejects_unknown_or_unconfigured_shared_backend(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "communication.sqlite3"
            with self.assertRaisesRegex(ValueError, "must be sqlite or postgres"):
                build_communication_gateway(
                    database_path=path,
                    coordination_signing_key=KEY,
                    coordination_backend="unknown",
                    now=lambda: NOW,
                )
            with self.assertRaisesRegex(ValueError, "postgres coordination backend"):
                build_communication_gateway(
                    database_path=path,
                    coordination_signing_key=KEY,
                    coordination_backend="postgres",
                    now=lambda: NOW,
                )

    def test_noc_builder_can_enable_signed_sqlite_coordination_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = build_communication_gateway(
                database_path=Path(directory) / "communication.sqlite3",
                coordination_signing_key=KEY,
                now=lambda: NOW,
            )
            self.assertEqual(application.control_plane.coordination_version, 1)
            self.assertTrue(store.path.endswith("communication.sqlite3"))
            self.assertTrue(application.admin is not None)


class _FakePostgresFactory:
    def __init__(self) -> None:
        self.connection = _FakePostgresConnection()

    def __call__(self):
        return self.connection


class _FakePostgresConnection:
    def __init__(self) -> None:
        self.executions: list[tuple[str, object]] = []
        self.commits = 0
        self.rollbacks = 0
        self.cursor_instance = _FakePostgresCursor(self)

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        return None


class _FakePostgresCursor:
    def __init__(self, connection: _FakePostgresConnection) -> None:
        self.connection = connection
        self.last_query = ""

    def execute(self, query, values=None):
        self.last_query = query
        self.connection.executions.append((query, values))

    def fetchone(self):
        if "SELECT version FROM safeharness_coordination_schema" in self.last_query:
            return (1,)
        return None

    def fetchall(self):
        return []

    def close(self):
        return None


if __name__ == "__main__":
    unittest.main()
