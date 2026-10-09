from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
from threading import Thread
import unittest
from datetime import datetime, timedelta, timezone

from safeharness import SafeHarnessRuntime, SessionContext, ToolDescriptor, ToolInvocation
from safeharness.adapters import execute_invocation
from safeharness.backends import (
    AsymmetricEnforcementReceiptIssuer,
    AsymmetricEnforcementReceiptVerifier,
    Ed25519ReceiptSigner,
    Ed25519ReceiptVerifier,
    ExternalEnforcementReceiptSigner,
    InMemoryAuditSink,
    SignedCapabilityGateway,
    SignedEnforcementReceiptAuthority,
    SQLiteEnforcementReceiptReplayStore,
    StaticToolCatalog,
    invocation_digest,
)
from safeharness.gateway import (
    RegisteredTool,
    RemoteToolGatewayClient,
    ToolGatewayApplication,
    ToolGatewayError,
    ToolRegistry,
    create_gateway_server,
    create_server_tls_context,
)
from safeharness.gateway.protocol import invocation_from_wire, invocation_to_wire, request_to_wire
from safeharness.runtime import RuntimeConfig, RuntimeServices
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _descriptor() -> ToolDescriptor:
    return ToolDescriptor(
        "lookup",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        required_capabilities=frozenset({"lookup:read"}),
    )


def _context(**overrides) -> SessionContext:
    values = {
        "tenant_id": "tenant-a",
        "agent_id": "agent-a",
        "session_id": "session-a",
        "run_id": "run-a",
    }
    values.update(overrides)
    return SessionContext(**values)


def _invocation(tool: ToolDescriptor, **overrides) -> ToolInvocation:
    values = {
        "tool_name": tool.name,
        "arguments": {"query": "alarm"},
        "call_id": "call-a",
        "tool_version": tool.version,
    }
    values.update(overrides)
    return ToolInvocation(**values)


class SignedEnforcementReceiptTests(unittest.IsolatedAsyncioTestCase):
    async def test_receipt_binds_identity_policy_tool_and_invocation(self) -> None:
        tool = _descriptor()
        context = _context()
        invocation = _invocation(tool, intent_digest="a" * 64)
        authority = SignedEnforcementReceiptAuthority(b"r" * 32)

        receipt = await authority.issue(
            context,
            tool,
            invocation,
            decision_id="decision-a",
            event_id="event-a",
            policy_version="policy-7",
            workload_id="spiffe://safeharness/agent-a",
        )
        valid = await authority.verify(
            context,
            tool,
            invocation,
            receipt,
            expected_decision_id="decision-a",
            expected_event_id="event-a",
            expected_policy_version="policy-7",
            workload_id="spiffe://safeharness/agent-a",
        )
        changed = await authority.verify(
            context,
            tool,
            _invocation(tool, arguments={"query": "secret"}),
            receipt,
        )
        wrong_workload = await authority.verify(
            context,
            tool,
            invocation,
            receipt,
            workload_id="spiffe://safeharness/other",
        )

        self.assertTrue(valid.allowed)
        self.assertEqual(valid.claims["decision_id"], "decision-a")
        self.assertEqual(valid.claims["event_id"], "event-a")
        self.assertEqual(valid.claims["policy_version"], "policy-7")
        self.assertFalse(changed.allowed)
        self.assertEqual(changed.reason_code, "enforcement_receipt_identity_mismatch")
        self.assertFalse(wrong_workload.allowed)
        self.assertEqual(
            wrong_workload.reason_code, "enforcement_receipt_identity_mismatch"
        )

    async def test_receipt_expiry_tampering_and_replay_fail_closed(self) -> None:
        now = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
        clock = [now]
        tool = _descriptor()
        context = _context()
        invocation = _invocation(tool)
        authority = SignedEnforcementReceiptAuthority(
            b"r" * 32,
            now=lambda: clock[0],
            default_ttl=timedelta(seconds=30),
        )
        receipt = await authority.issue(
            context,
            tool,
            invocation,
            decision_id="decision-a",
            event_id="event-a",
            policy_version="policy-7",
        )

        first = await authority.verify(context, tool, invocation, receipt, consume=True)
        replay = await authority.verify(context, tool, invocation, receipt, consume=True)
        tampered = await authority.verify(
            context, tool, invocation, receipt[:-1] + ("A" if receipt[-1] != "A" else "B")
        )
        clock[0] = now + timedelta(minutes=1)
        expired = await authority.verify(context, tool, invocation, receipt)

        self.assertTrue(first.allowed)
        self.assertEqual(replay.reason_code, "enforcement_receipt_replayed")
        self.assertEqual(tampered.reason_code, "enforcement_receipt_invalid")
        self.assertEqual(expired.reason_code, "enforcement_receipt_expired")

    async def test_receipt_is_not_part_of_invocation_digest_or_legacy_wire_requirement(self) -> None:
        tool = _descriptor()
        original = _invocation(tool)
        with_receipt = _invocation(tool, enforcement_receipt="receipt-value")
        legacy_wire = invocation_to_wire(original)

        parsed = invocation_from_wire(legacy_wire)

        self.assertEqual(invocation_digest(original), invocation_digest(with_receipt))
        self.assertNotIn("enforcement_receipt", legacy_wire)
        self.assertIsNone(parsed.enforcement_receipt)
        receipt_wire = invocation_to_wire(with_receipt)
        self.assertEqual(receipt_wire["enforcement_receipt"], "receipt-value")
        self.assertEqual(
            invocation_from_wire(receipt_wire).enforcement_receipt,
            "receipt-value",
        )

    async def test_sqlite_receipt_replay_survives_store_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/gateway.sqlite3"
            now = datetime(2026, 7, 19, 8, 0, tzinfo=timezone.utc)
            expiry = now + timedelta(minutes=1)
            first = SQLiteEnforcementReceiptReplayStore(path, now=lambda: now)
            restarted = SQLiteEnforcementReceiptReplayStore(path, now=lambda: now)

            self.assertTrue(await first.consume("receipt-a", expiry))
            self.assertFalse(await restarted.consume("receipt-a", expiry))


class AsymmetricEnforcementReceiptTests(unittest.IsolatedAsyncioTestCase):
    async def test_ed25519_separates_signing_and_verification_authority(self) -> None:
        now = datetime(2026, 7, 20, 3, 0, tzinfo=timezone.utc)
        private_key = _test_private_key("separation")
        signer = Ed25519ReceiptSigner(private_key, key_id="noc-control-plane-2026-07")
        public_verifier = Ed25519ReceiptVerifier(
            private_key.public_key(),
            key_id=signer.key_id,
        )
        issuer = AsymmetricEnforcementReceiptIssuer(signer, now=lambda: now)
        verifier = AsymmetricEnforcementReceiptVerifier(
            [public_verifier],
            now=lambda: now,
        )
        tool = _descriptor()
        context = _context()
        invocation = _invocation(tool, intent_digest="a" * 64)

        receipt = await issuer.issue(
            context,
            tool,
            invocation,
            decision_id="decision-a",
            event_id="event-a",
            policy_version="policy-7",
            workload_id="spiffe://safeharness/agent-a",
        )
        result = await verifier.verify(
            context,
            tool,
            invocation,
            receipt,
            expected_decision_id="decision-a",
            expected_event_id="event-a",
            expected_policy_version="policy-7",
            workload_id="spiffe://safeharness/agent-a",
        )

        self.assertTrue(receipt.startswith("shr2."))
        self.assertTrue(result.allowed)
        self.assertEqual(result.claims["decision_id"], "decision-a")
        self.assertFalse(hasattr(verifier, "issue"))
        self.assertFalse(hasattr(public_verifier, "sign"))

    async def test_rotation_unknown_key_algorithm_confusion_and_tampering_fail(self) -> None:
        now = datetime(2026, 7, 20, 3, 0, tzinfo=timezone.utc)
        old_private = _test_private_key("rotation-old")
        current_private = _test_private_key("rotation-current")
        old_signer = Ed25519ReceiptSigner(old_private, key_id="receipt-old")
        current_signer = Ed25519ReceiptSigner(current_private, key_id="receipt-current")
        verifier = AsymmetricEnforcementReceiptVerifier(
            [
                Ed25519ReceiptVerifier(old_private.public_key(), key_id=old_signer.key_id),
                Ed25519ReceiptVerifier(
                    current_private.public_key(),
                    key_id=current_signer.key_id,
                ),
            ],
            now=lambda: now,
        )
        tool = _descriptor()
        context = _context()
        invocation = _invocation(tool)
        old_receipt = await _issue_asymmetric(old_signer, now, context, tool, invocation)
        current_receipt = await _issue_asymmetric(
            current_signer,
            now,
            context,
            tool,
            invocation,
        )
        unknown_private = _test_private_key("rotation-unknown")
        unknown_receipt = await _issue_asymmetric(
            Ed25519ReceiptSigner(unknown_private, key_id="receipt-unknown"),
            now,
            context,
            tool,
            invocation,
        )
        confused = AsymmetricEnforcementReceiptVerifier(
            [_AlgorithmConfusedVerifier(current_signer.key_id)],
            now=lambda: now,
        )
        tampered = current_receipt[:-1] + (
            "A" if current_receipt[-1] != "A" else "B"
        )

        old_result = await verifier.verify(context, tool, invocation, old_receipt)
        current_result = await verifier.verify(context, tool, invocation, current_receipt)
        unknown_result = await verifier.verify(context, tool, invocation, unknown_receipt)
        confused_result = await confused.verify(
            context,
            tool,
            invocation,
            current_receipt,
        )
        tampered_result = await verifier.verify(context, tool, invocation, tampered)

        self.assertTrue(old_result.allowed)
        self.assertTrue(current_result.allowed)
        self.assertEqual(unknown_result.reason_code, "enforcement_receipt_invalid")
        self.assertEqual(confused_result.reason_code, "enforcement_receipt_invalid")
        self.assertEqual(tampered_result.reason_code, "enforcement_receipt_invalid")

    async def test_external_signer_supports_async_kms_boundary(self) -> None:
        now = datetime(2026, 7, 20, 3, 0, tzinfo=timezone.utc)
        private_key = _test_private_key("external-kms")
        signed_messages = []

        async def kms_sign(message: bytes) -> bytes:
            signed_messages.append(message)
            return private_key.sign(message)

        signer = ExternalEnforcementReceiptSigner(
            algorithm="EdDSA",
            key_id="kms-key-version-42",
            sign=kms_sign,
        )
        issuer = AsymmetricEnforcementReceiptIssuer(signer, now=lambda: now)
        verifier = AsymmetricEnforcementReceiptVerifier(
            [
                Ed25519ReceiptVerifier(
                    private_key.public_key(),
                    key_id=signer.key_id,
                )
            ],
            now=lambda: now,
        )
        tool = _descriptor()
        context = _context()
        invocation = _invocation(tool)

        receipt = await issuer.issue(
            context,
            tool,
            invocation,
            decision_id="decision-a",
            event_id="event-a",
            policy_version="policy-7",
        )
        result = await verifier.verify(context, tool, invocation, receipt)

        self.assertTrue(result.allowed)
        self.assertEqual(len(signed_messages), 1)
        self.assertTrue(signed_messages[0].startswith(b"shr2."))

    async def test_asymmetric_expiry_and_replay_fail_closed(self) -> None:
        now = datetime(2026, 7, 20, 3, 0, tzinfo=timezone.utc)
        clock = [now]
        private_key = _test_private_key("expiry-replay")
        signer = Ed25519ReceiptSigner(private_key, key_id="receipt-current")
        issuer = AsymmetricEnforcementReceiptIssuer(
            signer,
            now=lambda: clock[0],
            default_ttl=timedelta(seconds=30),
        )
        verifier = AsymmetricEnforcementReceiptVerifier(
            [Ed25519ReceiptVerifier(private_key.public_key(), key_id=signer.key_id)],
            now=lambda: clock[0],
        )
        tool = _descriptor()
        context = _context()
        invocation = _invocation(tool)
        receipt = await issuer.issue(
            context,
            tool,
            invocation,
            decision_id="decision-a",
            event_id="event-a",
            policy_version="policy-7",
        )

        first = await verifier.verify(context, tool, invocation, receipt, consume=True)
        replay = await verifier.verify(context, tool, invocation, receipt, consume=True)
        clock[0] = now + timedelta(minutes=1)
        expired = await verifier.verify(context, tool, invocation, receipt)

        self.assertTrue(first.allowed)
        self.assertEqual(replay.reason_code, "enforcement_receipt_replayed")
        self.assertEqual(expired.reason_code, "enforcement_receipt_expired")

    async def test_strict_gateway_accepts_asymmetric_receipt_and_rejects_replay(self) -> None:
        now = datetime(2026, 7, 20, 3, 0, tzinfo=timezone.utc)
        private_key = _test_private_key("strict-gateway")
        signer = Ed25519ReceiptSigner(private_key, key_id="receipt-current")
        issuer = AsymmetricEnforcementReceiptIssuer(signer, now=lambda: now)
        verifier = AsymmetricEnforcementReceiptVerifier(
            [Ed25519ReceiptVerifier(private_key.public_key(), key_id=signer.key_id)],
            now=lambda: now,
        )
        tool = _descriptor()
        context = _context()
        invocation = _invocation(tool)
        calls = []
        capabilities = SignedCapabilityGateway(
            b"c" * 32,
            {("tenant-a", "agent-a"): {"lookup:read"}},
        )
        application = ToolGatewayApplication(
            registry=ToolRegistry(
                [RegisteredTool(tool, lambda query: calls.append(query) or query)]
            ),
            capability_gateway=capabilities,
            enforcement_receipt_verifier=verifier,
            require_enforcement_receipt=True,
        )
        grant = await capabilities.issue(context, tool, invocation)
        receipt = await issuer.issue(
            context,
            tool,
            invocation,
            decision_id="decision-a",
            event_id="event-a",
            policy_version="policy-7",
        )
        bound = _invocation(
            tool,
            capability_token=grant.token,
            enforcement_receipt=receipt,
        )

        success_status, _ = await application.execute(request_to_wire(context, bound))
        replay_status, replay_response = await application.execute(
            request_to_wire(context, bound)
        )

        self.assertEqual(success_status, 200)
        self.assertEqual(replay_status, 403)
        self.assertIn(
            replay_response["error"]["code"],
            {"capability_token_replayed", "enforcement_receipt_replayed"},
        )
        self.assertEqual(calls, ["alarm"])

    async def test_asymmetric_receipt_round_trip_crosses_real_http_boundary(self) -> None:
        now = datetime(2026, 7, 20, 3, 0, tzinfo=timezone.utc)
        private_key = _test_private_key("http-boundary")
        signer = Ed25519ReceiptSigner(private_key, key_id="receipt-current")
        issuer = AsymmetricEnforcementReceiptIssuer(signer, now=lambda: now)
        verifier = AsymmetricEnforcementReceiptVerifier(
            [Ed25519ReceiptVerifier(private_key.public_key(), key_id=signer.key_id)],
            now=lambda: now,
        )
        tool = _descriptor()
        context = _context()
        invocation = _invocation(tool)
        calls = []
        capabilities = SignedCapabilityGateway(
            b"c" * 32,
            {("tenant-a", "agent-a"): {"lookup:read"}},
        )
        application = ToolGatewayApplication(
            registry=ToolRegistry(
                [RegisteredTool(tool, lambda query: calls.append(query) or query.upper())]
            ),
            capability_gateway=capabilities,
            enforcement_receipt_verifier=verifier,
            require_enforcement_receipt=True,
        )
        server = create_gateway_server(
            application,
            host="127.0.0.1",
            port=0,
            api_key="a" * 32,
            tenant_id="tenant-a",
            agent_id="agent-a",
        )
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = RemoteToolGatewayClient(
                f"http://127.0.0.1:{server.server_address[1]}",
                "a" * 32,
            )
            grant = await client.issue(context, tool, invocation)
            receipt = await issuer.issue(
                context,
                tool,
                invocation,
                decision_id="decision-a",
                event_id="event-a",
                policy_version="policy-7",
            )
            bound = _invocation(
                tool,
                capability_token=grant.token,
                enforcement_receipt=receipt,
            )
            result = await client.execute(context, bound)
            with self.assertRaises(ToolGatewayError) as replayed:
                await client.execute(context, bound)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(result, "ALARM")
        self.assertIn(
            replayed.exception.code,
            {"capability_token_replayed", "enforcement_receipt_replayed"},
        )
        self.assertEqual(calls, ["alarm"])


async def _issue_asymmetric(signer, now, context, tool, invocation) -> str:
    issuer = AsymmetricEnforcementReceiptIssuer(signer, now=lambda: now)
    return await issuer.issue(
        context,
        tool,
        invocation,
        decision_id="decision-a",
        event_id="event-a",
        policy_version="policy-7",
    )


def _test_private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


class _AlgorithmConfusedVerifier:
    algorithm = "ES256"

    def __init__(self, key_id: str) -> None:
        self.key_id = key_id

    async def verify(self, message: bytes, signature: bytes) -> bool:
        raise AssertionError("algorithm-confused verifier must not be called")


class GatewayTLSConfigurationTests(unittest.TestCase):
    def test_client_tls_context_requires_https(self) -> None:
        context = ssl.create_default_context()
        with self.assertRaises(ValueError):
            RemoteToolGatewayClient(
                "http://127.0.0.1:38100", "a" * 32, tls_context=context
            )

    def test_strict_mtls_cannot_run_without_cert_required_context(self) -> None:
        tool = _descriptor()
        application = ToolGatewayApplication(
            registry=ToolRegistry([RegisteredTool(tool, lambda query: query)]),
            capability_gateway=SignedCapabilityGateway(b"c" * 32, {}),
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        with self.assertRaises(ValueError):
            create_gateway_server(
                application,
                port=0,
                api_key="a" * 32,
                tls_context=context,
                require_mtls_identity=True,
            )

    def test_real_mtls_handshake_uses_verified_spiffe_uri_san(self) -> None:
        material = _test_mtls_material()
        if material is None:
            self.skipTest("openssl is unavailable")
        directory, paths = material
        self.addCleanup(directory.cleanup)
        tool = _descriptor()
        application = ToolGatewayApplication(
            registry=ToolRegistry([RegisteredTool(tool, lambda query: query)]),
            capability_gateway=SignedCapabilityGateway(b"c" * 32, {}),
            workload_identity="spiffe://fiberhome/safeharness/noc-agent",
        )
        server = create_gateway_server(
            application,
            host="127.0.0.1",
            port=0,
            api_key="a" * 32,
            tenant_id="tenant-a",
            agent_id="agent-a",
            tls_context=create_server_tls_context(
                certificate=paths["server_cert"],
                private_key=paths["server_key"],
                client_ca=paths["ca_cert"],
                require_client_certificate=True,
            ),
            require_mtls_identity=True,
        )
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client_context = ssl.create_default_context(cafile=paths["ca_cert"])
            client_context.load_cert_chain(paths["client_cert"], paths["client_key"])
            client = RemoteToolGatewayClient(
                f"https://localhost:{server.server_address[1]}",
                "a" * 32,
                tls_context=client_context,
            )
            health = asyncio.run(client.health())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(health["status"], "ready")


class ToolGatewayReceiptTests(unittest.IsolatedAsyncioTestCase):
    async def test_strict_gateway_requires_and_consumes_independent_receipt(self) -> None:
        tool = _descriptor()
        context = _context()
        calls = []
        capabilities = SignedCapabilityGateway(
            b"c" * 32,
            {("tenant-a", "agent-a"): {"lookup:read"}},
        )
        receipt_authority = SignedEnforcementReceiptAuthority(b"r" * 32)
        application = ToolGatewayApplication(
            registry=ToolRegistry(
                [RegisteredTool(tool, lambda query: calls.append(query) or query)]
            ),
            capability_gateway=capabilities,
            enforcement_receipt_verifier=receipt_authority,
            require_enforcement_receipt=True,
        )
        invocation = _invocation(tool)
        grant = await capabilities.issue(context, tool, invocation)
        capability_bound = _invocation(tool, capability_token=grant.token)

        missing_status, missing = await application.execute(
            request_to_wire(context, capability_bound)
        )
        receipt = await receipt_authority.issue(
            context,
            tool,
            invocation,
            decision_id="decision-a",
            event_id="event-a",
            policy_version="policy-7",
        )
        bound = _invocation(
            tool,
            capability_token=grant.token,
            enforcement_receipt=receipt,
        )
        success_status, success = await application.execute(request_to_wire(context, bound))
        replay_status, replay = await application.execute(request_to_wire(context, bound))

        self.assertEqual(missing_status, 403)
        self.assertEqual(missing["error"]["code"], "enforcement_receipt_missing")
        self.assertEqual(success_status, 200)
        self.assertEqual(success["result"], "alarm")
        self.assertEqual(replay_status, 403)
        self.assertIn(
            replay["error"]["code"],
            {"capability_token_replayed", "enforcement_receipt_replayed"},
        )
        self.assertEqual(calls, ["alarm"])

    async def test_invalid_capability_does_not_consume_a_valid_receipt(self) -> None:
        tool = _descriptor()
        context = _context()
        receipt_authority = SignedEnforcementReceiptAuthority(b"r" * 32)
        capabilities = SignedCapabilityGateway(
            b"c" * 32,
            {("tenant-a", "agent-a"): {"lookup:read"}},
        )
        calls = []
        application = ToolGatewayApplication(
            registry=ToolRegistry(
                [RegisteredTool(tool, lambda query: calls.append(query) or query)]
            ),
            capability_gateway=capabilities,
            enforcement_receipt_verifier=receipt_authority,
            require_enforcement_receipt=True,
        )
        invocation = _invocation(tool)
        receipt = await receipt_authority.issue(
            context,
            tool,
            invocation,
            decision_id="decision-a",
            event_id="event-a",
            policy_version="policy-7",
        )
        invalid = _invocation(
            tool,
            capability_token="not-a-capability",
            enforcement_receipt=receipt,
        )
        invalid_status, invalid_response = await application.execute(
            request_to_wire(context, invalid)
        )
        grant = await capabilities.issue(context, tool, invocation)
        valid = _invocation(
            tool,
            capability_token=grant.token,
            enforcement_receipt=receipt,
        )
        valid_status, valid_response = await application.execute(
            request_to_wire(context, valid)
        )

        self.assertEqual(invalid_status, 403)
        self.assertEqual(invalid_response["error"]["code"], "capability_token_invalid")
        self.assertEqual(valid_status, 200)
        self.assertEqual(valid_response["result"], "alarm")
        self.assertEqual(calls, ["alarm"])

    async def test_runtime_issues_receipt_after_allow_and_gateway_audits_fingerprint(self) -> None:
        tool = _descriptor()
        context = _context(metadata={"workload_id": "agent-workload-a"})
        receipt_authority = SignedEnforcementReceiptAuthority(b"r" * 32)
        capability_gateway = SignedCapabilityGateway(
            b"c" * 32,
            {("tenant-a", "agent-a"): {"lookup:read"}},
        )
        gateway_audit = _GatewayAuditSink()
        application = ToolGatewayApplication(
            registry=ToolRegistry([RegisteredTool(tool, lambda query: query.upper())]),
            capability_gateway=capability_gateway,
            enforcement_receipt_verifier=receipt_authority,
            require_enforcement_receipt=True,
            workload_identity="agent-workload-a",
            audit_sink=gateway_audit,
        )
        runtime = SafeHarnessRuntime(
            services=RuntimeServices(
                tool_catalog=StaticToolCatalog([tool]),
                capability_authority=_InspectingAuthority(capability_gateway),
                enforcement_receipt_issuer=receipt_authority,
                audit_sink=InMemoryAuditSink(),
            ),
            config=RuntimeConfig(policy_version="policy-runtime-1"),
        )
        invocation = _invocation(tool)
        grant = await capability_gateway.issue(context, tool, invocation)
        observed_receipt = []
        gateway_responses = []

        async def executor(effective: ToolInvocation):
            observed_receipt.append(effective.enforcement_receipt)
            status, response = await application.execute(request_to_wire(context, effective))
            gateway_responses.append((status, response))
            if status != 200:
                raise AssertionError(response)
            return response["result"]

        async with runtime.session(context) as session:
            outcome = await execute_invocation(
                session,
                invocation,
                executor,
                capability_token=grant.token,
            )

        receipt = observed_receipt[0]
        self.assertFalse(
            outcome.blocked,
            msg=(
                outcome.decision.reasons[-1].code
                if outcome.decision.reasons
                else outcome.error
            ),
        )
        self.assertIsNone(outcome.error, msg=str(gateway_responses))
        self.assertEqual(outcome.result, "ALARM")
        self.assertIsInstance(receipt, str)
        self.assertNotIn(receipt, str(gateway_audit.records))
        dispatch = next(record for record in gateway_audit.records if record.outcome == "dispatched")
        self.assertEqual(
            dispatch.details["enforcement_receipt_fingerprint"],
            hashlib.sha256(receipt.encode()).hexdigest(),
        )

    async def test_agent_audit_never_persists_receipt_token(self) -> None:
        tool = _descriptor()
        context = _context()
        receipt_authority = SignedEnforcementReceiptAuthority(b"r" * 32)
        capability_gateway = SignedCapabilityGateway(
            b"c" * 32,
            {("tenant-a", "agent-a"): {"lookup:read"}},
        )
        audit = InMemoryAuditSink()
        runtime = SafeHarnessRuntime(
            services=RuntimeServices(
                tool_catalog=StaticToolCatalog([tool]),
                capability_authority=_InspectingAuthority(capability_gateway),
                enforcement_receipt_issuer=receipt_authority,
                audit_sink=audit,
            ),
            config=RuntimeConfig(policy_version="policy-runtime-1"),
        )
        invocation = _invocation(tool)
        grant = await capability_gateway.issue(context, tool, invocation)
        observed = []

        async def executor(effective):
            observed.append(effective.enforcement_receipt)
            return "ok"

        async with runtime.session(context) as session:
            await execute_invocation(
                session, invocation, executor, capability_token=grant.token
            )

        self.assertIsInstance(observed[0], str)
        self.assertNotIn(observed[0], str(audit.records))
        self.assertTrue(
            all(
                "enforcement_receipt" not in record.event.payload
                for record in audit.records
            )
        )

    async def test_agent_adapter_rejects_caller_supplied_receipt(self) -> None:
        tool = _descriptor()
        runtime = SafeHarnessRuntime(
            services=RuntimeServices(
                tool_catalog=StaticToolCatalog([tool]),
                capability_authority=SignedCapabilityGateway(
                    b"c" * 32,
                    {("tenant-a", "agent-a"): {"lookup:read"}},
                ),
            )
        )
        async with runtime.session(_context()) as session:
            with self.assertRaises(ValueError):
                await execute_invocation(
                    session,
                    _invocation(tool, enforcement_receipt="caller-controlled"),
                    lambda invocation: invocation,
                )


class _GatewayAuditSink:
    def __init__(self) -> None:
        self.records = []

    async def write_gateway(self, record) -> None:
        self.records.append(record)


class _InspectingAuthority:
    def __init__(self, authority) -> None:
        self.authority = authority

    async def authorize(self, context, descriptor, invocation):
        return await self.authority.inspect(context, descriptor, invocation)


def _test_mtls_material():
    openssl = shutil.which("openssl")
    if openssl is None:
        return None
    directory = tempfile.TemporaryDirectory()
    root = Path(directory.name)
    paths = {
        "ca_cert": str(root / "ca.pem"),
        "ca_key": str(root / "ca.key"),
        "server_cert": str(root / "server.pem"),
        "server_key": str(root / "server.key"),
        "server_csr": str(root / "server.csr"),
        "client_cert": str(root / "client.pem"),
        "client_key": str(root / "client.key"),
        "client_csr": str(root / "client.csr"),
    }
    commands = (
        (
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", paths["ca_key"], "-out", paths["ca_cert"],
            "-subj", "/CN=SafeHarness Test CA", "-days", "1",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ),
        (
            "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", paths["server_key"], "-out", paths["server_csr"],
            "-subj", "/CN=localhost",
        ),
        (
            "x509", "-req", "-in", paths["server_csr"],
            "-CA", paths["ca_cert"], "-CAkey", paths["ca_key"],
            "-CAcreateserial", "-out", paths["server_cert"], "-days", "1",
            "-extfile", str(root / "server.ext"),
        ),
        (
            "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", paths["client_key"], "-out", paths["client_csr"],
            "-subj", "/CN=noc-agent",
        ),
        (
            "x509", "-req", "-in", paths["client_csr"],
            "-CA", paths["ca_cert"], "-CAkey", paths["ca_key"],
            "-CAcreateserial", "-out", paths["client_cert"], "-days", "1",
            "-extfile", str(root / "client.ext"),
        ),
    )
    (root / "server.ext").write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
        encoding="ascii",
    )
    (root / "client.ext").write_text(
        "subjectAltName=URI:spiffe://fiberhome/safeharness/noc-agent\n"
        "extendedKeyUsage=clientAuth\n",
        encoding="ascii",
    )
    try:
        for command in commands:
            subprocess.run(
                (openssl, *command),
                check=True,
                capture_output=True,
                timeout=15,
            )
    except (OSError, subprocess.SubprocessError):
        directory.cleanup()
        return None
    return directory, paths


if __name__ == "__main__":
    unittest.main()
