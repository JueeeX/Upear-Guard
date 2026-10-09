from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safeharness import SessionContext, ToolDescriptor, ToolInvocation
from safeharness.backends import (
    AsymmetricEnforcementReceiptIssuer,
    AsymmetricEnforcementReceiptVerifier,
    Ed25519ReceiptSigner,
    SignedEnforcementReceiptAuthority,
    build_enforcement_receipt_issuer_from_environment,
    build_enforcement_receipt_verifier_from_environment,
)
from examples.langgraph_noc.tool_gateway import build_gateway_application


class ReceiptEnvironmentConfigurationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.private_key = _test_private_key("configuration-current")
        self.private_path, self.public_path = _write_key_pair(
            self.root,
            "receipt-current",
            self.private_key,
        )

    async def test_ed25519_environment_separates_agent_and_gateway_keys(self) -> None:
        issuer = build_enforcement_receipt_issuer_from_environment(
            {
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE": "ed25519",
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_KEY_ID": "receipt-current",
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_PRIVATE_KEY_FILE": str(
                    self.private_path
                ),
            }
        )
        verifier = build_enforcement_receipt_verifier_from_environment(
            environ={
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE": "ed25519",
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_KEY_ID": "receipt-current",
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILE": str(
                    self.public_path
                ),
            }
        )
        context, tool, invocation = _request()

        receipt = await issuer.issue(
            context,
            tool,
            invocation,
            decision_id="decision-a",
            event_id="event-a",
            policy_version="policy-a",
        )
        result = await verifier.verify(context, tool, invocation, receipt)

        self.assertIsInstance(issuer, AsymmetricEnforcementReceiptIssuer)
        self.assertIsInstance(verifier, AsymmetricEnforcementReceiptVerifier)
        self.assertTrue(result.allowed)
        self.assertFalse(hasattr(verifier, "issue"))

    async def test_public_key_json_supports_rotation(self) -> None:
        old_private = _test_private_key("configuration-old")
        _, old_public_path = _write_key_pair(self.root, "receipt-old", old_private)
        verifier = build_enforcement_receipt_verifier_from_environment(
            environ={
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE": "ed25519",
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILES": json.dumps(
                    {
                        "receipt-current": str(self.public_path),
                        "receipt-old": str(old_public_path),
                    }
                ),
            }
        )
        context, tool, invocation = _request()

        results = []
        for key_id, private_key in (
            ("receipt-current", self.private_key),
            ("receipt-old", old_private),
        ):
            issuer = AsymmetricEnforcementReceiptIssuer(
                Ed25519ReceiptSigner(private_key, key_id=key_id)
            )
            receipt = await issuer.issue(
                context,
                tool,
                invocation,
                decision_id="decision-a",
                event_id="event-a",
                policy_version="policy-a",
            )
            results.append(await verifier.verify(context, tool, invocation, receipt))

        self.assertTrue(all(result.allowed for result in results))

    async def test_hmac_environment_remains_compatible(self) -> None:
        values = {"SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY": "r" * 32}
        issuer = build_enforcement_receipt_issuer_from_environment(values)
        verifier = build_enforcement_receipt_verifier_from_environment(environ=values)
        context, tool, invocation = _request()

        receipt = await issuer.issue(
            context,
            tool,
            invocation,
            decision_id="decision-a",
            event_id="event-a",
            policy_version="policy-a",
        )
        result = await verifier.verify(context, tool, invocation, receipt)

        self.assertIsInstance(issuer, SignedEnforcementReceiptAuthority)
        self.assertIsInstance(verifier, SignedEnforcementReceiptAuthority)
        self.assertTrue(result.allowed)

    def test_gateway_rejects_private_key_and_ambiguous_modes(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not receive.*private key"):
            build_enforcement_receipt_verifier_from_environment(
                environ={
                    "SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE": "ed25519",
                    "SAFEHARNESS_ENFORCEMENT_RECEIPT_KEY_ID": "receipt-current",
                    "SAFEHARNESS_ENFORCEMENT_RECEIPT_PRIVATE_KEY_FILE": str(
                        self.private_path
                    ),
                    "SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILE": str(
                        self.public_path
                    ),
                }
            )
        with self.assertRaisesRegex(ValueError, "requires.*MODE=hmac"):
            build_enforcement_receipt_issuer_from_environment(
                {
                    "SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE": "ed25519",
                    "SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY": "r" * 32,
                    "SAFEHARNESS_ENFORCEMENT_RECEIPT_KEY_ID": "receipt-current",
                    "SAFEHARNESS_ENFORCEMENT_RECEIPT_PRIVATE_KEY_FILE": str(
                        self.private_path
                    ),
                }
            )

    def test_kms_mode_requires_an_explicit_provider_adapter(self) -> None:
        with self.assertRaisesRegex(ValueError, "ExternalEnforcementReceiptSigner"):
            build_enforcement_receipt_issuer_from_environment(
                {"SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE": "kms"}
            )

    def test_gateway_builder_rejects_shared_key_plus_explicit_verifier(self) -> None:
        verifier = build_enforcement_receipt_verifier_from_environment(
            environ={
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE": "ed25519",
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_KEY_ID": "receipt-current",
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILE": str(
                    self.public_path
                ),
            }
        )

        with self.assertRaisesRegex(ValueError, "either an HMAC.*or an explicit"):
            build_gateway_application(
                signing_key="s" * 32,
                enforcement_receipt_key="r" * 32,
                enforcement_receipt_verifier=verifier,
            )


def _request() -> tuple[SessionContext, ToolDescriptor, ToolInvocation]:
    context = SessionContext(
        tenant_id="tenant-a",
        agent_id="agent-a",
        session_id="session-a",
        run_id="run-a",
    )
    tool = ToolDescriptor(
        "lookup",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
    )
    invocation = ToolInvocation(
        tool.name,
        {"query": "alarm"},
        call_id="call-a",
        tool_version=tool.version,
    )
    return context, tool, invocation


def _write_key_pair(
    root: Path,
    name: str,
    private_key: Ed25519PrivateKey,
) -> tuple[Path, Path]:
    private_path = root / f"{name}-private.pem"
    public_path = root / f"{name}-public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def _test_private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


if __name__ == "__main__":
    unittest.main()
