from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.smoke.generate_receipt_keys import main


class ReceiptKeyGenerationTests(unittest.TestCase):
    def test_keygen_creates_and_reuses_the_same_valid_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_path = Path(directory) / "private" / "receipt-private.pem"
            public_path = Path(directory) / "public" / "receipt-public.pem"
            values = {
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_PRIVATE_KEY_FILE": str(private_path),
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILE": str(public_path),
            }
            private_key = Ed25519PrivateKey.from_private_bytes(b"k" * 32)
            with patch(
                "deploy.smoke.generate_receipt_keys.Ed25519PrivateKey.generate",
                return_value=private_key,
            ), patch.dict(os.environ, values, clear=True):
                main()
                first_private = private_path.read_bytes()
                first_public = public_path.read_bytes()
                main()

            self.assertEqual(private_path.read_bytes(), first_private)
            self.assertEqual(public_path.read_bytes(), first_public)
            self.assertIn(b"BEGIN PRIVATE KEY", first_private)
            self.assertIn(b"BEGIN PUBLIC KEY", first_public)

    def test_keygen_rejects_an_incomplete_persistent_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_path = Path(directory) / "private" / "receipt-private.pem"
            public_path = Path(directory) / "public" / "receipt-public.pem"
            private_path.parent.mkdir(parents=True)
            private_path.write_bytes(b"incomplete")
            values = {
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_PRIVATE_KEY_FILE": str(private_path),
                "SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILE": str(public_path),
            }

            with patch.dict(os.environ, values, clear=True):
                with self.assertRaisesRegex(RuntimeError, "incomplete key pair"):
                    main()


if __name__ == "__main__":
    unittest.main()
