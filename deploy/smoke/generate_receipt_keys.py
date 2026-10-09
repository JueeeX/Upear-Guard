"""Generate or validate an isolated Ed25519 staging receipt key pair."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def main() -> None:
    private_path = Path(
        os.environ.get(
            "SAFEHARNESS_ENFORCEMENT_RECEIPT_PRIVATE_KEY_FILE",
            "/receipt-private/receipt-private.pem",
        )
    )
    public_path = Path(
        os.environ.get(
            "SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILE",
            "/receipt-public/receipt-public.pem",
        )
    )
    owner = _safeharness_identity()
    _prepare_directory(private_path.parent, mode=0o700, owner=owner)
    _prepare_directory(public_path.parent, mode=0o755, owner=owner)
    if private_path.exists() or public_path.exists():
        if not private_path.is_file() or not public_path.is_file():
            raise RuntimeError("receipt key volumes contain an incomplete key pair")
        _take_ownership(private_path, owner=owner)
        _take_ownership(public_path, owner=owner)
        _validate_pair(private_path, public_path)
        _secure_file(private_path, mode=0o400, owner=owner)
        _secure_file(public_path, mode=0o444, owner=owner)
        _secure_file(private_path.parent, mode=0o700, owner=owner)
        _secure_file(public_path.parent, mode=0o755, owner=owner)
        print("SafeHarness asymmetric staging receipt key pair is ready.")
        return

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_temp = _write_temporary(
        private_path.parent,
        private_pem,
        mode=0o400,
    )
    public_temp = _write_temporary(
        public_path.parent,
        public_pem,
        mode=0o444,
    )
    try:
        os.replace(private_temp, private_path)
        os.replace(public_temp, public_path)
    finally:
        Path(private_temp).unlink(missing_ok=True)
        Path(public_temp).unlink(missing_ok=True)
    _validate_pair(private_path, public_path)
    _secure_file(private_path, mode=0o400, owner=owner)
    _secure_file(public_path, mode=0o444, owner=owner)
    _secure_file(private_path.parent, mode=0o700, owner=owner)
    _secure_file(public_path.parent, mode=0o755, owner=owner)
    print("SafeHarness asymmetric staging receipt key pair is ready.")


def _write_temporary(
    directory: Path,
    content: bytes,
    *,
    mode: int,
) -> str:
    descriptor, path = tempfile.mkstemp(prefix=".receipt-key-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, mode)
    except Exception:
        Path(path).unlink(missing_ok=True)
        raise
    return path


def _prepare_directory(
    path: Path,
    *,
    mode: int,
    owner: tuple[int, int] | None,
) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _take_ownership(path, owner=owner)
    os.chmod(path, mode)


def _secure_file(
    path: Path,
    *,
    mode: int,
    owner: tuple[int, int] | None,
) -> None:
    if owner is not None:
        os.chown(path, os.geteuid(), os.getegid())
    os.chmod(path, mode)
    if owner is not None:
        os.chown(path, *owner)


def _take_ownership(path: Path, *, owner: tuple[int, int] | None) -> None:
    if owner is not None:
        os.chown(path, os.geteuid(), os.getegid())


def _safeharness_identity() -> tuple[int, int] | None:
    if os.name != "posix" or os.geteuid() != 0:
        return None
    import pwd

    account = pwd.getpwnam("safeharness")
    return account.pw_uid, account.pw_gid


def _validate_pair(private_path: Path, public_path: Path) -> None:
    private_key = serialization.load_pem_private_key(
        private_path.read_bytes(),
        password=None,
    )
    public_key = serialization.load_pem_public_key(public_path.read_bytes())
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RuntimeError("staging receipt private key is not Ed25519")
    if not isinstance(public_key, Ed25519PublicKey):
        raise RuntimeError("staging receipt public key is not Ed25519")
    expected_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    actual_public = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if expected_public != actual_public:
        raise RuntimeError("staging receipt public key does not match the private key")


if __name__ == "__main__":
    main()
