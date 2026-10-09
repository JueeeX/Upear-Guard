"""Run the staging smoke path with an isolated asymmetric receipt key."""

from __future__ import annotations

import asyncio
import os

from deploy.smoke.staging_smoke import main as staging_main


async def main() -> None:
    if os.environ.get("SAFEHARNESS_ENFORCEMENT_RECEIPT_MODE", "").lower() != "ed25519":
        raise RuntimeError("asymmetric receipt smoke requires ed25519 mode")
    if os.environ.get("SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY"):
        raise RuntimeError("asymmetric receipt smoke must not receive an HMAC receipt key")
    await staging_main()
    print("SafeHarness asymmetric receipt smoke test passed: private/public trust split.")


if __name__ == "__main__":
    asyncio.run(main())
