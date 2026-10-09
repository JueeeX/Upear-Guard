"""Initialize the isolated SUMC identity used by the product demo."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")


def main() -> None:
    database_url = os.environ.get("DATABASE_URL", "")
    password = os.environ.pop("SAFEHARNESS_DEMO_ADMIN_PASSWORD", "")
    tenant_id = os.environ.get("SAFEHARNESS_DEMO_TENANT_ID", "fiberhome-demo")
    if not database_url.startswith("sqlite:///"):
        raise SystemExit("DATABASE_URL must point to the isolated demo SQLite database")
    if password != "admin123":
        raise SystemExit("SAFEHARNESS_DEMO_ADMIN_PASSWORD must be admin123 for the product demo")
    if _IDENTIFIER.fullmatch(tenant_id) is None:
        raise SystemExit("SAFEHARNESS_DEMO_TENANT_ID is invalid")

    from core.auth.password import hash_password, verify_password
    from core.db.engine import SessionLocal, init_db
    from core.db.models import LocalUser, UserShadow
    from core.services.local_user_service import (
        CE_ONBOARDING_VERSION,
        ensure_ce_default_admin,
    )

    init_db()
    db = SessionLocal()
    try:
        user_id, _created = ensure_ce_default_admin(db)
        if not user_id:
            raise RuntimeError("demo administrator could not be initialized")
        shadow = db.get(UserShadow, user_id)
        local = db.get(LocalUser, user_id)
        if shadow is None or local is None:
            raise RuntimeError("demo administrator records are incomplete")

        metadata = dict(shadow.extra_data or {})
        metadata.update(
            {
                "tenant_id": tenant_id,
                "role": "super_admin",
                "onboarding_completed_version": CE_ONBOARDING_VERSION,
            }
        )
        metadata.pop("must_change_password", None)
        metadata.pop("onboarding_required", None)
        shadow.extra_data = metadata
        shadow.updated_at = datetime.now(timezone.utc)
        local.password_hash = hash_password(password)
        local.password_updated_at = datetime.now(timezone.utc)
        local.status = "active"
        db.commit()

        db.refresh(shadow)
        db.refresh(local)
        if shadow.extra_data.get("tenant_id") != tenant_id:
            raise RuntimeError("demo tenant binding was not persisted")
        if shadow.extra_data.get("role") != "super_admin":
            raise RuntimeError("demo role binding was not persisted")
        if not verify_password(password, local.password_hash):
            raise RuntimeError("demo password verification failed")
    finally:
        db.close()

    print(f"Demo identity ready: admin tenant={tenant_id} role=super_admin")


if __name__ == "__main__":
    main()
