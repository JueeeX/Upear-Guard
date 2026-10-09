from __future__ import annotations

from pathlib import Path
import re
import unittest

from deploy.compose.validate_env import configuration_errors


class DeploymentConfigurationTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[1]

    def test_distinct_url_safe_secrets_are_accepted(self) -> None:
        values = _valid_values()

        self.assertEqual(configuration_errors(values), ())

    def test_placeholders_weak_values_and_reuse_are_rejected_without_values(self) -> None:
        values = _valid_values()
        values["SAFEHARNESS_GATEWAY_API_KEY"] = "replace-with-at-least-32-characters"
        values["SAFEHARNESS_REDIS_PASSWORD"] = "short"
        values["SAFEHARNESS_POSTGRES_READER_PASSWORD"] = values[
            "SAFEHARNESS_POSTGRES_WRITER_PASSWORD"
        ]

        errors = configuration_errors(values)
        serialized = "\n".join(errors)

        self.assertIn("SAFEHARNESS_GATEWAY_API_KEY still contains", serialized)
        self.assertIn("SAFEHARNESS_REDIS_PASSWORD must contain", serialized)
        self.assertIn("separate secrets are required", serialized)
        self.assertNotIn("replace-with-at-least-32-characters", serialized)

    def test_dsn_unsafe_characters_are_rejected(self) -> None:
        values = _valid_values()
        values["SAFEHARNESS_POSTGRES_ADMIN_PASSWORD"] = "unsafe/password-value"

        errors = configuration_errors(values)

        self.assertIn(
            "SAFEHARNESS_POSTGRES_ADMIN_PASSWORD must use URL-safe characters "
            "in this staging stack",
            errors,
        )

    def test_staging_wires_strict_receipts_and_redis_namespace(self) -> None:
        compose = (self.root / "deploy/compose/compose.yaml").read_text(
            encoding="utf-8"
        )
        redis_acl = (self.root / "deploy/redis/start-redis.sh").read_text(
            encoding="utf-8"
        )
        alerts = (self.root / "deploy/observability/alerts.yaml").read_text(
            encoding="utf-8"
        )

        self.assertEqual(compose.count('SAFEHARNESS_REQUIRE_ENFORCEMENT_RECEIPT: "true"'), 6)
        self.assertIn("~safeharness:receipt-replay:*", redis_acl)
        self.assertIn(
            "user safeharness_communication on ",
            redis_acl,
        )
        self.assertIn("~safeharness:communication-rate:*", redis_acl)
        self.assertIn("-@all +incr +pexpireat +multi +exec +ping +quit", redis_acl)
        self.assertIn("enforcement_receipt_store_unavailable", alerts)
        self.assertIn("enforcement_receipt_identity_mismatch", alerts)

    def test_communication_maintenance_uses_dedicated_identities(self) -> None:
        compose = (self.root / "deploy/compose/compose.yaml").read_text(
            encoding="utf-8"
        )
        bootstrap = (self.root / "deploy/postgres/bootstrap.sh").read_text(
            encoding="utf-8"
        )
        config_check = _service_block(compose, "config-check")
        postgres = _service_block(compose, "postgres")
        migration = _service_block(compose, "communication-postgres-migrate")
        maintenance = _service_block(compose, "communication-maintenance")

        self.assertIn("CREATE ROLE safeharness_retention LOGIN PASSWORD", bootstrap)
        self.assertIn("TO safeharness_writer, safeharness_reader, safeharness_retention", bootstrap)
        for service in (config_check, postgres):
            self.assertIn("SAFEHARNESS_POSTGRES_RETENTION_PASSWORD", service)
        self.assertIn("SAFEHARNESS_REDIS_COMMUNICATION_PASSWORD", config_check)
        self.assertIn(
            "SAFEHARNESS_COMMUNICATION_RETENTION_ROLE: safeharness_retention",
            migration,
        )
        self.assertIn("safeharness_retention:", maintenance)
        self.assertIn("safeharness_reader:", maintenance)
        self.assertNotIn("safeharness_writer:", maintenance)
        self.assertIn('command: ["safeharness-communication-maintain"]', maintenance)
        self.assertIn("communication-maintenance-state:/maintenance-state", maintenance)
        self.assertIn("cap_drop: [ALL]", maintenance)
        self.assertIn("profiles: [communication-maintenance]", maintenance)

    def test_staging_wires_restore_and_dependency_failure_checks(self) -> None:
        compose = (self.root / "deploy/compose/compose.yaml").read_text(
            encoding="utf-8"
        )
        backup = (self.root / "deploy/postgres/backup.sh").read_text(encoding="utf-8")
        restore = (self.root / "deploy/postgres/restore-check.sh").read_text(
            encoding="utf-8"
        )
        failure_test = (self.root / "deploy/smoke/dependency_failure.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("postgres-restore-check:", compose)
        self.assertIn("profiles: [restore]", compose)
        self.assertIn("dependency-failure-test:", compose)
        self.assertEqual(compose.count("profiles: [failure-test]"), 3)
        self.assertIn('sha256sum "$partial"', backup)
        self.assertNotIn("--table=safeharness_schema", backup)
        self.assertIn("safeharness-postgres-init", restore)
        self.assertIn("safeharness_restore_check_", restore)
        self.assertIn("gateway_audit_unavailable", failure_test)
        self.assertIn("capability_replay_store_unavailable", failure_test)

    def test_observability_ports_use_a_separate_management_network(self) -> None:
        compose = (self.root / "deploy/compose/compose.yaml").read_text(
            encoding="utf-8"
        )

        self.assertIn('"127.0.0.1:39090:9090"', compose)
        self.assertIn('"127.0.0.1:33000:3000"', compose)
        self.assertEqual(compose.count("networks: [observability, management]"), 2)
        self.assertIn("  observability:\n    internal: true\n  management:\n", compose)

    def test_asymmetric_profile_separates_private_and_public_key_mounts(self) -> None:
        compose = (self.root / "deploy/compose/compose.yaml").read_text(
            encoding="utf-8"
        )
        gateway_blocks = (
            _service_block(compose, "asymmetric-gateway"),
            _service_block(compose, "asymmetric-gateway-replica"),
        )
        smoke = _service_block(compose, "asymmetric-smoke-test")
        keygen = _service_block(compose, "receipt-keygen")

        self.assertEqual(compose.count("profiles: [asymmetric-test]"), 4)
        for gateway in gateway_blocks:
            self.assertIn("SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILE", gateway)
            self.assertIn("receipt-public:/receipt-public:ro", gateway)
            self.assertNotIn("SAFEHARNESS_ENFORCEMENT_RECEIPT_PRIVATE_KEY_FILE", gateway)
            self.assertNotIn("SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY", gateway)
        self.assertIn("SAFEHARNESS_ENFORCEMENT_RECEIPT_PRIVATE_KEY_FILE", smoke)
        self.assertIn("receipt-private:/receipt-private:ro", smoke)
        self.assertNotIn("SAFEHARNESS_ENFORCEMENT_RECEIPT_PUBLIC_KEY_FILE", smoke)
        self.assertNotIn("SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY", smoke)
        self.assertIn("receipt-private:/receipt-private", keygen)
        self.assertIn("receipt-public:/receipt-public", keygen)
        self.assertIn("cap_add: [CHOWN]", keygen)
        self.assertEqual(compose.count("cap_add: [CHOWN]"), 2)

    def test_communication_profile_is_isolated_and_runs_real_http_smoke(self) -> None:
        compose = (self.root / "deploy/compose/compose.yaml").read_text(
            encoding="utf-8"
        )
        smoke = (
            self.root / "deploy/smoke/agent_communication.py"
        ).read_text(encoding="utf-8")
        gateway = _service_block(compose, "communication-gateway")
        data_init = _service_block(compose, "communication-data-init")
        smoke_service = _service_block(compose, "communication-smoke-test")

        self.assertEqual(compose.count("profiles: [communication-test]"), 3)
        self.assertIn("communication-data:/communication-data", data_init)
        self.assertIn("user: root", data_init)
        self.assertIn("cap_add: [CHOWN]", data_init)
        self.assertIn("condition: service_completed_successfully", gateway)
        self.assertIn("communication-data:/communication-data", gateway)
        self.assertIn('"127.0.0.1:38200:38200"', gateway)
        for name in (
            "SAFEHARNESS_COMMUNICATION_SUPERVISOR_API_KEY",
            "SAFEHARNESS_COMMUNICATION_DIAGNOSIS_API_KEY",
            "SAFEHARNESS_COMMUNICATION_COORDINATION_SIGNING_KEY",
            "SAFEHARNESS_COMMUNICATION_ADMIN_API_KEY",
        ):
            self.assertIn(f"${{{name}:?set in config/deployment.env}}", gateway)
        for name in (
            "SAFEHARNESS_COMMUNICATION_SUPERVISOR_API_KEY",
            "SAFEHARNESS_COMMUNICATION_DIAGNOSIS_API_KEY",
            "SAFEHARNESS_COMMUNICATION_ADMIN_API_KEY",
        ):
            self.assertIn(f"${{{name}:?set in config/deployment.env}}", smoke_service)
        self.assertIn("communication-data:/communication-data:ro", smoke_service)
        self.assertIn("deploy.smoke.agent_communication", smoke_service)
        self.assertIn("mode=ro&immutable=1", smoke)
        self.assertIn("communication_message_replayed", smoke)
        self.assertIn("authenticated_principal_mismatch", smoke)
        self.assertIn("prompt_injection_detected", smoke)
        self.assertIn("safeharness_coordination_state", smoke)
        self.assertIn("recipient_quarantined", smoke)


def _valid_values() -> dict[str, str]:
    names = (
        "SAFEHARNESS_POSTGRES_ADMIN_PASSWORD",
        "SAFEHARNESS_POSTGRES_MIGRATOR_PASSWORD",
        "SAFEHARNESS_POSTGRES_WRITER_PASSWORD",
        "SAFEHARNESS_POSTGRES_READER_PASSWORD",
        "SAFEHARNESS_POSTGRES_RETENTION_PASSWORD",
        "SAFEHARNESS_REDIS_PASSWORD",
        "SAFEHARNESS_REDIS_GATEWAY_PASSWORD",
        "SAFEHARNESS_REDIS_COMMUNICATION_PASSWORD",
        "SAFEHARNESS_GATEWAY_API_KEY",
        "SAFEHARNESS_GATEWAY_SIGNING_KEY",
        "SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY",
        "GRAFANA_ADMIN_PASSWORD",
    )
    return {name: f"{index:02d}" * 24 for index, name in enumerate(names, start=1)}


def _service_block(compose: str, name: str) -> str:
    marker = f"  {name}:\n"
    if marker not in compose:
        raise AssertionError(f"missing Compose service: {name}")
    remainder = compose.split(marker, 1)[1]
    next_service = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", remainder)
    return remainder if next_service is None else remainder[: next_service.start()]


if __name__ == "__main__":
    unittest.main()
