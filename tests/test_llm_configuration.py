from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class LLMConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing_config = Path(directory) / "missing.env"
            with patch.dict(os.environ, {"SAFEHARNESS_ENV_FILE": str(missing_config)}):
                import llm_api

                self.llm_api = importlib.reload(llm_api)

    def test_dotenv_loads_values_without_overriding_process_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dotenv = Path(directory) / ".env"
            dotenv.write_text(
                "SAFEHARNESS_LLM_BASE_URL=https://dotenv.example/v1\n"
                "SAFEHARNESS_LLM_API_KEY=dotenv-key\n"
                "SAFEHARNESS_LLM_MODEL=dotenv-model\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"SAFEHARNESS_LLM_API_KEY": "process-key"},
                clear=True,
            ):
                self.llm_api.load_env_file(dotenv)
                self.assertEqual(
                    os.environ["SAFEHARNESS_LLM_BASE_URL"],
                    "https://dotenv.example/v1",
                )
                self.assertEqual(os.environ["SAFEHARNESS_LLM_API_KEY"], "process-key")
                self.assertEqual(os.environ["SAFEHARNESS_LLM_MODEL"], "dotenv-model")

    def test_generic_env_does_not_shadow_communication_secrets(self) -> None:
        generic_env = Path(__file__).resolve().parents[1] / "config" / "llm.env.example"
        with tempfile.TemporaryDirectory() as directory:
            communication_env = Path(directory) / "communication.env"
            communication_env.write_text(
                "SAFEHARNESS_COMMUNICATION_SUPERVISOR_API_KEY=supervisor-secret\n"
                "SAFEHARNESS_COMMUNICATION_DIAGNOSIS_API_KEY=diagnosis-secret\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                self.llm_api.load_env_file(generic_env)
                self.llm_api.load_env_file(communication_env)

                self.assertEqual(
                    os.environ["SAFEHARNESS_COMMUNICATION_SUPERVISOR_API_KEY"],
                    "supervisor-secret",
                )
                self.assertEqual(
                    os.environ["SAFEHARNESS_COMMUNICATION_DIAGNOSIS_API_KEY"],
                    "diagnosis-secret",
                )

    def test_default_llm_config_stays_in_config_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preferred = root / "config" / "llm.env"
            legacy = root / ".env"
            legacy.write_text("SAFEHARNESS_LLM_MODEL=legacy-model\n", encoding="utf-8")
            with (
                patch.object(self.llm_api, "_DEFAULT_ENV_PATH", preferred),
                patch.dict(os.environ, {}, clear=True),
            ):
                self.assertEqual(self.llm_api._default_env_path(), preferred)
                self.assertIsNone(self.llm_api.load_env_file())
                preferred.parent.mkdir()
                preferred.write_text(
                    "SAFEHARNESS_LLM_MODEL=preferred-model\n", encoding="utf-8"
                )
                self.assertEqual(self.llm_api._default_env_path(), preferred)
                self.llm_api.load_env_file()
                self.assertEqual(os.environ["SAFEHARNESS_LLM_MODEL"], "preferred-model")

    def test_env_and_judge_aliases_resolve_from_configuration(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SAFEHARNESS_LLM_MODEL": "agent-model",
                "SAFEHARNESS_JUDGE_MODEL": "judge-model",
            },
            clear=True,
        ):
            self.assertEqual(self.llm_api.resolve_model_name("env"), "agent-model")
            self.assertEqual(
                self.llm_api.resolve_model_name("judge", role="judge"),
                "judge-model",
            )
            self.assertEqual(
                self.llm_api.resolve_model_name("gpt4o"),
                "deepseek-v4-flash",
            )

    def test_endpoint_uses_preferred_safeharness_variables(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SAFEHARNESS_LLM_BASE_URL": "https://gateway.example/v1",
                "SAFEHARNESS_LLM_API_KEY": "test-key",
                "OPENAI_BASE_URL": "https://ignored.example/v1",
                "OPENAI_API_KEY": "ignored-key",
            },
            clear=True,
        ):
            self.assertEqual(
                self.llm_api._endpoint_settings(),
                ("https://gateway.example/v1", "test-key"),
            )

    def test_placeholder_or_missing_key_is_rejected_before_network(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SAFEHARNESS_LLM_BASE_URL": "https://gateway.example/v1",
                "SAFEHARNESS_LLM_API_KEY": "replace-with-your-api-key",
            },
            clear=True,
        ):
            with self.assertRaises(self.llm_api.LLMConfigurationError):
                self.llm_api._endpoint_settings()

    def test_raw_model_ids_and_legacy_provider_variables_remain_supported(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OPENAI_BASE_URL": "https://legacy.example/v1",
                "OPENAI_API_KEY": "legacy-key",
            },
            clear=True,
        ):
            self.assertEqual(
                self.llm_api.resolve_model_name("provider-specific-model"),
                "provider-specific-model",
            )
            self.assertEqual(
                self.llm_api._endpoint_settings(),
                ("https://legacy.example/v1", "legacy-key"),
            )

    def test_judge_requests_native_json_output(self) -> None:
        with (
            patch.object(self.llm_api, "resolve_model_name", return_value="judge-model"),
            patch.object(self.llm_api, "call_llm", return_value="{}") as call_llm,
        ):
            self.llm_api.call_judge_model([{"role": "user", "content": "check"}], "judge")

        self.assertEqual(
            call_llm.call_args.kwargs["params"]["response_format"],
            {"type": "json_object"},
        )


if __name__ == "__main__":
    unittest.main()
