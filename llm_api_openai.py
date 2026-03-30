"""
OpenAI-compatible LLM adapter used by SafeHarness.

This repository expects a root-level `llm_api_openai.py` providing:
  - call_llm(messages, model, ...)
  - call_by_name(model_key, messages, ...)
  - MODEL_FUNC_MAP: dict[str, Callable]

Environment variables (OpenAI-compatible):
  - OPENAI_API_KEY: required
  - OPENAI_BASE_URL: optional (e.g. DeepSeek / OpenRouter / local gateway)

Model mapping:
  - Keys must match config `models.*` (e.g. deepseek_v3_2).
  - Override actual provider model id via env:
      SAFEHARNESS_MODEL_DEEPSEEK_V3_2="deepseek-chat"
"""

from __future__ import annotations

import os
from typing import Any, Callable

from openai import OpenAI


def _client() -> OpenAI:
    # `OpenAI(base_url=...)` is supported in openai>=1.0 for OpenAI-compatible providers.
    return OpenAI(
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=os.getenv("OPENAI_BASE_URL") or None,
    )


def call_llm(
    messages: list[dict[str, Any]],
    model: str,
    *,
    temperature: float = 0.0,
    max_tokens: int | None = None,
    timeout_s: float | None = 60.0,
) -> str | None:
    """
    Call a chat-completions style model and return assistant content string.
    Returns None if the response is empty.
    """
    client = _client()

    # The OpenAI SDK will raise if api_key is missing; keep the error explicit.
    if not (os.getenv("OPENAI_API_KEY") or "").strip():
        raise RuntimeError(
            "缺少环境变量 OPENAI_API_KEY。请先执行：\n"
            'export OPENAI_API_KEY="你的key"\n'
            "如使用第三方 OpenAI-compatible 服务，还可设置 OPENAI_BASE_URL。"
        )

    resp = client.chat.completions.create(
        model=model,
        messages=messages,  # type: ignore[arg-type]
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout_s,
    )

    choice = resp.choices[0] if resp.choices else None
    content = getattr(getattr(choice, "message", None), "content", None) if choice else None
    if content is None:
        return None
    return str(content)


def _env_model(key: str, default: str) -> str:
    env_key = f"SAFEHARNESS_MODEL_{key.upper()}"
    return (os.getenv(env_key) or default).strip()


def call_by_name(model_key: str, messages: list[dict[str, Any]], **kwargs) -> str | None:
    """
    Call the model by config key (e.g. 'deepseek_v3_2').
    """
    fn = MODEL_FUNC_MAP.get(model_key)
    if not fn:
        raise KeyError(
            f"未知模型 key：{model_key}. 可用：{sorted(MODEL_FUNC_MAP.keys())}. "
            "请检查 config/experiment.yaml 的 models 配置或补充 MODEL_FUNC_MAP。"
        )
    return fn(messages, **kwargs)


def _call_deepseek_v3_2(messages: list[dict[str, Any]], **kwargs) -> str | None:
    # Default to a commonly used DeepSeek chat model id on OpenAI-compatible gateways.
    # Override with: export SAFEHARNESS_MODEL_DEEPSEEK_V3_2="your-provider-model-id"
    model = _env_model("deepseek_v3_2", "deepseek-chat")
    return call_llm(messages, model=model, **kwargs)

def _call_deepseek_chat(messages: list[dict[str, Any]], **kwargs) -> str | None:
    # Backward-compatible key used by earlier configs.
    model = _env_model("deepseek_chat", "deepseek-chat")
    return call_llm(messages, model=model, **kwargs)


def _call_gpt4o(messages: list[dict[str, Any]], **kwargs) -> str | None:
    # Backward-compatible key used by earlier configs.
    model = _env_model("gpt4o", "gpt-4o")
    return call_llm(messages, model=model, **kwargs)


MODEL_FUNC_MAP: dict[str, Callable[..., str | None]] = {
    "deepseek_v3_2": _call_deepseek_v3_2,
    "deepseek_chat": _call_deepseek_chat,
    "gpt4o": _call_gpt4o,
}

