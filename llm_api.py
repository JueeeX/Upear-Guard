# -*- coding: UTF-8 -*-

import logging
import os
import time

from openai import OpenAI
from anthropic import Anthropic

logger = logging.getLogger(__name__)


class InsufficientBalanceError(RuntimeError):
    """API 返回 402 / 余额不足时抛出，供上层终止批处理任务。"""


def _is_insufficient_balance(exc: BaseException) -> bool:
    if getattr(exc, "status_code", None) == 402:
        return True
    return "insufficient balance" in str(exc).lower()


# ── 配置：通过环境变量读取，支持 OpenAI / Anthropic / DeepSeek ──

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")

HTTP_MAX_RETRIES = 5

EMPTY_RESPONSE_MAX_ATTEMPTS = 10
_EMPTY_RETRY_BASE_DELAY_SEC = 0.5


def _sleep_before_empty_retry(attempt_index: int) -> None:
    time.sleep(_EMPTY_RETRY_BASE_DELAY_SEC * (2**attempt_index))


def _get_openai_client(model_name: str, timeout: int) -> OpenAI:
    """Return an OpenAI-compatible client configured for the given model."""
    if model_name.startswith("deepseek"):
        return OpenAI(
            base_url=DEEPSEEK_BASE_URL,
            api_key=DEEPSEEK_API_KEY,
            timeout=timeout,
            max_retries=HTTP_MAX_RETRIES,
        )
    return OpenAI(
        base_url=OPENAI_BASE_URL,
        api_key=OPENAI_API_KEY,
        timeout=timeout,
        max_retries=HTTP_MAX_RETRIES,
    )


def call_llm(messages, model_name, params=None, timeout=3600):
    """OpenAI-compatible API 调用（用于 GPT / DeepSeek 等）"""
    create_kw = params if params else {}
    last_bad: str | None = None
    try:
        client = _get_openai_client(model_name, timeout)
    except Exception as e:
        if _is_insufficient_balance(e):
            raise InsufficientBalanceError(str(e)) from e
        logger.warning("Error creating OpenAI client: %s: %r", type(e).__name__, e)
        return None

    for attempt in range(EMPTY_RESPONSE_MAX_ATTEMPTS):
        try:
            completion = client.chat.completions.create(
                model=model_name,
                messages=messages,
                **create_kw,
            )
            answer = completion.choices[0].message.content
        except Exception as e:
            if _is_insufficient_balance(e):
                raise InsufficientBalanceError(str(e)) from e
            logger.warning("Error calling LLM: %s: %r", type(e).__name__, e)
            return None

        if isinstance(answer, str) and answer != "":
            return answer

        last_bad = repr(answer)
        if attempt + 1 < EMPTY_RESPONSE_MAX_ATTEMPTS:
            logger.info(
                "LLM empty response (%s), retry %d/%d (model=%r)",
                last_bad, attempt + 1, EMPTY_RESPONSE_MAX_ATTEMPTS, model_name,
            )
            _sleep_before_empty_retry(attempt)

    logger.warning(
        "LLM empty response after %d attempts, last content=%s",
        EMPTY_RESPONSE_MAX_ATTEMPTS, last_bad,
    )
    return None


def call_anthropic(messages, model_name, max_tokens=4096, timeout=3600):
    """Anthropic native API 调用（用于 Claude 系列）"""
    system_text = None
    user_messages = []
    for m in messages:
        if m["role"] == "system":
            system_text = m["content"]
        else:
            user_messages.append(m)

    kwargs = dict(
        model=model_name,
        max_tokens=max_tokens,
        messages=user_messages,
    )
    if system_text:
        kwargs["system"] = system_text

    last_bad: str | None = None
    try:
        client = Anthropic(
            api_key=ANTHROPIC_API_KEY,
            timeout=timeout,
            max_retries=HTTP_MAX_RETRIES,
        )
    except Exception as e:
        if _is_insufficient_balance(e):
            raise InsufficientBalanceError(str(e)) from e
        logger.warning("Error creating Anthropic client: %s: %r", type(e).__name__, e)
        return None

    for attempt in range(EMPTY_RESPONSE_MAX_ATTEMPTS):
        try:
            message = client.messages.create(**kwargs)
            answer = message.content[0].text
        except Exception as e:
            if _is_insufficient_balance(e):
                raise InsufficientBalanceError(str(e)) from e
            logger.warning("Error calling Anthropic: %s: %r", type(e).__name__, e)
            return None

        if isinstance(answer, str) and answer != "":
            return answer

        last_bad = repr(answer)
        if attempt + 1 < EMPTY_RESPONSE_MAX_ATTEMPTS:
            logger.info(
                "Anthropic empty response (%s), retry %d/%d (model=%r)",
                last_bad, attempt + 1, EMPTY_RESPONSE_MAX_ATTEMPTS, model_name,
            )
            _sleep_before_empty_retry(attempt)

    logger.warning(
        "Anthropic empty response after %d attempts, last content=%s",
        EMPTY_RESPONSE_MAX_ATTEMPTS, last_bad,
    )
    return None


# ── 便捷函数：每个模型对应一个带默认参数的调用 ──

def call_claude_sonnet(messages):
    return call_anthropic(messages, model_name="claude-sonnet-4-5-20250929")

def call_claude_sonnet_4_6(messages):
    return call_anthropic(messages, model_name="claude-sonnet-4-6")

def call_claude_3_haiku(messages):
    return call_anthropic(messages, model_name="claude-3-haiku-20240307")

def call_gpt_5_4(messages):
    return call_llm(messages, model_name="gpt-5.4-2026-03-05")

def call_gpt4o(messages):
    return call_llm(messages, model_name="gpt-4o")

def call_gpt_4o_mini(messages):
    return call_llm(messages, model_name="gpt-4o-mini-2024-07-18")

def call_deepseek_chat(messages):
    return call_llm(messages, model_name="deepseek-chat")

def call_deepseek_reasoner(messages):
    return call_llm(messages, model_name="deepseek-reasoner")


MODEL_FUNC_MAP = {
    "deepseek_chat": call_deepseek_chat,
    "deepseek_reasoner": call_deepseek_reasoner,
    "gpt5.4": call_gpt_5_4,
    "gpt4o": call_gpt4o,
    "gpt4omini": call_gpt_4o_mini,
    "sonnet4.6": call_claude_sonnet_4_6,
    "claude_sonnet": call_claude_sonnet,
    "claude3haiku": call_claude_3_haiku,
}


def call_by_name(model_short_name, messages):
    """通过简短的模型名调用，例如 call_by_name('deepseek_chat', messages)"""
    func = MODEL_FUNC_MAP.get(model_short_name)
    if func is None:
        raise ValueError(
            f"Unknown model '{model_short_name}', available: {list(MODEL_FUNC_MAP.keys())}"
        )
    return func(messages)
