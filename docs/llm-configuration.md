# Model Configuration

The `safeharness` runtime itself has no model-provider dependency. This
configuration applies to the paper-reproduction Harnesses and to applications
that use `llm_api.py` or `src.llm_client`.

## Quick setup

Copy `config/llm.env.example` to `config/llm.env`, then set one compatible
endpoint, its API key, and its model ID:

```powershell
Copy-Item config\llm.env.example config\llm.env
```

```dotenv
SAFEHARNESS_LLM_BASE_URL=https://your-provider.example/v1
SAFEHARNESS_LLM_API_KEY=replace-with-a-real-key
SAFEHARNESS_LLM_MODEL=your-model-id

# Optional: use a distinct model for evaluation.
SAFEHARNESS_JUDGE_MODEL=your-judge-model-id

# Enable semantic prompt-injection and tool-intent checks in the NOC demo.
SAFEHARNESS_ENABLE_SEMANTIC_JUDGE=true
```

The default experiment configuration uses `env` for the Agent and `judge` for
the evaluator. `judge` falls back to `SAFEHARNESS_LLM_MODEL` when
`SAFEHARNESS_JUDGE_MODEL` is empty.

`SAFEHARNESS_LLM_BASE_URL` must point to an OpenAI-compatible Chat Completions
endpoint. Many gateways require the `/v1` path segment. Existing `OPENAI_*`,
`DEEPSEEK_*`, and `ANTHROPIC_*` variables remain fallback inputs for older
deployments, but `SAFEHARNESS_LLM_*` is the preferred interface.

## Runtime security Judge

The LangGraph NOC demo uses `SAFEHARNESS_JUDGE_MODEL` through the
`JudgeProvider` interface for two decisions:

- `prompt_injection_detection` evaluates user, retrieval, tool, memory, and
  inter-Agent content that did not already match deterministic rules.
- `tool_intent_alignment` checks that a tool call with external side effects
  faithfully implements the most recent inspected user request.

The Judge is defense in depth. It cannot grant a capability, rewrite the trusted
tool catalog, replace operator approval, or activate a blocked user intent.
Invalid, empty, or ambiguous Judge output is handled conservatively. Set
`SAFEHARNESS_ENABLE_SEMANTIC_JUDGE=false` only when deterministic filtering is
an explicit deployment decision; signed capabilities, schema enforcement,
approval, and intent-digest controls remain active. When the Judge is disabled
or unavailable, every tool call with external side effects requires an operator
approval instead of being treated as semantically aligned.

Enabling the Judge sends the inspected text and redacted security context to the
configured model endpoint. Production deployments should use an approved local
or enterprise endpoint whose retention and data-handling policy matches the
content classification.

## Precedence and safety

- The process environment takes precedence over values in `config/llm.env`.
- Set `SAFEHARNESS_ENV_FILE` to load a different dotenv file, such as one
  mounted by a container or secret manager.
- `config/llm.env` is ignored by Git. Never add API keys to source code, documentation,
  configuration YAML, or commits.
- A missing or placeholder key fails closed at the client boundary: no provider
  request is made and the caller receives `None` with a configuration log.

## Switching providers

For a new provider, edit only the three primary values in `config/llm.env`; the Agent and
experiment configuration can remain unchanged:

```dotenv
SAFEHARNESS_LLM_BASE_URL=https://gateway.example/v1
SAFEHARNESS_LLM_API_KEY=your-key
SAFEHARNESS_LLM_MODEL=provider-model-name
```

Raw provider model IDs are also accepted in `config/experiment.yaml`. Legacy
short aliases such as `gpt4o` and `deepseek_chat` are retained for old scripts,
but new experiments should use `env` and `judge` so endpoint changes stay out
of source and YAML.
