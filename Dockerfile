FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN addgroup --system safeharness \
    && adduser --system --ingroup safeharness --home /app safeharness \
    && mkdir -p /app \
    && chown safeharness:safeharness /app

WORKDIR /app
COPY pyproject.toml README.md LICENSE /app/
COPY src /app/src
RUN python -m pip install --no-cache-dir ".[production,observability]"
COPY --chown=safeharness:safeharness llm_api.py /app/llm_api.py
COPY --chown=safeharness:safeharness examples /app/examples
COPY --chown=safeharness:safeharness deploy /app/deploy

USER safeharness
EXPOSE 38100

CMD ["python", "-m", "examples.langgraph_noc.tool_gateway", "--host", "0.0.0.0"]
