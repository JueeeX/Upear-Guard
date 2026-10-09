FROM postgres:17-alpine

RUN apk add --no-cache python3 py3-pip \
    && python3 -m venv /opt/safeharness-venv
ENV PATH="/opt/safeharness-venv/bin:$PATH"

WORKDIR /opt/safeharness
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir ".[production]"

COPY --chown=postgres:postgres --chmod=0555 deploy/postgres/restore-check.sh /opt/safeharness/restore-check.sh

USER postgres
ENTRYPOINT ["sh", "/opt/safeharness/restore-check.sh"]
