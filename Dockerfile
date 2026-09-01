FROM python:3.11.16-slim-bookworm

ARG VERSION=local
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="BreachScope" \
      org.opencontainers.image.description="Internal DFIR log analysis console" \
      org.opencontainers.image.source="https://github.com/bbk0416/BreachScope" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.created="$BUILD_DATE"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BS_CASES_ROOT=/data/cases \
    BS_CASE_HISTORY_PATH=/data/case_history.json \
    BS_AUDIT_LOG_PATH=/data/audit.jsonl \
    BS_BUILD_VERSION=$VERSION \
    BS_BUILD_SHA=$VCS_REF \
    BS_BUILD_TIME=$BUILD_DATE

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends fontconfig fonts-nanum curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt requirements-lock-py311.txt README.md ./
COPY api ./api
COPY breachscope ./breachscope
COPY docs ./docs
COPY rules ./rules
COPY samples ./samples
COPY scenarios ./scenarios
COPY scripts ./scripts
COPY templates ./templates
COPY run.sh run_web_fastapi.sh ./

RUN python -m pip install --no-cache-dir --require-hashes -r requirements-lock-py311.txt \
    && python -m pip install --no-cache-dir --no-deps --no-build-isolation -e .

RUN useradd --create-home --uid 10001 breachscope \
    && mkdir -p /data \
    && chown -R breachscope:breachscope /data /app

USER breachscope

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health/live || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
