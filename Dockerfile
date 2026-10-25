# Trida AI Blueprint — AML Alert Investigation & Case File Agent
# Multi-stage build; the runtime image runs as a non-root user.

FROM python:3.12-slim AS build
WORKDIR /app
COPY pyproject.toml constraints.txt README.md ./
COPY src ./src
RUN pip install --no-cache-dir -r constraints.txt \
 && pip install --no-cache-dir --no-deps .

FROM python:3.12-slim
RUN useradd --create-home appuser
WORKDIR /app
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin/uvicorn /usr/local/bin/aml-agent /usr/local/bin/aml-agent-demo /usr/local/bin/
COPY migrations ./migrations
COPY data ./data
COPY evals ./evals
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data
USER appuser
ENV AML_SQLITE_PATH=/app/data/aml.db \
    OBJECT_STORE_DIR=/app/data/evidence-objects \
    MIGRATIONS_DIR=/app/migrations \
    SEED_ALERTS_PATH=/app/data/seed_alerts.json
EXPOSE 8000
CMD ["uvicorn", "aml_investigations.api:app", "--host", "0.0.0.0", "--port", "8000"]
