"""Static image contract: the shipped image must contain everything
the app reads at runtime (migrations, seed feed) and run non-root."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_contract():
    dockerfile = (REPO_ROOT / "Dockerfile").read_text()
    assert "COPY migrations ./migrations" in dockerfile
    assert "COPY data ./data" in dockerfile
    assert "MIGRATIONS_DIR=/app/migrations" in dockerfile
    assert "SEED_ALERTS_PATH=/app/data/seed_alerts.json" in dockerfile
    assert "USER appuser" in dockerfile
    assert "python:3.12-slim AS build" in dockerfile  # multi-stage


def test_compose_contract():
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    assert "pgvector/pgvector:pg16" in compose
    assert "minio:" in compose
    assert "S3_ENDPOINT_URL: http://minio:8333" in compose
    assert "DATABASE_URL:" in compose
