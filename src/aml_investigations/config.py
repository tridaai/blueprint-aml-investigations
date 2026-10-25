"""Runtime configuration, from the environment only.

Defaults are the local development profile: a SQLite case store in
``./data`` and a filesystem object store next to it. Setting
``DATABASE_URL`` selects the Postgres profile; setting
``S3_ENDPOINT_URL`` selects the S3-compatible object store
(SeaweedFS in docker-compose, service name ``minio``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str | None
    sqlite_path: Path
    migrations_dir: Path
    object_store_dir: Path
    s3_endpoint_url: str | None
    s3_bucket: str
    seed_alerts_path: Path
    screening_lists_path: Path
    transaction_streams_path: Path
    typology_rules_path: Path
    log_level: str

    @property
    def use_postgres(self) -> bool:
        return bool(self.database_url)


def _resolve(env_value: str | None, *candidates: Path) -> Path:
    """First existing candidate wins; env override always wins.

    The package may be imported from the repo (src layout) or from an
    installed wheel, so relative-to-CWD paths are tried before the
    path relative to this source file.
    """
    if env_value:
        return Path(env_value)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def load_settings() -> Settings:
    repo_root = Path(__file__).resolve().parents[2]
    return Settings(
        database_url=os.environ.get("DATABASE_URL") or None,
        sqlite_path=Path(os.environ.get("AML_SQLITE_PATH", "./data/aml.db")),
        migrations_dir=_resolve(
            os.environ.get("MIGRATIONS_DIR"),
            Path("./migrations"),
            repo_root / "migrations",
        ),
        object_store_dir=Path(
            os.environ.get("OBJECT_STORE_DIR", "./data/evidence-objects")
        ),
        s3_endpoint_url=os.environ.get("S3_ENDPOINT_URL") or None,
        s3_bucket=os.environ.get("S3_BUCKET", "aml-evidence"),
        seed_alerts_path=_resolve(
            os.environ.get("SEED_ALERTS_PATH"),
            Path("./data/seed_alerts.json"),
            repo_root / "data" / "seed_alerts.json",
        ),
        screening_lists_path=_resolve(
            os.environ.get("SCREENING_LISTS_PATH"),
            Path("./data/screening_lists.json"),
            repo_root / "data" / "screening_lists.json",
        ),
        transaction_streams_path=_resolve(
            os.environ.get("TRANSACTION_STREAMS_PATH"),
            Path("./data/transaction_streams.json"),
            repo_root / "data" / "transaction_streams.json",
        ),
        typology_rules_path=_resolve(
            os.environ.get("TYPOLOGY_RULES_PATH"),
            Path("./data/typology_rules.json"),
            repo_root / "data" / "typology_rules.json",
        ),
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
    )
