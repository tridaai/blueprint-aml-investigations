"""Postgres parity mode for the test suite (R16).

The suite's default profile runs store-backed tests on the
in-memory double, plus one SQLite replay per domain (the store
contract, exercised per adapter). That samples the SQL adapter; it
does not prove the whole suite behaves identically on the
production store. Parity mode closes that gap without rewriting a
single test:

    AML_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5433/aml_parity \
        uv run pytest -q

When the variable is set, conftest activates this module after
collection (every test module already imported):

- every module attribute bound to the original ``InMemoryCaseStore``
  class is replaced by a factory returning a ``PgParityStore`` — a
  real ``SqlCaseStore`` over a fresh, fully migrated Postgres
  schema (one schema per store instance, so instances are as
  isolated as the in-memory double is);
- ``SqlCaseStore.sqlite(path, ...)`` is replaced by a Postgres
  store keyed by the resolved path: the same path maps to the
  same schema, so the reopen/persistence tests verify the same
  property against Postgres that they verify against a file.

Some tests reach into the in-memory double's internals on purpose —
they simulate an attacker with direct database access rewriting,
deleting, or appending an evidence row (tests/test_evidence_chain.py,
tests/test_traps_r15.py, tests/test_redteam_r19.py).
``PgParityStore`` therefore exposes an
``_evidence`` view with exactly the list operations those tests
perform, implemented as UPDATE/DELETE statements against the
``evidence_items`` table in the store's schema: the same tampering,
through the same test code, one layer down. Nothing about the
tests changes.

Schemas created during a run are dropped at session end (best
effort). The mode is all-or-nothing and loud: if the variable is
set but Postgres is unreachable, activation raises rather than
silently falling back to the in-memory profile.
"""

from __future__ import annotations

import hashlib
import sys
import threading
import uuid
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

import aml_investigations.stores as _stores_module
from aml_investigations.migrations import run_migrations
from aml_investigations.stores import SqlCaseStore

ENV_VAR = "AML_TEST_DATABASE_URL"

_REPO_ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = _REPO_ROOT / "migrations"

_lock = threading.Lock()
_created_schemas: list[str] = []
_activated = False


def parity_url() -> str | None:
    import os

    return os.environ.get(ENV_VAR) or None


def _admin(url: str) -> psycopg.Connection:
    return psycopg.connect(url, autocommit=True)


def _register_schema(url: str, schema: str) -> None:
    with _lock:
        _created_schemas.append(schema)


def _create_schema(url: str, schema: str) -> None:
    with _admin(url) as conn:
        conn.execute(f'CREATE SCHEMA "{schema}"')
    _register_schema(url, schema)


def _connect_in_schema(url: str, schema: str) -> psycopg.Connection:
    conn = psycopg.connect(url, row_factory=dict_row)
    conn.execute(f'SET search_path TO "{schema}"')
    conn.commit()
    return conn


class _EvidenceView:
    """List-shaped live view over one case's evidence rows.

    Supports exactly what the tampering tests do with the
    in-memory double's list: read an item by position, replace the
    item at a position, delete the item at a position, append an
    item, and pop the tail item (the R19 chain attacks) — as SQL
    against the store's own table, committed immediately (the
    tampering is meant to be durable, like a real DB write).
    """

    def __init__(self, store: "PgParityStore", case_id: str) -> None:
        self._store = store
        self._case_id = case_id

    def _items(self):
        return self._store.list_evidence(self._case_id)

    def __len__(self) -> int:
        return len(self._items())

    def __iter__(self):
        return iter(self._items())

    def __getitem__(self, index):
        return self._items()[index]

    def __setitem__(self, index, item) -> None:
        current = self._items()[index]
        self._store._execute(
            "UPDATE evidence_items SET kind = ?, chain_hash = ?, payload = ?"
            " WHERE case_id = ? AND seq = ?",
            (
                item.kind,
                item.chain_hash,
                item.model_dump_json(),
                self._case_id,
                current.seq,
            ),
        )
        self._store._commit()

    def __delitem__(self, index) -> None:
        current = self._items()[index]
        self._store._execute(
            "DELETE FROM evidence_items WHERE case_id = ? AND seq = ?",
            (self._case_id, current.seq),
        )
        self._store._commit()

    def append(self, item) -> None:
        self._store._execute(
            "INSERT INTO evidence_items"
            " (case_id, seq, kind, chain_hash, payload)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                self._case_id,
                item.seq,
                item.kind,
                item.chain_hash,
                item.model_dump_json(),
            ),
        )
        self._store._commit()

    def pop(self, index: int = -1):
        items = self._items()
        item = items[index]
        del self[index]
        return item


class _EvidenceByCase:
    def __init__(self, store: "PgParityStore") -> None:
        self._store = store

    def __getitem__(self, case_id: str) -> _EvidenceView:
        return _EvidenceView(self._store, case_id)


class PgParityStore(SqlCaseStore):
    """A SqlCaseStore over one isolated, migrated Postgres schema."""

    def __init__(self, conn, schema: str) -> None:
        super().__init__(conn, "format")
        self._schema = schema

    @classmethod
    def fresh(cls, url: str) -> "PgParityStore":
        """A brand-new schema: the in-memory double's semantics."""
        schema = f"t_{uuid.uuid4().hex[:20]}"
        _create_schema(url, schema)
        conn = _connect_in_schema(url, schema)
        run_migrations(conn, MIGRATIONS_DIR, "postgres", "format")
        return cls(conn, schema)

    @classmethod
    def for_path(cls, url: str, path: Path, migrations_dir: Path) -> "PgParityStore":
        """The schema keyed by a would-be SQLite path (reopen parity)."""
        key = hashlib.sha256(str(Path(path).resolve()).encode()).hexdigest()[:24]
        schema = f"f_{key}"
        with _admin(url) as conn:
            conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        _register_schema(url, schema)
        conn = _connect_in_schema(url, schema)
        run_migrations(conn, migrations_dir, "postgres", "format")
        return cls(conn, schema)

    @property
    def _evidence(self) -> _EvidenceByCase:  # tampering-view (see module docstring)
        return _EvidenceByCase(self)


def _in_memory_factory() -> PgParityStore:
    url = parity_url()
    assert url is not None  # activation only happens with the variable set
    return PgParityStore.fresh(url)


def _pg_sqlite(cls, path, migrations_dir) -> PgParityStore:
    url = parity_url()
    assert url is not None
    return PgParityStore.for_path(url, Path(path), Path(migrations_dir))


def activate() -> bool:
    """Swap the suite's store constructions to Postgres. Idempotent."""
    global _activated
    url = parity_url()
    if not url:
        return False
    if _activated:
        return True
    # Fail loud, once, before any test runs against a half-swapped suite.
    with _admin(url):
        pass
    original = _stores_module.InMemoryCaseStore
    for module in list(sys.modules.values()):
        if module is None:
            continue
        try:
            namespace = vars(module)
        except TypeError:
            continue
        if namespace.get("InMemoryCaseStore") is original:
            namespace["InMemoryCaseStore"] = _in_memory_factory
    SqlCaseStore.sqlite = classmethod(_pg_sqlite)  # type: ignore[method-assign]
    _activated = True
    return True


def cleanup() -> None:
    """Drop every schema this run created (best effort).

    The parity stores' connections are still open at session end,
    some idle inside a transaction holding read locks on their
    schema's tables — a DROP SCHEMA would wait on those locks
    forever. The parity database is a throwaway, so terminate its
    other backends first, then drop.
    """
    url = parity_url()
    if not url or not _created_schemas:
        return
    try:
        with _admin(url) as conn:
            conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
                " WHERE datname = current_database()"
                " AND pid <> pg_backend_pid()"
            )
            for schema in _created_schemas:
                conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
    except Exception:
        pass
