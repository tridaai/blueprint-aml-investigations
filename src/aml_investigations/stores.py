"""Case-store adapters.

``SqlCaseStore`` is the production-shaped adapter: one implementation
over a DB-API connection, used with SQLite locally (the repo default)
and with PostgreSQL when ``DATABASE_URL`` is set. SQL is written with
``?`` placeholders and translated for psycopg's ``%s`` paramstyle.
Payloads are stored as JSON text in both dialects, alongside the
columns the queue and the clocks need to filter on.

``InMemoryCaseStore`` is the test double: same contract, no disk.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from .migrations import run_migrations
from .models import AuditEvent, Case, EvidenceItem


class InMemoryCaseStore:
    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}
        self._evidence: dict[str, list[EvidenceItem]] = {}
        self._audit: list[AuditEvent] = []
        self._lock = threading.Lock()

    def ping(self) -> bool:
        return True

    def create_case(self, case: Case) -> Case:
        with self._lock:
            self._cases[case.case_id] = case.model_copy(deep=True)
        return case

    def get_case(self, case_id: str) -> Case | None:
        case = self._cases.get(case_id)
        return case.model_copy(deep=True) if case else None

    def get_case_by_alert(self, alert_id: str) -> Case | None:
        for case in self._cases.values():
            if case.alert_id == alert_id:
                return case.model_copy(deep=True)
        return None

    def update_case(self, case: Case) -> Case:
        with self._lock:
            if case.case_id not in self._cases:
                raise KeyError(case.case_id)
            self._cases[case.case_id] = case.model_copy(deep=True)
        return case

    def list_cases(self, status: str | None = None) -> list[Case]:
        cases = list(self._cases.values())
        if status is not None:
            cases = [c for c in cases if c.status.value == status]
        return [c.model_copy(deep=True) for c in cases]

    def add_evidence_item(self, item: EvidenceItem) -> EvidenceItem:
        with self._lock:
            self._evidence.setdefault(item.case_id, []).append(item.model_copy(deep=True))
        return item

    def list_evidence(self, case_id: str) -> list[EvidenceItem]:
        items = self._evidence.get(case_id, [])
        return [i.model_copy(deep=True) for i in sorted(items, key=lambda i: i.seq)]

    def get_evidence_item(self, case_id: str, seq: int) -> EvidenceItem | None:
        for item in self._evidence.get(case_id, []):
            if item.seq == seq:
                return item.model_copy(deep=True)
        return None

    def append_audit(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            self._audit.append(event.model_copy(deep=True))
        return event

    def list_audit(self, case_id: str) -> list[AuditEvent]:
        return [e.model_copy(deep=True) for e in self._audit if e.case_id == case_id]


class SqlCaseStore:
    """Case store over SQLite or PostgreSQL (same SQL, two paramstyles)."""

    def __init__(self, conn, paramstyle: str) -> None:
        self._conn = conn
        self._paramstyle = paramstyle
        self._lock = threading.Lock()

    # -- construction ------------------------------------------------
    @classmethod
    def sqlite(cls, path: Path, migrations_dir: Path) -> "SqlCaseStore":
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        store = cls(conn, "qmark")
        run_migrations(conn, migrations_dir, "sqlite", "qmark")
        return store

    @classmethod
    def postgres(cls, database_url: str, migrations_dir: Path) -> "SqlCaseStore":
        import psycopg
        from psycopg.rows import dict_row

        conn = psycopg.connect(database_url, row_factory=dict_row)
        store = cls(conn, "format")
        run_migrations(conn, migrations_dir, "postgres", "format")
        return store

    # -- helpers -------------------------------------------------------
    def _sql(self, sql: str) -> str:
        if self._paramstyle == "format":
            return sql.replace("?", "%s")
        return sql

    def _execute(self, sql: str, params: tuple = ()):
        with self._lock:
            cur = self._conn.execute(self._sql(sql), params)
            return cur

    def _fetchone(self, sql: str, params: tuple = ()):
        cur = self._execute(sql, params)
        row = cur.fetchone()
        if row is None:
            return None
        return dict(row)

    def _fetchall(self, sql: str, params: tuple = ()) -> list[dict]:
        cur = self._execute(sql, params)
        return [dict(row) for row in cur.fetchall()]

    def _commit(self) -> None:
        with self._lock:
            self._conn.commit()

    # -- contract ------------------------------------------------------
    def ping(self) -> bool:
        try:
            self._fetchone("SELECT 1 AS one")
            return True
        except Exception:
            return False

    def create_case(self, case: Case) -> Case:
        self._execute(
            "INSERT INTO cases (case_id, alert_id, customer_id, account_id, status,"
            " severity, detected_on, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                case.case_id,
                case.alert_id,
                case.customer_id,
                case.account_id,
                case.status.value,
                case.severity.value,
                case.detected_on.isoformat(),
                case.model_dump_json(),
            ),
        )
        self._commit()
        return case

    def get_case(self, case_id: str) -> Case | None:
        row = self._fetchone("SELECT payload FROM cases WHERE case_id = ?", (case_id,))
        return Case.model_validate_json(row["payload"]) if row else None

    def get_case_by_alert(self, alert_id: str) -> Case | None:
        row = self._fetchone("SELECT payload FROM cases WHERE alert_id = ?", (alert_id,))
        return Case.model_validate_json(row["payload"]) if row else None

    def update_case(self, case: Case) -> Case:
        self._execute(
            "UPDATE cases SET status = ?, payload = ? WHERE case_id = ?",
            (case.status.value, case.model_dump_json(), case.case_id),
        )
        self._commit()
        return case

    def list_cases(self, status: str | None = None) -> list[Case]:
        if status is None:
            rows = self._fetchall("SELECT payload FROM cases ORDER BY detected_on, case_id")
        else:
            rows = self._fetchall(
                "SELECT payload FROM cases WHERE status = ?", (status,)
            )
        return [Case.model_validate_json(r["payload"]) for r in rows]

    def add_evidence_item(self, item: EvidenceItem) -> EvidenceItem:
        self._execute(
            "INSERT INTO evidence_items (case_id, seq, kind, chain_hash, payload)"
            " VALUES (?, ?, ?, ?, ?)",
            (item.case_id, item.seq, item.kind, item.chain_hash, item.model_dump_json()),
        )
        self._commit()
        return item

    def list_evidence(self, case_id: str) -> list[EvidenceItem]:
        rows = self._fetchall(
            "SELECT payload FROM evidence_items WHERE case_id = ? ORDER BY seq ASC",
            (case_id,),
        )
        return [EvidenceItem.model_validate_json(r["payload"]) for r in rows]

    def get_evidence_item(self, case_id: str, seq: int) -> EvidenceItem | None:
        row = self._fetchone(
            "SELECT payload FROM evidence_items WHERE case_id = ? AND seq = ?",
            (case_id, seq),
        )
        return EvidenceItem.model_validate_json(row["payload"]) if row else None

    def append_audit(self, event: AuditEvent) -> AuditEvent:
        self._execute(
            "INSERT INTO audit_events (event_id, case_id, ts, actor, event, payload)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.case_id,
                event.ts.isoformat(),
                event.actor,
                event.event,
                event.model_dump_json(),
            ),
        )
        self._commit()
        return event

    def list_audit(self, case_id: str) -> list[AuditEvent]:
        rows = self._fetchall(
            "SELECT payload FROM audit_events WHERE case_id = ? ORDER BY ts ASC, event_id ASC",
            (case_id,),
        )
        return [AuditEvent.model_validate_json(r["payload"]) for r in rows]
