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
from .models import (
    AccountProfile,
    AuditEvent,
    Case,
    DispositionConfirmation,
    DispositionRecord,
    EvidenceItem,
    InvestigationRecord,
    ListKind,
    ListSnapshot,
    RulePack,
    ScreeningHit,
    ScreeningRun,
    Transaction,
    TransactionBatch,
    TypologyFinding,
    TypologyRun,
)


class InMemoryCaseStore:
    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}
        self._evidence: dict[str, list[EvidenceItem]] = {}
        self._audit: list[AuditEvent] = []
        self._snapshots: dict[tuple[str, str], ListSnapshot] = {}
        self._runs: list[ScreeningRun] = []
        self._hits: dict[str, ScreeningHit] = {}
        self._packs: dict[tuple[str, str], RulePack] = {}
        self._profiles: dict[str, AccountProfile] = {}
        self._batches: dict[str, TransactionBatch] = {}
        self._transactions: dict[str, list[Transaction]] = {}
        self._typology_runs: list[TypologyRun] = []
        self._findings: dict[str, TypologyFinding] = {}
        self._investigation_records: list[InvestigationRecord] = []
        self._dispositions: list[DispositionRecord] = []
        self._confirmations: list[DispositionConfirmation] = []
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

    # --- screening (Law 3): snapshots, runs, hits --------------------
    def save_snapshot(self, snapshot: ListSnapshot) -> ListSnapshot:
        with self._lock:
            key = (snapshot.list_kind.value, snapshot.version)
            if key in self._snapshots:
                raise KeyError(f"snapshot already exists: {key}")
            self._snapshots[key] = snapshot.model_copy(deep=True)
        return snapshot

    def get_snapshot(self, list_kind: ListKind, version: str) -> ListSnapshot | None:
        snap = self._snapshots.get((list_kind.value, version))
        return snap.model_copy(deep=True) if snap else None

    def list_snapshots(self, list_kind: ListKind | None = None) -> list[ListSnapshot]:
        snaps = list(self._snapshots.values())
        if list_kind is not None:
            snaps = [s for s in snaps if s.list_kind is list_kind]
        return [s.model_copy(deep=True) for s in snaps]

    def add_screening_run(self, run: ScreeningRun) -> ScreeningRun:
        with self._lock:
            self._runs.append(run.model_copy(deep=True))
        return run

    def list_screening_runs(self, case_id: str) -> list[ScreeningRun]:
        return [
            r.model_copy(deep=True)
            for r in self._runs
            if r.case_id == case_id
        ]

    def add_hit(self, hit: ScreeningHit) -> ScreeningHit:
        with self._lock:
            self._hits[hit.hit_id] = hit.model_copy(deep=True)
        return hit

    def get_hit(self, hit_id: str) -> ScreeningHit | None:
        hit = self._hits.get(hit_id)
        return hit.model_copy(deep=True) if hit else None

    def list_hits(self, case_id: str) -> list[ScreeningHit]:
        return [
            h.model_copy(deep=True)
            for h in self._hits.values()
            if h.case_id == case_id
        ]

    def update_hit(self, hit: ScreeningHit) -> ScreeningHit:
        with self._lock:
            if hit.hit_id not in self._hits:
                raise KeyError(hit.hit_id)
            self._hits[hit.hit_id] = hit.model_copy(deep=True)
        return hit

    # --- typologies (Law 4): packs, profiles, transactions, findings --
    def save_rule_pack(self, pack: RulePack) -> RulePack:
        with self._lock:
            key = (pack.pack_id, pack.version)
            if key in self._packs:
                raise KeyError(f"rule pack already exists: {key}")
            self._packs[key] = pack.model_copy(deep=True)
        return pack

    def get_rule_pack(self, pack_id: str, version: str) -> RulePack | None:
        pack = self._packs.get((pack_id, version))
        return pack.model_copy(deep=True) if pack else None

    def list_rule_packs(self) -> list[RulePack]:
        return [p.model_copy(deep=True) for p in self._packs.values()]

    def save_account_profile(self, profile: AccountProfile) -> AccountProfile:
        with self._lock:
            self._profiles[profile.account_id] = profile.model_copy(deep=True)
        return profile

    def get_account_profile(self, account_id: str) -> AccountProfile | None:
        profile = self._profiles.get(account_id)
        return profile.model_copy(deep=True) if profile else None

    def add_transaction_batch(self, batch: TransactionBatch) -> TransactionBatch:
        with self._lock:
            self._batches[batch.batch_id] = batch.model_copy(deep=True)
        return batch

    def get_transaction_batch(
        self, case_id: str, content_sha256: str
    ) -> TransactionBatch | None:
        for batch in self._batches.values():
            if batch.case_id == case_id and batch.content_sha256 == content_sha256:
                return batch.model_copy(deep=True)
        return None

    def list_transaction_batches(self, case_id: str) -> list[TransactionBatch]:
        return [
            b.model_copy(deep=True)
            for b in self._batches.values()
            if b.case_id == case_id
        ]

    def add_transactions(
        self, case_id: str, batch_id: str, transactions: list[Transaction]
    ) -> None:
        with self._lock:
            existing = {t.transaction_id for t in self._transactions.get(case_id, [])}
            for txn in transactions:
                if txn.transaction_id in existing:
                    raise KeyError(
                        f"transaction already stored for case {case_id}: "
                        f"{txn.transaction_id}"
                    )
                existing.add(txn.transaction_id)
            self._transactions.setdefault(case_id, []).extend(
                t.model_copy(deep=True) for t in transactions
            )

    def list_transactions(self, case_id: str) -> list[Transaction]:
        txns = self._transactions.get(case_id, [])
        ordered = sorted(txns, key=lambda t: (t.posted_at, t.transaction_id))
        return [t.model_copy(deep=True) for t in ordered]

    def add_typology_run(self, run: TypologyRun) -> TypologyRun:
        with self._lock:
            self._typology_runs.append(run.model_copy(deep=True))
        return run

    def list_typology_runs(self, case_id: str) -> list[TypologyRun]:
        return [
            r.model_copy(deep=True)
            for r in self._typology_runs
            if r.case_id == case_id
        ]

    def get_typology_run_by_fingerprint(
        self, case_id: str, pack_id: str, version: str, fingerprint: str
    ) -> TypologyRun | None:
        for run in self._typology_runs:
            if (
                run.case_id == case_id
                and run.rule_pack_id == pack_id
                and run.rule_pack_version == version
                and run.input_fingerprint == fingerprint
            ):
                return run.model_copy(deep=True)
        return None

    def add_finding(self, finding: TypologyFinding) -> TypologyFinding:
        with self._lock:
            self._findings[finding.finding_id] = finding.model_copy(deep=True)
        return finding

    def list_findings(self, case_id: str) -> list[TypologyFinding]:
        # Insertion order; the service presents findings in engine order.
        return [
            f.model_copy(deep=True)
            for f in self._findings.values()
            if f.case_id == case_id
        ]

    # --- investigations (R4): append-only record versions -----------
    def add_investigation_record(
        self, record: InvestigationRecord
    ) -> InvestigationRecord:
        with self._lock:
            self._investigation_records.append(record.model_copy(deep=True))
        return record

    def list_investigation_records(
        self, case_id: str
    ) -> list[InvestigationRecord]:
        records = [
            r for r in self._investigation_records if r.case_id == case_id
        ]
        return [
            r.model_copy(deep=True)
            for r in sorted(records, key=lambda r: r.version)
        ]

    def get_investigation_record(
        self, record_id: str
    ) -> InvestigationRecord | None:
        for record in self._investigation_records:
            if record.record_id == record_id:
                return record.model_copy(deep=True)
        return None

    # --- dispositions (R5): append-only records + confirmations -----
    def add_disposition(self, record: DispositionRecord) -> DispositionRecord:
        with self._lock:
            self._dispositions.append(record.model_copy(deep=True))
        return record

    def list_dispositions(self, case_id: str) -> list[DispositionRecord]:
        records = [r for r in self._dispositions if r.case_id == case_id]
        return [
            r.model_copy(deep=True)
            for r in sorted(records, key=lambda r: (r.decided_at, r.disposition_id))
        ]

    def get_disposition(self, disposition_id: str) -> DispositionRecord | None:
        for record in self._dispositions:
            if record.disposition_id == disposition_id:
                return record.model_copy(deep=True)
        return None

    def add_confirmation(
        self, confirmation: DispositionConfirmation
    ) -> DispositionConfirmation:
        with self._lock:
            self._confirmations.append(confirmation.model_copy(deep=True))
        return confirmation

    def list_confirmations(
        self, case_id: str
    ) -> list[DispositionConfirmation]:
        confs = [c for c in self._confirmations if c.case_id == case_id]
        return [
            c.model_copy(deep=True)
            for c in sorted(confs, key=lambda c: (c.decided_at, c.confirmation_id))
        ]

    def get_confirmation_for(
        self, disposition_id: str
    ) -> DispositionConfirmation | None:
        for confirmation in self._confirmations:
            if confirmation.disposition_id == disposition_id:
                return confirmation.model_copy(deep=True)
        return None


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

    # --- screening (Law 3): snapshots, runs, hits --------------------
    def save_snapshot(self, snapshot: ListSnapshot) -> ListSnapshot:
        self._execute(
            "INSERT INTO list_snapshots (snapshot_id, list_kind, version,"
            " published_at, content_hash, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (
                snapshot.snapshot_id,
                snapshot.list_kind.value,
                snapshot.version,
                snapshot.published_at.isoformat(),
                snapshot.content_hash,
                snapshot.model_dump_json(),
            ),
        )
        self._commit()
        return snapshot

    def get_snapshot(self, list_kind: ListKind, version: str) -> ListSnapshot | None:
        row = self._fetchone(
            "SELECT payload FROM list_snapshots WHERE list_kind = ? AND version = ?",
            (list_kind.value, version),
        )
        return ListSnapshot.model_validate_json(row["payload"]) if row else None

    def list_snapshots(self, list_kind: ListKind | None = None) -> list[ListSnapshot]:
        if list_kind is None:
            rows = self._fetchall(
                "SELECT payload FROM list_snapshots ORDER BY list_kind, published_at"
            )
        else:
            rows = self._fetchall(
                "SELECT payload FROM list_snapshots WHERE list_kind = ?"
                " ORDER BY published_at",
                (list_kind.value,),
            )
        return [ListSnapshot.model_validate_json(r["payload"]) for r in rows]

    def add_screening_run(self, run: ScreeningRun) -> ScreeningRun:
        self._execute(
            "INSERT INTO screening_runs (run_id, case_id, run_at, payload)"
            " VALUES (?, ?, ?, ?)",
            (run.run_id, run.case_id, run.run_at.isoformat(), run.model_dump_json()),
        )
        self._commit()
        return run

    def list_screening_runs(self, case_id: str) -> list[ScreeningRun]:
        rows = self._fetchall(
            "SELECT payload FROM screening_runs WHERE case_id = ?"
            " ORDER BY run_at ASC, run_id ASC",
            (case_id,),
        )
        return [ScreeningRun.model_validate_json(r["payload"]) for r in rows]

    def add_hit(self, hit: ScreeningHit) -> ScreeningHit:
        self._execute(
            "INSERT INTO screening_hits (hit_id, case_id, run_id, list_kind,"
            " status, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (
                hit.hit_id,
                hit.case_id,
                hit.run_id,
                hit.list_kind.value,
                hit.status.value,
                hit.model_dump_json(),
            ),
        )
        self._commit()
        return hit

    def get_hit(self, hit_id: str) -> ScreeningHit | None:
        row = self._fetchone(
            "SELECT payload FROM screening_hits WHERE hit_id = ?", (hit_id,)
        )
        return ScreeningHit.model_validate_json(row["payload"]) if row else None

    def list_hits(self, case_id: str) -> list[ScreeningHit]:
        rows = self._fetchall(
            "SELECT payload FROM screening_hits WHERE case_id = ?"
            " ORDER BY hit_id ASC",
            (case_id,),
        )
        return [ScreeningHit.model_validate_json(r["payload"]) for r in rows]

    def update_hit(self, hit: ScreeningHit) -> ScreeningHit:
        self._execute(
            "UPDATE screening_hits SET status = ?, payload = ? WHERE hit_id = ?",
            (hit.status.value, hit.model_dump_json(), hit.hit_id),
        )
        self._commit()
        return hit

    # --- typologies (Law 4): packs, profiles, transactions, findings --
    def save_rule_pack(self, pack: RulePack) -> RulePack:
        self._execute(
            "INSERT INTO rule_packs (pack_id, version, content_hash, payload)"
            " VALUES (?, ?, ?, ?)",
            (pack.pack_id, pack.version, pack.content_hash, pack.model_dump_json()),
        )
        self._commit()
        return pack

    def get_rule_pack(self, pack_id: str, version: str) -> RulePack | None:
        row = self._fetchone(
            "SELECT payload FROM rule_packs WHERE pack_id = ? AND version = ?",
            (pack_id, version),
        )
        return RulePack.model_validate_json(row["payload"]) if row else None

    def list_rule_packs(self) -> list[RulePack]:
        rows = self._fetchall(
            "SELECT payload FROM rule_packs ORDER BY pack_id, version"
        )
        return [RulePack.model_validate_json(r["payload"]) for r in rows]

    def save_account_profile(self, profile: AccountProfile) -> AccountProfile:
        existing = self.get_account_profile(profile.account_id)
        if existing is None:
            self._execute(
                "INSERT INTO account_profiles (account_id, customer_id, payload)"
                " VALUES (?, ?, ?)",
                (profile.account_id, profile.customer_id, profile.model_dump_json()),
            )
        else:
            self._execute(
                "UPDATE account_profiles SET payload = ? WHERE account_id = ?",
                (profile.model_dump_json(), profile.account_id),
            )
        self._commit()
        return profile

    def get_account_profile(self, account_id: str) -> AccountProfile | None:
        row = self._fetchone(
            "SELECT payload FROM account_profiles WHERE account_id = ?",
            (account_id,),
        )
        return AccountProfile.model_validate_json(row["payload"]) if row else None

    def add_transaction_batch(self, batch: TransactionBatch) -> TransactionBatch:
        self._execute(
            "INSERT INTO transaction_batches (batch_id, case_id, account_id,"
            " content_sha256, evidence_seq, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (
                batch.batch_id,
                batch.case_id,
                batch.account_id,
                batch.content_sha256,
                batch.evidence_seq,
                batch.model_dump_json(),
            ),
        )
        self._commit()
        return batch

    def get_transaction_batch(
        self, case_id: str, content_sha256: str
    ) -> TransactionBatch | None:
        row = self._fetchone(
            "SELECT payload FROM transaction_batches WHERE case_id = ?"
            " AND content_sha256 = ?",
            (case_id, content_sha256),
        )
        return TransactionBatch.model_validate_json(row["payload"]) if row else None

    def list_transaction_batches(self, case_id: str) -> list[TransactionBatch]:
        rows = self._fetchall(
            "SELECT payload FROM transaction_batches WHERE case_id = ?"
            " ORDER BY batch_id",
            (case_id,),
        )
        return [TransactionBatch.model_validate_json(r["payload"]) for r in rows]

    def add_transactions(
        self, case_id: str, batch_id: str, transactions: list[Transaction]
    ) -> None:
        for txn in transactions:
            self._execute(
                "INSERT INTO transactions (transaction_id, case_id, batch_id,"
                " account_id, posted_at, payload) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    txn.transaction_id,
                    case_id,
                    batch_id,
                    txn.account_id,
                    txn.posted_at.isoformat(),
                    txn.model_dump_json(),
                ),
            )
        self._commit()

    def list_transactions(self, case_id: str) -> list[Transaction]:
        rows = self._fetchall(
            "SELECT payload FROM transactions WHERE case_id = ?"
            " ORDER BY posted_at, transaction_id",
            (case_id,),
        )
        return [Transaction.model_validate_json(r["payload"]) for r in rows]

    def add_typology_run(self, run: TypologyRun) -> TypologyRun:
        self._execute(
            "INSERT INTO typology_runs (run_id, case_id, rule_pack_id,"
            " rule_pack_version, input_fingerprint, run_at, payload)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                run.run_id,
                run.case_id,
                run.rule_pack_id,
                run.rule_pack_version,
                run.input_fingerprint,
                run.run_at.isoformat(),
                run.model_dump_json(),
            ),
        )
        self._commit()
        return run

    def list_typology_runs(self, case_id: str) -> list[TypologyRun]:
        rows = self._fetchall(
            "SELECT payload FROM typology_runs WHERE case_id = ?"
            " ORDER BY run_at ASC, run_id ASC",
            (case_id,),
        )
        return [TypologyRun.model_validate_json(r["payload"]) for r in rows]

    def get_typology_run_by_fingerprint(
        self, case_id: str, pack_id: str, version: str, fingerprint: str
    ) -> TypologyRun | None:
        row = self._fetchone(
            "SELECT payload FROM typology_runs WHERE case_id = ?"
            " AND rule_pack_id = ? AND rule_pack_version = ?"
            " AND input_fingerprint = ?",
            (case_id, pack_id, version, fingerprint),
        )
        return TypologyRun.model_validate_json(row["payload"]) if row else None

    def add_finding(self, finding: TypologyFinding) -> TypologyFinding:
        self._execute(
            "INSERT INTO typology_findings (finding_id, case_id, run_id,"
            " typology_id, payload) VALUES (?, ?, ?, ?, ?)",
            (
                finding.finding_id,
                finding.case_id,
                finding.run_id,
                finding.typology_id,
                finding.model_dump_json(),
            ),
        )
        self._commit()
        return finding

    def list_findings(self, case_id: str) -> list[TypologyFinding]:
        rows = self._fetchall(
            "SELECT payload FROM typology_findings WHERE case_id = ?"
            " ORDER BY finding_id",
            (case_id,),
        )
        return [TypologyFinding.model_validate_json(r["payload"]) for r in rows]

    # --- investigations (R4): append-only record versions -----------
    def add_investigation_record(
        self, record: InvestigationRecord
    ) -> InvestigationRecord:
        self._execute(
            "INSERT INTO investigation_records (record_id, case_id, version,"
            " created_at, payload) VALUES (?, ?, ?, ?, ?)",
            (
                record.record_id,
                record.case_id,
                record.version,
                record.created_at.isoformat(),
                record.model_dump_json(),
            ),
        )
        self._commit()
        return record

    def list_investigation_records(
        self, case_id: str
    ) -> list[InvestigationRecord]:
        rows = self._fetchall(
            "SELECT payload FROM investigation_records WHERE case_id = ?"
            " ORDER BY version ASC",
            (case_id,),
        )
        return [InvestigationRecord.model_validate_json(r["payload"]) for r in rows]

    def get_investigation_record(
        self, record_id: str
    ) -> InvestigationRecord | None:
        row = self._fetchone(
            "SELECT payload FROM investigation_records WHERE record_id = ?",
            (record_id,),
        )
        return (
            InvestigationRecord.model_validate_json(row["payload"]) if row else None
        )

    # --- dispositions (R5): append-only records + confirmations -----
    def add_disposition(self, record: DispositionRecord) -> DispositionRecord:
        self._execute(
            "INSERT INTO dispositions (disposition_id, case_id, outcome,"
            " decided_at, payload) VALUES (?, ?, ?, ?, ?)",
            (
                record.disposition_id,
                record.case_id,
                record.outcome.value,
                record.decided_at.isoformat(),
                record.model_dump_json(),
            ),
        )
        self._commit()
        return record

    def list_dispositions(self, case_id: str) -> list[DispositionRecord]:
        rows = self._fetchall(
            "SELECT payload FROM dispositions WHERE case_id = ?"
            " ORDER BY decided_at ASC, disposition_id ASC",
            (case_id,),
        )
        return [DispositionRecord.model_validate_json(r["payload"]) for r in rows]

    def get_disposition(self, disposition_id: str) -> DispositionRecord | None:
        row = self._fetchone(
            "SELECT payload FROM dispositions WHERE disposition_id = ?",
            (disposition_id,),
        )
        return DispositionRecord.model_validate_json(row["payload"]) if row else None

    def add_confirmation(
        self, confirmation: DispositionConfirmation
    ) -> DispositionConfirmation:
        self._execute(
            "INSERT INTO disposition_confirmations (confirmation_id,"
            " disposition_id, case_id, decided_at, payload)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                confirmation.confirmation_id,
                confirmation.disposition_id,
                confirmation.case_id,
                confirmation.decided_at.isoformat(),
                confirmation.model_dump_json(),
            ),
        )
        self._commit()
        return confirmation

    def list_confirmations(
        self, case_id: str
    ) -> list[DispositionConfirmation]:
        rows = self._fetchall(
            "SELECT payload FROM disposition_confirmations WHERE case_id = ?"
            " ORDER BY decided_at ASC, confirmation_id ASC",
            (case_id,),
        )
        return [
            DispositionConfirmation.model_validate_json(r["payload"]) for r in rows
        ]

    def get_confirmation_for(
        self, disposition_id: str
    ) -> DispositionConfirmation | None:
        row = self._fetchone(
            "SELECT payload FROM disposition_confirmations"
            " WHERE disposition_id = ?",
            (disposition_id,),
        )
        return (
            DispositionConfirmation.model_validate_json(row["payload"])
            if row
            else None
        )
