"""Ports: the interfaces every external system sits behind.

The blueprint never talks to a monitoring vendor, a database, or an
object store directly — it talks to these protocols, and each
deployment profile wires an adapter. Tests wire in-memory doubles
that honour the same contracts.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import (
    Alert,
    AuditEvent,
    Case,
    EvidenceItem,
    ListKind,
    ListSnapshot,
    ScreeningHit,
    ScreeningRun,
)


@runtime_checkable
class CaseStore(Protocol):
    """Persistence for cases, evidence metadata, and the audit log."""

    def ping(self) -> bool: ...

    # --- cases -----------------------------------------------------
    def create_case(self, case: Case) -> Case: ...

    def get_case(self, case_id: str) -> Case | None: ...

    def get_case_by_alert(self, alert_id: str) -> Case | None: ...

    def update_case(self, case: Case) -> Case: ...

    def list_cases(self, status: str | None = None) -> list[Case]: ...

    # --- evidence metadata (blobs live in the ObjectStore) ---------
    def add_evidence_item(self, item: EvidenceItem) -> EvidenceItem: ...

    def list_evidence(self, case_id: str) -> list[EvidenceItem]: ...

    def get_evidence_item(self, case_id: str, seq: int) -> EvidenceItem | None: ...

    # --- audit ------------------------------------------------------
    def append_audit(self, event: AuditEvent) -> AuditEvent: ...

    def list_audit(self, case_id: str) -> list[AuditEvent]: ...


@runtime_checkable
class ObjectStore(Protocol):
    """Blob storage for evidence content (S3-compatible in production).

    There is deliberately no update or delete: evidence is immutable
    (Law 5). Corrections are new items in the case store.
    """

    def ping(self) -> bool: ...

    def put(self, key: str, content: bytes, media_type: str) -> None: ...

    def get(self, key: str) -> bytes: ...


@runtime_checkable
class AlertSource(Protocol):
    """The transaction-monitoring system, as an intake port."""

    def get_alert(self, alert_id: str) -> Alert | None: ...

    def list_alerts(self) -> list[Alert]: ...


@runtime_checkable
class ScreeningStore(Protocol):
    """Persistence for list snapshots, screening runs, and hits.

    There is deliberately no update or delete for snapshots: a
    snapshot, once ingested, is immutable (Law 3). Hits are the one
    mutable record — an analyst's clear/confirm is a status change
    with the reason kept on the hit and in the audit log.
    """

    def save_snapshot(self, snapshot: ListSnapshot) -> ListSnapshot: ...

    def get_snapshot(
        self, list_kind: ListKind, version: str
    ) -> ListSnapshot | None: ...

    def list_snapshots(
        self, list_kind: ListKind | None = None
    ) -> list[ListSnapshot]: ...

    def add_screening_run(self, run: ScreeningRun) -> ScreeningRun: ...

    def list_screening_runs(self, case_id: str) -> list[ScreeningRun]: ...

    def add_hit(self, hit: ScreeningHit) -> ScreeningHit: ...

    def get_hit(self, hit_id: str) -> ScreeningHit | None: ...

    def list_hits(self, case_id: str) -> list[ScreeningHit]: ...

    def update_hit(self, hit: ScreeningHit) -> ScreeningHit: ...


@runtime_checkable
class ScreeningListSource(Protocol):
    """Where snapshot definitions come from (a licensed list feed in
    production; a reference JSON file in the blueprint)."""

    def list_snapshots(self) -> list[ListSnapshot]: ...
