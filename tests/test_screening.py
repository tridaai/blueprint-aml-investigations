"""R2 screening: snapshots, pins, matching, namesakes (Law 3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from aml_investigations.errors import (
    ScreeningError,
    ScreeningPinRequiredError,
    SnapshotImmutableError,
    SnapshotNotFoundError,
)
from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.models import (
    Alert,
    HitStatus,
    ListEntry,
    ListKind,
    ListSnapshot,
    ScreeningSubject,
)
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.screening import (
    ScreeningService,
    match_name,
    normalise_name,
    snapshot_content_hash,
)
from aml_investigations.stores import SqlCaseStore

REPO_ROOT = Path(__file__).resolve().parents[1]

PINS_V1 = {
    ListKind.SANCTIONS: "2026.10.1",
    ListKind.PEP: "2026.10.1",
    ListKind.ADVERSE_MEDIA: "2026.10.1",
}


def _snapshot(kind, version, published_at, entries):
    return ListSnapshot(
        list_kind=kind,
        version=version,
        published_at=published_at,
        source_note="test feed",
        entries=entries,
    )


def sanctions_v1():
    return _snapshot(
        ListKind.SANCTIONS,
        "2026.10.1",
        "2026-10-01T00:00:00Z",
        [
            ListEntry(
                entry_id="SDN-1001",
                name="Viktor Petrov",
                aliases=["Victor Petrov"],
                dob="1962-04-11",
                identifiers=["PP-XK-4471"],
            ),
            ListEntry(entry_id="SDN-1002", name="Dmitri Sokolov", dob="1975-01-30"),
        ],
    )


def sanctions_v2():
    return _snapshot(
        ListKind.SANCTIONS,
        "2026.10.2",
        "2026-10-24T00:00:00Z",
        sanctions_v1().entries
        + [
            ListEntry(
                entry_id="SDN-1004",
                name="Daniel Okafor",
                dob="1985-03-04",
                identifiers=["PP-NG-2210"],
            )
        ],
    )


def pep_v1():
    return _snapshot(
        ListKind.PEP,
        "2026.10.1",
        "2026-10-01T00:00:00Z",
        [ListEntry(entry_id="PEP-2001", name="Helena Voss", dob="1968-09-19")],
    )


def adverse_v1():
    return _snapshot(
        ListKind.ADVERSE_MEDIA,
        "2026.10.1",
        "2026-10-01T00:00:00Z",
        [ListEntry(entry_id="ADV-3001", name="Kestrel Trading FZE")],
    )


def ingest_v1(services):
    services.screening.ingest_snapshot(sanctions_v1())
    services.screening.ingest_snapshot(pep_v1())
    services.screening.ingest_snapshot(adverse_v1())


def _open_case(services, alert: Alert):
    intake = IntakeService(
        services.store, ListAlertFeed([alert]), services.evidence
    )
    return intake.open_case(alert.alert_id)


def okafor_alert(alert_id="ALRT-S-001"):
    return Alert(
        alert_id=alert_id,
        rule_id="TM-STRUCTURING-01",
        customer_id="CUST-1001",
        account_id="ACCT-5001",
        severity="high",
        detected_on="2026-10-20",
        summary="Structuring pattern.",
        raw={
            "customer_name": "Daniel Okafor",
            "customer_dob": "1985-03-04",
            "customer_identifiers": ["PP-NG-2210"],
            "counterparties": [{"name": "Viktor Petrov", "dob": "1979-06-02"}],
        },
    )


# --- snapshots --------------------------------------------------------


def test_snapshot_ingest_computes_hash_and_is_idempotent(services):
    snap = services.screening.ingest_snapshot(sanctions_v1())
    assert snap.content_hash == snapshot_content_hash(sanctions_v1())
    again = services.screening.ingest_snapshot(sanctions_v1())
    assert again.snapshot_id == snap.snapshot_id
    assert len(services.store.list_snapshots(ListKind.SANCTIONS)) == 1


def test_snapshot_conflicting_reingest_is_refused_and_original_stands(services):
    original = services.screening.ingest_snapshot(sanctions_v1())
    mutated = sanctions_v1().model_copy(
        update={
            "snapshot_id": "snap-mutated",
            "content_hash": "",
            "entries": sanctions_v1().entries[:1],
        }
    )
    with pytest.raises(SnapshotImmutableError):
        services.screening.ingest_snapshot(mutated)
    stored = services.store.get_snapshot(ListKind.SANCTIONS, "2026.10.1")
    assert stored.content_hash == original.content_hash
    assert stored.entry_count == 2


def test_snapshot_with_wrong_declared_hash_is_refused(services):
    forged = sanctions_v1().model_copy(update={"content_hash": "0" * 64})
    with pytest.raises(ScreeningError):
        services.screening.ingest_snapshot(forged)
    assert services.store.get_snapshot(ListKind.SANCTIONS, "2026.10.1") is None


def test_corrected_list_as_new_version_is_accepted(services):
    services.screening.ingest_snapshot(sanctions_v1())
    services.screening.ingest_snapshot(sanctions_v2())
    versions = {
        s.version for s in services.store.list_snapshots(ListKind.SANCTIONS)
    }
    assert versions == {"2026.10.1", "2026.10.2"}


# --- deterministic matching --------------------------------------------


def test_normalise_name_handles_diacritics_and_punctuation():
    assert normalise_name("José  O'Brien-Smith") == ["jose", "o", "brien", "smith"]
    assert normalise_name("JOSÉ OBRIEN SMITH") == ["jose", "obrien", "smith"]


def test_match_name_rules():
    assert match_name(["daniel", "okafor"], ["daniel", "okafor"]) == (1.0, "exact_name")
    assert match_name(["okafor", "daniel"], ["daniel", "okafor"]) == (
        0.95,
        "name_token_set",
    )
    assert match_name(
        ["daniel", "okafor"], ["daniel", "james", "okafor"]
    ) == (0.85, "name_token_subset")
    score, rule = match_name(
        ["daniel", "okafor", "smith"], ["daniel", "okafor", "jones"]
    )
    assert rule == "name_token_overlap" and score == 0.5
    assert match_name(["daniel", "okafor"], ["helena", "voss"]) is None
    assert match_name(["okafor"], ["daniel", "okafor"]) is None  # 1-token subset is not a match


# --- pins are mandatory -------------------------------------------------


def test_screening_without_a_pin_set_is_refused(services):
    ingest_v1(services)
    case = _open_case(services, okafor_alert())
    with pytest.raises(ScreeningPinRequiredError):
        services.screening.screen_case(case.case_id, {}, actor="screening-service")
    assert services.store.list_screening_runs(case.case_id) == []


def test_screening_against_an_uningested_version_is_refused(services):
    ingest_v1(services)
    case = _open_case(services, okafor_alert())
    with pytest.raises(SnapshotNotFoundError):
        services.screening.screen_case(
            case.case_id,
            {ListKind.SANCTIONS: "1999.01.1"},
            actor="screening-service",
        )


def test_screening_with_no_subjects_is_refused(services):
    ingest_v1(services)
    bare = Alert(
        alert_id="ALRT-S-002",
        rule_id="TM-VELOCITY-03",
        customer_id="CUST-1002",
        account_id="ACCT-5002",
        detected_on="2026-10-21",
    )
    case = _open_case(services, bare)
    with pytest.raises(ScreeningError):
        services.screening.screen_case(case.case_id, PINS_V1, actor="screening-service")


# --- a run is recorded, pinned, and evidenced ---------------------------


def test_run_records_pins_evidence_and_case_record(services):
    ingest_v1(services)
    case = _open_case(services, okafor_alert())
    run = services.screening.screen_case(case.case_id, PINS_V1, actor="screening-service")

    assert run.subject_count == 2  # customer + counterparty
    assert {p.list_kind for p in run.pins} == {
        ListKind.SANCTIONS,
        ListKind.PEP,
        ListKind.ADVERSE_MEDIA,
    }
    assert all(p.version == "2026.10.1" for p in run.pins)
    assert run.evidence_seq is not None

    refreshed = services.store.get_case(case.case_id)
    assert {s.list_kind: s.version for s in refreshed.screened_against} == {
        ListKind.SANCTIONS: "2026.10.1",
        ListKind.PEP: "2026.10.1",
        ListKind.ADVERSE_MEDIA: "2026.10.1",
    }
    assert refreshed.screening_stale is False

    kinds = [i.kind for i in services.store.list_evidence(case.case_id)]
    assert "screening_result" in kinds
    assert services.evidence.verify_chain(case.case_id) is True
    events = [e.event for e in services.store.list_audit(case.case_id)]
    assert "screening_run" in events


def test_screening_state_survives_a_new_service_instance(services):
    ingest_v1(services)
    case = _open_case(services, okafor_alert())
    services.screening.screen_case(case.case_id, PINS_V1, actor="screening-service")
    fresh = ScreeningService(services.store, services.store, services.evidence)
    assert fresh.unresolved_sanctions_hits(case.case_id) == []
    runs = services.store.list_screening_runs(case.case_id)
    assert len(runs) == 1 and runs[0].pins[0].version == "2026.10.1"


# --- namesakes ------------------------------------------------------------


def test_namesake_counterparty_is_a_cleared_hit_with_reason(services):
    ingest_v1(services)
    case = _open_case(services, okafor_alert())
    run = services.screening.screen_case(case.case_id, PINS_V1, actor="screening-service")
    hits = [
        h for h in services.store.list_hits(case.case_id) if h.run_id == run.run_id
    ]
    assert len(hits) == 1
    hit = hits[0]
    assert hit.subject_name == "Viktor Petrov"
    assert hit.entry_id == "SDN-1001"
    assert hit.status is HitStatus.CLEARED
    assert hit.cleared_reason == "date_of_birth_mismatch"
    assert "dob_mismatch_auto_cleared" in hit.basis
    assert run.open_hits == 0 and run.cleared_hits == 1
    refreshed = services.store.get_case(case.case_id)
    assert "SANCTIONS_HIT" not in refreshed.flags


def test_alias_surface_matches(services):
    ingest_v1(services)
    case = _open_case(services, okafor_alert())
    subjects = [
        ScreeningSubject(
            subject_ref="counterparty:x",
            name="Victor Petrov",
            role="counterparty",
            dob="1962-04-11",
        )
    ]
    run = services.screening.screen_case(
        case.case_id,
        {ListKind.SANCTIONS: "2026.10.1"},
        actor="screening-service",
        subjects=subjects,
    )
    hits = services.store.list_hits(case.case_id)
    assert len(hits) == 1
    assert hits[0].status is HitStatus.OPEN
    assert hits[0].strength == "strong"  # DOB corroborates
    assert "dob_match" in hits[0].basis
    assert run.open_hits == 1


# --- SQL store round trip ---------------------------------------------------


def test_screening_persists_in_sql_store(tmp_path):
    store = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects)
    intake = IntakeService(store, ListAlertFeed([okafor_alert("ALRT-SQL-1")]), evidence)
    screening = ScreeningService(store, store, evidence)
    screening.ingest_snapshot(sanctions_v1())
    case = intake.open_case("ALRT-SQL-1")
    screening.screen_case(
        case.case_id, {ListKind.SANCTIONS: "2026.10.1"}, actor="screening-service"
    )

    reopened = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    snap = reopened.get_snapshot(ListKind.SANCTIONS, "2026.10.1")
    assert snap is not None and snap.entry_count == 2
    persisted = reopened.get_case(case.case_id)
    assert persisted.screened_against[0].version == "2026.10.1"
    assert len(reopened.list_screening_runs(case.case_id)) == 1
    hits = reopened.list_hits(case.case_id)
    assert len(hits) == 1 and hits[0].status is HitStatus.CLEARED
    assert EvidenceService(reopened, objects).verify_chain(case.case_id) is True
