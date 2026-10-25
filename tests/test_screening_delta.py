"""R2 delta re-screening and the sanctions must-escalate posture."""

from __future__ import annotations

import pytest

from aml_investigations.errors import (
    IllegalTransitionError,
    SanctionsHitBlocksCloseError,
    ScreeningError,
)
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.models import (
    Alert,
    CaseStatus,
    Disposition,
    HitStatus,
    ListKind,
)
from tests.test_screening import ingest_v1, okafor_alert, sanctions_v2

PINS_V1 = {ListKind.SANCTIONS: "2026.10.1"}
PINS_V2 = {ListKind.SANCTIONS: "2026.10.2"}


def _open_case(services, alert: Alert):
    intake = IntakeService(services.store, ListAlertFeed([alert]), services.evidence)
    return intake.open_case(alert.alert_id)


def _walk_to_gate(services, case_id: str):
    for target in (
        CaseStatus.ASSEMBLING,
        CaseStatus.INVESTIGATING,
        CaseStatus.AWAITING_ANALYST,
    ):
        services.workflow.transition(case_id, target, actor="investigation-service")


def _screened_case_on_v2(services):
    """Case screened clean on sanctions v1, then hit by the v2 delta."""
    ingest_v1(services)
    case = _open_case(services, okafor_alert())
    services.screening.screen_case(case.case_id, PINS_V1, actor="screening-service")
    services.screening.ingest_snapshot(sanctions_v2())
    services.screening.screen_case(case.case_id, PINS_V2, actor="screening-service")
    return services.store.get_case(case.case_id)


def test_delta_flags_stale_on_ingest(services):
    ingest_v1(services)
    case = _open_case(services, okafor_alert())
    services.screening.screen_case(case.case_id, PINS_V1, actor="screening-service")
    assert services.store.get_case(case.case_id).screening_stale is False

    services.screening.ingest_snapshot(sanctions_v2())

    flagged = services.store.get_case(case.case_id)
    assert flagged.screening_stale is True
    assert "STALE_SCREENING" in flagged.flags
    events = [e.event for e in services.store.list_audit(case.case_id)]
    assert "screening_stale_flagged" in events


def test_terminal_cases_are_not_flagged_stale(services):
    ingest_v1(services)
    case = _open_case(services, okafor_alert())
    services.screening.screen_case(case.case_id, PINS_V1, actor="screening-service")
    _walk_to_gate(services, case.case_id)
    services.workflow.transition(
        case.case_id,
        CaseStatus.CLOSED,
        actor="analyst:j.rivera",
        disposition=Disposition(
            analyst="j.rivera", decision="close", reason_code="BENIGN"
        ),
    )
    services.screening.ingest_snapshot(sanctions_v2())
    closed = services.store.get_case(case.case_id)
    assert closed.screening_stale is False
    assert "STALE_SCREENING" not in closed.flags


def test_rescreen_on_delta_surfaces_hit_and_clears_stale(services):
    ingest_v1(services)
    case = _open_case(services, okafor_alert())
    first = services.screening.screen_case(
        case.case_id, PINS_V1, actor="screening-service"
    )
    assert first.open_hits == 0  # Daniel Okafor is not on v1

    services.screening.ingest_snapshot(sanctions_v2())
    assert services.store.get_case(case.case_id).screening_stale is True

    second = services.screening.screen_case(
        case.case_id, PINS_V2, actor="screening-service"
    )
    assert second.is_rescreen is True
    assert second.open_hits == 1

    refreshed = services.store.get_case(case.case_id)
    assert refreshed.screening_stale is False
    assert "STALE_SCREENING" not in refreshed.flags
    assert "SANCTIONS_HIT" in refreshed.flags
    assert {
        s.list_kind: s.version for s in refreshed.screened_against
    }[ListKind.SANCTIONS] == "2026.10.2"

    # Both versions' runs stay on the record.
    runs = services.store.list_screening_runs(case.case_id)
    assert [r.pins[0].version for r in runs] == ["2026.10.1", "2026.10.2"]

    run_hits = [
        h
        for h in services.store.list_hits(case.case_id)
        if h.run_id == second.run_id and h.list_kind is ListKind.SANCTIONS
    ]
    # The re-screen re-runs every subject: the namesake clears again,
    # and exactly one OPEN hit surfaces — the delta's new entry.
    open_hits = [h for h in run_hits if h.status is HitStatus.OPEN]
    assert len(open_hits) == 1
    assert any(h.status is HitStatus.CLEARED for h in run_hits)
    hit = open_hits[0]
    assert hit.entry_id == "SDN-1004"
    assert hit.snapshot_version == "2026.10.2"
    assert hit.strength == "strong"
    assert "identifier_match" in hit.basis

    events = [e.event for e in services.store.list_audit(case.case_id)]
    assert "sanctions_hit" in events
    assert services.evidence.verify_chain(case.case_id) is True


def test_sanctions_hit_blocks_plain_close(services):
    case = _screened_case_on_v2(services)
    _walk_to_gate(services, case.case_id)
    with pytest.raises(SanctionsHitBlocksCloseError):
        services.workflow.transition(
            case.case_id,
            CaseStatus.CLOSED,
            actor="analyst:j.rivera",
            disposition=Disposition(
                analyst="j.rivera", decision="close", reason_code="BENIGN"
            ),
        )
    still = services.store.get_case(case.case_id)
    assert still.status is CaseStatus.AWAITING_ANALYST
    refusals = [
        e
        for e in services.store.list_audit(case.case_id)
        if e.event == "transition_refused"
    ]
    assert refusals and "sanctions" in refusals[-1].detail["reason"]


def test_sanctions_hit_still_allows_escalate_and_file_sar(services):
    case = _screened_case_on_v2(services)
    _walk_to_gate(services, case.case_id)
    escalated = services.workflow.transition(
        case.case_id,
        CaseStatus.ESCALATED,
        actor="analyst:j.rivera",
        disposition=Disposition(
            analyst="j.rivera", decision="escalate", reason_code="SANCTIONS_HIT"
        ),
    )
    assert escalated.status is CaseStatus.ESCALATED
    services.workflow.transition(
        case.case_id, CaseStatus.AWAITING_ANALYST, actor="supervisor:m.okafor"
    )
    filed = services.workflow.transition(
        case.case_id,
        CaseStatus.FILED_SAR,
        actor="analyst:j.rivera",
        disposition=Disposition(
            analyst="j.rivera", decision="file_sar", reason_code="SANCTIONS_HIT"
        ),
    )
    assert filed.status is CaseStatus.FILED_SAR


def test_clearing_the_hit_with_a_reason_unblocks_close(services):
    case = _screened_case_on_v2(services)
    hit = services.screening.unresolved_sanctions_hits(case.case_id)[0]

    with pytest.raises(ScreeningError):
        services.screening.set_hit_status(
            hit.hit_id, HitStatus.CLEARED, actor="analyst:j.rivera", reason="  "
        )

    cleared = services.screening.set_hit_status(
        hit.hit_id,
        HitStatus.CLEARED,
        actor="analyst:j.rivera",
        reason="Different person: passport number on file does not match the listing.",
    )
    assert cleared.status is HitStatus.CLEARED
    refreshed = services.store.get_case(case.case_id)
    assert "SANCTIONS_HIT" not in refreshed.flags
    events = [e.event for e in services.store.list_audit(case.case_id)]
    assert "screening_hit_cleared" in events

    _walk_to_gate(services, case.case_id)
    closed = services.workflow.transition(
        case.case_id,
        CaseStatus.CLOSED,
        actor="analyst:j.rivera",
        disposition=Disposition(
            analyst="j.rivera", decision="close", reason_code="HIT_CLEARED_NAME_MATCH_ONLY"
        ),
    )
    assert closed.status is CaseStatus.CLOSED


def test_confirmed_hit_still_blocks_close(services):
    case = _screened_case_on_v2(services)
    hit = services.screening.unresolved_sanctions_hits(case.case_id)[0]
    services.screening.set_hit_status(
        hit.hit_id,
        HitStatus.CONFIRMED,
        actor="analyst:j.rivera",
        reason="Identifier and DOB both match the listing.",
    )
    _walk_to_gate(services, case.case_id)
    with pytest.raises(IllegalTransitionError):
        services.workflow.transition(
            case.case_id,
            CaseStatus.CLOSED,
            actor="analyst:j.rivera",
            disposition=Disposition(
                analyst="j.rivera", decision="close", reason_code="BENIGN"
            ),
        )
