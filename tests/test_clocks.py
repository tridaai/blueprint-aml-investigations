"""R8 regulatory clocks: deadlines computed in code (Law 6).

The graded table pins the arithmetic to literal expected dates —
day 30, day 60, leap-year February, month-end detection — computed
independently of the implementation. Around it: the subject
extension is a coded state (an unidentified subject moves the
operative deadline to the 60-day outer limit; a bare name does
not identify), boundary states land on the exact days, a standing
no-file disposition closes the clock and is named as the no-file
documentation, a terminal case with no disposition is a reported
violation, the continuing-activity trigger fires at intake, and
escalation crossings are recorded on the chain exactly once.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from aml_investigations.clocks import (
    RegulatoryClockService,
    continuing_deadlines,
    filing_deadlines,
)
from aml_investigations.errors import CaseNotFoundError
from aml_investigations.evidence import EvidenceService
from aml_investigations.models import (
    Alert,
    Case,
    CaseStatus,
    ClockState,
    Disposition,
    DispositionOutcome,
    DispositionRecord,
    HitStatus,
    ListKind,
    ScreeningHit,
)
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.stores import SqlCaseStore

REPO_ROOT = Path(__file__).resolve().parents[1]

_counter = [0]


def _bare_case(
    services,
    *,
    customer_id: str = "CUST-CLK",
    detected_on: date = date(2026, 10, 20),
    status: CaseStatus = CaseStatus.OPENED,
    subject: bool = False,
    name_only: bool = False,
) -> Case:
    """A case straight into the store, with (optionally) its alert
    payload evidence — the facts a filing clock reads."""
    _counter[0] += 1
    n = _counter[0]
    case = Case(
        alert_id=f"ALRT-CLK-{n}",
        customer_id=customer_id,
        account_id=f"ACCT-CLK-{n}",
        rule_id="TM-CLOCK-01",
        detected_on=detected_on,
        status=status,
    )
    services.store.create_case(case)
    if subject or name_only:
        raw = {"customer_name": "Casey Subject", "counterparties": []}
        if not name_only:
            raw["customer_dob"] = "1980-04-12"
            raw["customer_identifiers"] = ["PP-XX-0001"]
        alert = Alert(
            alert_id=case.alert_id,
            rule_id=case.rule_id,
            customer_id=customer_id,
            account_id=case.account_id,
            detected_on=detected_on,
            raw=raw,
        )
        services.evidence.add_item(
            case.case_id,
            kind="alert_payload",
            content=alert.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"monitoring-feed:{case.alert_id}",
            captured_by="test",
        )
    return services.store.get_case(case.case_id)


def _disposition_record(
    case_id: str,
    *,
    outcome: DispositionOutcome = DispositionOutcome.CLOSE_NO_ACTION,
    codes: list[str] | None = None,
    requires_confirmation: bool = False,
    review_due_on: date | None = None,
    decided_at: datetime | None = None,
) -> DispositionRecord:
    return DispositionRecord(
        case_id=case_id,
        analyst_id="e.okafor",
        analyst_role="analyst",
        outcome=outcome,
        rationale_codes=codes or ["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"],
        rationale_vocabulary_version="2026.10.1",
        record_id="inv-test",
        record_version=1,
        requires_confirmation=requires_confirmation,
        review_period_days=90 if review_due_on else None,
        review_due_on=review_due_on,
        decided_at=decided_at
        or datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc),
    )


# -- the graded deadline table --------------------------------------


@pytest.mark.parametrize(
    "detected_on, initial, outer",
    [
        (date(2026, 10, 20), date(2026, 11, 19), date(2026, 12, 19)),
        (date(2026, 1, 31), date(2026, 3, 2), date(2026, 4, 1)),
        (date(2024, 2, 29), date(2024, 3, 30), date(2024, 4, 29)),
        (date(2023, 2, 28), date(2023, 3, 30), date(2023, 4, 29)),
        (date(2026, 12, 15), date(2027, 1, 14), date(2027, 2, 13)),
        (date(2026, 2, 28), date(2026, 3, 30), date(2026, 4, 29)),
    ],
)
def test_filing_deadline_table(detected_on, initial, outer):
    assert filing_deadlines(detected_on) == (initial, outer)


def test_filing_clock_carries_both_deadlines(services):
    case = _bare_case(services, subject=True)
    clock = services.clocks.filing_clock(case, as_of=date(2026, 10, 21))
    assert clock.initial_deadline == date(2026, 11, 19)
    assert clock.outer_deadline == date(2026, 12, 19)
    assert clock.operative_deadline == date(2026, 11, 19)
    assert clock.operative_deadline_kind == "initial"
    assert clock.subject_identified is True
    assert clock.subject_basis == "alert_payload"
    assert clock.state is ClockState.ON_TRACK
    assert clock.days_remaining == 29


def test_continuing_deadline_table():
    review, filing = continuing_deadlines(date(2026, 9, 1))
    assert review == date(2026, 11, 30)
    assert filing == date(2026, 12, 30)


# -- the subject extension is a coded state ---------------------------


def test_unidentified_subject_uses_outer_deadline(services):
    case = _bare_case(services)  # no alert payload facts at all
    clock = services.clocks.filing_clock(case, as_of=date(2026, 11, 25))
    assert clock.subject_identified is False
    assert clock.subject_basis == "none"
    assert clock.operative_deadline == date(2026, 12, 19)
    assert clock.operative_deadline_kind == "outer"
    # Past the 30-day mark, still on track against the outer limit.
    assert clock.state is ClockState.ON_TRACK
    assert clock.days_remaining == 24


def test_bare_name_does_not_identify_a_subject(services):
    case = _bare_case(services, name_only=True)
    clock = services.clocks.filing_clock(case, as_of=date(2026, 10, 21))
    assert clock.subject_identified is False
    assert clock.operative_deadline_kind == "outer"


def test_identifiers_alone_identify_a_subject(services):
    # Name + recorded identifiers, no date of birth: identified.
    fresh = _bare_case(services, customer_id="CUST-CLK-ID")
    alert = Alert(
        alert_id=fresh.alert_id,
        rule_id=fresh.rule_id,
        customer_id=fresh.customer_id,
        account_id=fresh.account_id,
        detected_on=fresh.detected_on,
        raw={"customer_name": "Casey Subject",
             "customer_identifiers": ["PP-XX-0001"]},
    )
    services.evidence.add_item(
        fresh.case_id,
        kind="alert_payload",
        content=alert.model_dump_json(indent=2).encode("utf-8"),
        source_ref="monitoring-feed:ids",
        captured_by="test",
    )
    clock = services.clocks.filing_clock(fresh, as_of=date(2026, 10, 21))
    assert clock.subject_identified is True
    assert clock.subject_basis == "alert_payload"


def test_corroborated_hit_identifies_subject(services):
    case = _bare_case(services)
    services.store.add_hit(
        ScreeningHit(
            case_id=case.case_id,
            run_id="run-test",
            subject_ref=case.customer_id,
            subject_name="Casey Subject",
            subject_role="customer",
            list_kind=ListKind.SANCTIONS,
            snapshot_id="snap-test",
            snapshot_version="2026.10.1",
            entry_id="SDN-1",
            entry_name="Casey Subject",
            score=0.99,
            basis="name + identifier match",
            strength="strong",
            status=HitStatus.OPEN,
        )
    )
    clock = services.clocks.filing_clock(case, as_of=date(2026, 10, 21))
    assert clock.subject_identified is True
    assert clock.subject_basis == "screening_hit"
    assert clock.operative_deadline_kind == "initial"


# -- boundary states ---------------------------------------------------


def test_boundary_states(services):
    case = _bare_case(services, subject=True)  # deadline 2026-11-19
    clocks = services.clocks
    assert clocks.filing_clock(case, as_of=date(2026, 11, 11)).state is (
        ClockState.ON_TRACK
    )  # 8 days left
    assert clocks.filing_clock(case, as_of=date(2026, 11, 12)).state is (
        ClockState.DUE_SOON
    )  # exactly 7 days left
    assert clocks.filing_clock(case, as_of=date(2026, 11, 19)).state is (
        ClockState.DUE
    )  # day 30 exactly
    overdue = clocks.filing_clock(case, as_of=date(2026, 11, 20))
    assert overdue.state is ClockState.OVERDUE  # day 31
    assert overdue.days_remaining == -1


def test_outer_boundary_day_60(services):
    case = _bare_case(services)  # unidentified; outer 2026-12-19
    clocks = services.clocks
    assert clocks.filing_clock(case, as_of=date(2026, 12, 19)).state is (
        ClockState.DUE
    )
    assert clocks.filing_clock(case, as_of=date(2026, 12, 20)).state is (
        ClockState.OVERDUE
    )


def test_clock_computation_is_deterministic(services):
    case = _bare_case(services, subject=True)
    first = services.clocks.case_clocks(case.case_id, as_of=date(2026, 11, 1))
    second = services.clocks.case_clocks(case.case_id, as_of=date(2026, 11, 1))
    assert first == second


# -- endings: satisfied, no-file, violations ----------------------------


def test_satisfied_when_filed(services):
    case = _bare_case(
        services,
        status=CaseStatus.FILED_SAR,
        subject=True,
    )
    case.disposition = Disposition(
        analyst="e.okafor",
        decision="file_sar",
        reason_code="STRUCTURING_CONFIRMED",
        decided_at=datetime(2026, 11, 1, tzinfo=timezone.utc),
    )
    services.store.update_case(case)
    view = services.clocks.case_clocks(case.case_id, as_of=date(2027, 1, 1))
    assert view.filing.state is ClockState.SATISFIED
    assert view.filing.days_remaining is None
    assert view.violations == []


def test_closed_no_file_names_the_disposition(services):
    case = _bare_case(services, status=CaseStatus.CLOSED, subject=True)
    record = _disposition_record(case.case_id)
    services.store.add_disposition(record)
    view = services.clocks.case_clocks(case.case_id, as_of=date(2026, 12, 1))
    assert view.filing.state is ClockState.CLOSED_NO_FILE
    assert view.filing.no_file_disposition_id == record.disposition_id
    assert view.filing.no_file_rationale_codes == [
        "NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"
    ]
    assert view.filing.no_file_decided_on == date(2026, 10, 24)
    assert view.violations == []


def test_pending_confirmation_keeps_clock_live(services):
    case = _bare_case(
        services, status=CaseStatus.PENDING_CONFIRMATION, subject=True
    )
    services.store.add_disposition(
        _disposition_record(case.case_id, requires_confirmation=True)
    )
    clock = services.clocks.filing_clock(case, as_of=date(2026, 10, 25))
    assert clock.state in (
        ClockState.ON_TRACK,
        ClockState.DUE_SOON,
        ClockState.DUE,
        ClockState.OVERDUE,
    )
    assert clock.no_file_disposition_id is None


def test_close_monitor_closes_clock_with_review_date(services):
    case = _bare_case(services, status=CaseStatus.MONITORING, subject=True)
    record = _disposition_record(
        case.case_id,
        outcome=DispositionOutcome.CLOSE_MONITOR,
        codes=["PATTERN_EXPLAINED_MONITOR_ACTIVITY"],
        review_due_on=date(2027, 1, 22),
    )
    services.store.add_disposition(record)
    clock = services.clocks.filing_clock(case, as_of=date(2026, 12, 1))
    assert clock.state is ClockState.CLOSED_NO_FILE
    assert clock.no_file_disposition_id == record.disposition_id
    assert clock.monitor_review_due_on == date(2027, 1, 22)


def test_reopened_case_clock_is_live_again(services):
    case = _bare_case(services, status=CaseStatus.ESCALATED, subject=True)
    services.store.add_disposition(
        _disposition_record(
            case.case_id,
            outcome=DispositionOutcome.CLOSE_MONITOR,
            codes=["PATTERN_EXPLAINED_MONITOR_ACTIVITY"],
            review_due_on=date(2027, 1, 22),
            decided_at=datetime(2026, 10, 20, tzinfo=timezone.utc),
        )
    )
    services.store.add_disposition(
        _disposition_record(
            case.case_id,
            outcome=DispositionOutcome.ESCALATE_L2,
            codes=["CONFLICTING_EVIDENCE"],
            decided_at=datetime(2026, 10, 24, tzinfo=timezone.utc),
        )
    )
    clock = services.clocks.filing_clock(case, as_of=date(2026, 10, 25))
    assert clock.state is not ClockState.CLOSED_NO_FILE
    assert clock.no_file_disposition_id is None


def test_terminal_without_disposition_is_a_violation(services):
    case = _bare_case(services, status=CaseStatus.CLOSED, subject=True)
    view = services.clocks.case_clocks(case.case_id, as_of=date(2026, 10, 25))
    assert "terminal_without_disposition" in view.violations
    assert view.filing.state is not ClockState.CLOSED_NO_FILE
    assert view.filing.no_file_disposition_id is None


# -- the continuing-activity trigger -------------------------------------


def _filed_prior(services, customer_id: str, decided: datetime) -> Case:
    prior = Case(
        alert_id=f"ALRT-PRIOR-{customer_id}",
        customer_id=customer_id,
        account_id="ACCT-PRIOR",
        rule_id="TM-STRUCTURING-01",
        detected_on=date(2026, 8, 2),
        status=CaseStatus.FILED_SAR,
        disposition=Disposition(
            analyst="e.okafor",
            decision="file_sar",
            reason_code="STRUCTURING_CONFIRMED",
            decided_at=decided,
        ),
    )
    services.store.create_case(prior)
    return prior


def test_intake_starts_continuing_clock_for_filed_customer(services):
    prior = _filed_prior(
        services, "CUST-1001", datetime(2026, 9, 1, 9, 30, tzinfo=timezone.utc)
    )
    case = services.intake.open_case("ALRT-T-001")
    assert case.case_id != prior.case_id

    clocks = services.clocks
    link = clocks.continuing_link_for(case.case_id)
    assert link is not None
    assert link.prior_case_id == prior.case_id
    assert link.determination_on == date(2026, 9, 1)
    assert link.review_due_on == date(2026, 11, 30)
    assert link.filing_due_on == date(2026, 12, 30)
    kinds = [i.kind for i in services.store.list_evidence(case.case_id)]
    assert kinds == ["alert_payload", "continuing_activity_link"]
    events = [e.event for e in services.store.list_audit(case.case_id)]
    assert "continuing_activity_clock_started" in events

    at_review = clocks.case_clocks(case.case_id, as_of=date(2026, 11, 30))
    continuing = at_review.continuing_activity
    assert continuing is not None
    assert continuing.state is ClockState.DUE
    assert continuing.operative_deadline_kind == "continuing_review"
    assert continuing.review_overdue is False

    after_review = clocks.case_clocks(case.case_id, as_of=date(2026, 12, 15))
    continuing = after_review.continuing_activity
    assert continuing.operative_deadline_kind == "continuing_filing"
    assert continuing.operative_deadline == date(2026, 12, 30)
    assert continuing.review_overdue is True
    assert continuing.state is ClockState.ON_TRACK  # 15 days to filing

    past_filing = clocks.case_clocks(case.case_id, as_of=date(2026, 12, 31))
    assert past_filing.continuing_activity.state is ClockState.OVERDUE
    assert past_filing.continuing_activity.days_remaining == -1

    # Intake idempotency: re-delivering the alert opens nothing
    # new and starts no second clock.
    again = services.intake.open_case("ALRT-T-001")
    assert again.case_id == case.case_id
    kinds = [i.kind for i in services.store.list_evidence(case.case_id)]
    assert kinds.count("continuing_activity_link") == 1


def test_no_continuing_clock_without_filed_prior(services):
    case = services.intake.open_case("ALRT-T-002")  # CUST-1002: no priors
    assert services.clocks.continuing_link_for(case.case_id) is None
    view = services.clocks.case_clocks(case.case_id, as_of=date(2026, 11, 1))
    assert view.continuing_activity is None


def test_continuing_clock_satisfied_when_new_case_files(services):
    _filed_prior(
        services, "CUST-1001", datetime(2026, 9, 1, tzinfo=timezone.utc)
    )
    case = services.intake.open_case("ALRT-T-001")
    case.status = CaseStatus.FILED_SAR
    case.disposition = Disposition(
        analyst="e.okafor",
        decision="file_sar",
        reason_code="STRUCTURING_CONFIRMED",
        decided_at=datetime(2026, 11, 20, tzinfo=timezone.utc),
    )
    services.store.update_case(case)
    view = services.clocks.case_clocks(case.case_id, as_of=date(2027, 2, 1))
    assert view.continuing_activity.state is ClockState.SATISFIED


# -- escalation: recording, idempotency, the queue -----------------------


def test_refresh_records_due_then_overdue_once_each(services):
    case = _bare_case(
        services, detected_on=date(2026, 9, 25), subject=True
    )  # initial deadline 2026-10-25
    clocks = services.clocks
    assert clocks.refresh_escalations(case.case_id, as_of=date(2026, 10, 24)) == []
    due_events = clocks.refresh_escalations(case.case_id, as_of=date(2026, 10, 25))
    assert len(due_events) == 1
    assert due_events[0].state == "due"
    assert due_events[0].deadline == date(2026, 10, 25)
    assert due_events[0].deadline_kind == "initial"
    assert due_events[0].evidence_seq is not None
    # Re-computation never duplicates a crossing.
    assert clocks.refresh_escalations(case.case_id, as_of=date(2026, 10, 25)) == []
    over_events = clocks.refresh_escalations(case.case_id, as_of=date(2026, 10, 28))
    assert len(over_events) == 1
    assert over_events[0].state == "overdue"
    assert over_events[0].days_overdue == 3
    assert clocks.refresh_escalations(case.case_id, as_of=date(2026, 10, 29)) == []
    recorded = clocks.recorded_escalations(case.case_id)
    assert [e.state for e in recorded] == ["due", "overdue"]
    assert services.evidence.verify_chain(case.case_id) is True
    view = clocks.case_clocks(case.case_id, as_of=date(2026, 10, 28))
    assert len(view.escalations) == 2


def test_refresh_on_ended_clock_records_nothing(services):
    case = _bare_case(
        services, status=CaseStatus.FILED_SAR, subject=True
    )
    case.disposition = Disposition(
        analyst="e.okafor",
        decision="file_sar",
        reason_code="STRUCTURING_CONFIRMED",
    )
    services.store.update_case(case)
    assert (
        services.clocks.refresh_escalations(
            case.case_id, as_of=date(2027, 6, 1)
        )
        == []
    )


def test_escalation_queue_order_and_exclusions(services):
    as_of = date(2026, 10, 25)
    overdue = _bare_case(
        services, customer_id="CUST-Q-OVER", detected_on=date(2026, 8, 1),
        subject=True,
    )  # deadline 2026-08-31
    due = _bare_case(
        services, customer_id="CUST-Q-DUE", detected_on=date(2026, 9, 25),
        subject=True,
    )  # deadline 2026-10-25
    soon = _bare_case(
        services, customer_id="CUST-Q-SOON", detected_on=date(2026, 10, 2),
        subject=True,
    )  # deadline 2026-11-01, 7 days out
    _bare_case(
        services, customer_id="CUST-Q-CALM", detected_on=date(2026, 10, 24),
        subject=True,
    )  # on track
    filed = _bare_case(
        services, customer_id="CUST-Q-FILED", detected_on=date(2026, 8, 1),
        status=CaseStatus.FILED_SAR, subject=True,
    )
    filed.disposition = Disposition(
        analyst="e.okafor", decision="file_sar",
        reason_code="STRUCTURING_CONFIRMED",
    )
    services.store.update_case(filed)
    closed = _bare_case(
        services, customer_id="CUST-Q-CLOSED", detected_on=date(2026, 8, 1),
        status=CaseStatus.CLOSED, subject=True,
    )
    services.store.add_disposition(_disposition_record(closed.case_id))

    queue = services.clocks.escalation_queue(as_of=as_of)
    assert [e.case_id for e in queue] == [
        overdue.case_id,
        due.case_id,
        soon.case_id,
    ]
    assert [e.state for e in queue] == [
        ClockState.OVERDUE,
        ClockState.DUE,
        ClockState.DUE_SOON,
    ]
    assert "2026-08-31" in queue[0].reason
    assert "30-day initial deadline" in queue[0].reason
    assert "overdue" in queue[0].reason
    assert queue[1].reason.endswith("due today")
    assert filed.case_id not in [e.case_id for e in queue]
    assert closed.case_id not in [e.case_id for e in queue]


def test_board_puts_most_urgent_first(services):
    as_of = date(2026, 10, 25)
    calm = _bare_case(
        services, customer_id="CUST-B-CALM", detected_on=date(2026, 10, 24),
        subject=True,
    )
    overdue = _bare_case(
        services, customer_id="CUST-B-OVER", detected_on=date(2026, 8, 1),
        subject=True,
    )
    board = services.clocks.clock_board(as_of=as_of)
    ids = [v.case_id for v in board]
    assert ids.index(overdue.case_id) < ids.index(calm.case_id)
    assert board[ids.index(overdue.case_id)].filing.state is ClockState.OVERDUE


def test_case_clocks_unknown_case(services):
    with pytest.raises(CaseNotFoundError):
        services.clocks.case_clocks("case-nope", as_of=date(2026, 10, 25))


# -- the derivation runs over the SQL store too ---------------------------


def test_clocks_over_sql_store(tmp_path):
    store = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects)
    clocks = RegulatoryClockService(store, store, store, evidence)
    case = Case(
        alert_id="ALRT-SQL-1",
        customer_id="CUST-SQL",
        account_id="ACCT-SQL",
        rule_id="TM-CLOCK-01",
        detected_on=date(2026, 9, 25),
    )
    store.create_case(case)
    fresh = clocks.refresh_escalations(case.case_id, as_of=date(2026, 11, 30))
    assert len(fresh) == 1  # outer deadline 2026-11-24 crossed, overdue
    assert fresh[0].deadline_kind == "outer"

    reopened = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    clocks2 = RegulatoryClockService(
        reopened, reopened, reopened, EvidenceService(reopened, objects)
    )
    assert clocks2.refresh_escalations(case.case_id, as_of=date(2026, 11, 30)) == []
    assert len(clocks2.recorded_escalations(case.case_id)) == 1
    view = clocks2.case_clocks(case.case_id, as_of=date(2026, 11, 30))
    assert view.filing.state is ClockState.OVERDUE
    assert view.filing.operative_deadline == date(2026, 11, 24)
