"""R9 continuing-activity reviews: the workflow answering R8's clock.

A review is assembled per cycle — window activity, every item
cited, the continuation assessment coded in code — and only a
named analyst's recorded disposition answers the clock for that
cycle: file_continuing routes the case through the R5 gate into
the R6 narrative path (whose draft cites the review and the prior
filing), no_file_this_cycle is documented by coded rationale and
starts the next cycle, chained by review id. An opened but
undispositioned review satisfies nothing.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from aml_investigations.approval import SarApprovalService
from aml_investigations.clocks import RegulatoryClockService
from aml_investigations.dispositions import DispositionService
from aml_investigations.errors import ContinuingReviewRefusedError
from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.investigation import InvestigationService
from aml_investigations.models import (
    Alert,
    ApprovalOutcome,
    CaseStatus,
    ClockState,
    DispositionOutcome,
    ListKind,
    ReviewOutcome,
    RulePack,
    Transaction,
)
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.reviews import ContinuingReviewService
from aml_investigations.sar import SarNarrativeService
from aml_investigations.sealing import CaseSealingService
from aml_investigations.screening import ScreeningService
from aml_investigations.stores import InMemoryCaseStore, SqlCaseStore
from aml_investigations.transactions import ListTransactionFeed
from aml_investigations.typologies import TypologyService
from aml_investigations.workflow import CaseWorkflow
from tests.test_sar import (
    ACCOUNT,
    ANALYST,
    CUSTOMER,
    CUSTOMER_SUBJECT,
    SANCTIONS,
    STRUCTURING_STREAM,
    identity_alert,
    profile,
    txn,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REVIEWER = "b.osei"
APPROVER = "m.rivera"


class Stack:
    """The full stack with R9 wired: intake records continuing
    links, the clock service reads review outcomes, the narrative
    service cites continuing reviews."""

    def __init__(self, tmp_path: Path, alerts, store=None):
        self.store = store or InMemoryCaseStore()
        self.objects = LocalObjectStore(tmp_path / "objects")
        self.evidence = EvidenceService(
            self.store, self.objects, seal_store=self.store
        )
        self.workflow = CaseWorkflow(
            self.store, screening_store=self.store
        )
        self.clocks = RegulatoryClockService(
            self.store,
            self.store,
            self.store,
            self.evidence,
            approvals=self.store,
            review_store=self.store,
        )
        self._alerts = list(alerts)
        self.intake = self._make_intake()
        self.screening = ScreeningService(
            self.store, self.store, self.evidence, seal_store=self.store
        )
        self.typologies = TypologyService(
            self.store, self.store, self.evidence, seal_store=self.store
        )
        self.investigations = InvestigationService(
            self.store,
            self.store,
            self.store,
            self.store,
            self.evidence,
            disposition_store=self.store,
            seal_store=self.store,
        )
        self.dispositions = DispositionService(
            self.store,
            self.store,
            self.store,
            self.store,
            self.evidence,
            self.workflow,
            seal_store=self.store,
        )
        self.sar = SarNarrativeService(
            self.store,
            self.store,
            self.store,
            self.store,
            self.evidence,
            approval_store=self.store,
            seal_store=self.store,
            review_store=self.store,
        )
        self.approvals = SarApprovalService(
            self.store,
            self.store,
            self.store,
            self.store,
            self.sar,
            self.evidence,
            self.workflow,
            seal_store=self.store,
        )
        self.sealing = CaseSealingService(
            self.store,
            self.store,
            self.store,
            self.store,
            self.store,
            self.evidence,
            self.store,
        )
        self.reviews = ContinuingReviewService(
            self.store,
            self.store,
            self.store,
            self.store,
            self.store,
            self.store,
            self.store,
            self.evidence,
            self.clocks,
            self.dispositions,
            seal_store=self.store,
        )
        self.screening.ingest_snapshot(SANCTIONS, actor="test-feed")
        self.typologies.register_rule_pack(
            RulePack(pack_id="test-pack", version="1.0")
        )

    def _make_intake(self) -> IntakeService:
        return IntakeService(
            self.store,
            ListAlertFeed(self._alerts),
            self.evidence,
            clock_service=self.clocks,
        )

    def add_alert(self, alert: Alert) -> None:
        """A later alert arrives: the feed is rebuilt around the
        extended list (ListAlertFeed snapshots its alerts)."""
        self._alerts.append(alert)
        self.intake = self._make_intake()

    def open_case(self, alert_id: str, stream) -> str:
        case_id = self.intake.open_case(alert_id).case_id
        self.workflow.transition(
            case_id, CaseStatus.ASSEMBLING, actor="test"
        )
        self.screening.screen_case(
            case_id,
            {ListKind.SANCTIONS: "2026.10.1"},
            actor="test",
            subjects=[CUSTOMER_SUBJECT],
        )
        feed = ListTransactionFeed([profile()], {ACCOUNT: stream})
        self.typologies.ingest_from_source(
            case_id, feed, actor="test-feed"
        )
        self.typologies.run_typologies(
            case_id, "test-pack", "1.0", actor="test-runner"
        )
        self.workflow.transition(
            case_id, CaseStatus.INVESTIGATING, actor="test"
        )
        return case_id

    def investigated_case(self, alert_id: str, stream):
        case_id = self.open_case(alert_id, stream)
        record = self.investigations.run_investigation(
            case_id, actor="test"
        )
        self.workflow.transition(
            case_id, CaseStatus.AWAITING_ANALYST, actor="test"
        )
        return case_id, record

    def filed_prior(self, alert_id: str = "ALRT-S-1") -> tuple[str, date]:
        """A complete prior filing; returns (case_id,
        determination date) — the anchor every R9 date hangs off."""
        case_id, record = self.investigated_case(
            alert_id, STRUCTURING_STREAM
        )
        self.dispositions.record_disposition(
            case_id,
            analyst_id=ANALYST,
            analyst_role="analyst",
            outcome=DispositionOutcome.ESCALATE_SAR,
            rationale_codes=["STRUCTURING_SUSPECTED"],
            record_id=record.record_id,
            record_version=record.version,
        )
        self.sar.draft_narrative(case_id, actor="sar-drafting-service")
        self.approvals.decide_narrative(
            case_id,
            approver_id=APPROVER,
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
        case = self.store.get_case(case_id)
        assert case.status is CaseStatus.FILED_SAR
        return case_id, self.clocks.filing_determination_date(case)

    def continuing_case(self, stream_factory):
        """Prior filed; a new alert inside the window; the new
        case investigated and standing at the analyst gate, its
        continuing clock running. Returns (prior_id,
        determination, case_id, record)."""
        prior_id, determination = self.filed_prior()
        self.add_alert(
            window_alert(
                "ALRT-R9-2", determination + timedelta(days=5)
            )
        )
        case_id, record = self.investigated_case(
            "ALRT-R9-2", stream_factory(determination)
        )
        return prior_id, determination, case_id, record


def window_alert(alert_id: str, detected: date) -> Alert:
    # A date object, not a string: model_copy does not re-run
    # pydantic's coercion, and the alert's detected_on is a date.
    return identity_alert(alert_id).model_copy(
        update={"detected_on": detected}
    )


def window_structuring(determination: date) -> list[Transaction]:
    """The filed typology again, inside the window — plus one
    pre-window transaction the review must not count as window
    activity."""
    return [
        txn(
            "T-W0",
            determination - timedelta(days=40),
            "4200.00",
            channel="ach",
        ),
        txn(
            "T-W1",
            determination + timedelta(days=10),
            "9500",
            cash=True,
            channel="branch",
        ),
        txn(
            "T-W2",
            determination + timedelta(days=12),
            "9600",
            cash=True,
            channel="branch",
        ),
        txn(
            "T-W3",
            determination + timedelta(days=14),
            "9700",
            cash=True,
            channel="branch",
        ),
    ]


def window_cadence(determination: date) -> list[Transaction]:
    """The control cadence inside the window: regular sub-threshold
    cash deposits that fire no typology."""
    return [
        txn(
            f"T-N{i}",
            determination + timedelta(days=10 + 10 * i),
            "9500",
            cash=True,
            channel="branch",
        )
        for i in range(9)
    ]


# ------------------------------------------------------------------
# The file-continuing cycle, end to end
# ------------------------------------------------------------------


def test_file_continuing_cycle_end_to_end(tmp_path):
    stack = Stack(tmp_path, [identity_alert("ALRT-S-1")])
    prior_id, determination, case_id, record = stack.continuing_case(
        window_structuring
    )
    assert record.hypothesis.label == "structuring"

    link = stack.clocks.continuing_link_for(case_id)
    assert link is not None and link.prior_case_id == prior_id

    review = stack.reviews.open_review(case_id, actor=REVIEWER)
    assert review.cycle == 1
    assert review.prior_case_id == prior_id
    assert review.determination_on == determination
    assert review.review_due_on == determination + timedelta(days=90)
    assert review.filing_due_on == determination + timedelta(days=120)
    assert review.record_id == record.record_id
    assert review.filed_typology_label == "structuring"
    assert review.prior_narrative_id is not None
    assert review.continuation_assessment == "continues_filed_typology"
    kinds = [item.kind for item in review.activity]
    assert "prior_filing" in kinds
    assert "window_alert" in kinds
    assert "window_transactions" in kinds
    assert "record_hypothesis" in kinds
    assert "typology_finding" in kinds
    assert "screening_state" in kinds
    assert stack.reviews.verify_review(review) == []
    assert review.evidence_seq is not None

    # An open review does not satisfy the clock.
    clocks = stack.clocks.case_clocks(
        case_id, as_of=determination + timedelta(days=95)
    )
    continuing = clocks.continuing_activity
    assert continuing is not None
    assert continuing.state in (
        ClockState.ON_TRACK,
        ClockState.DUE_SOON,
        ClockState.DUE,
        ClockState.OVERDUE,
    )
    assert continuing.answered_by_review_id is None

    # One open review per cycle.
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.open_review(case_id, actor=REVIEWER)
    assert refused.value.reason == "review_already_open"

    # The decision is a named analyst's, with coded rationale.
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.record_review_disposition(
            case_id,
            review.review_id,
            analyst_id="investigation-service",
            analyst_role="senior_analyst",
            outcome=ReviewOutcome.FILE_CONTINUING,
            rationale_codes=["STRUCTURING_SUSPECTED"],
        )
    assert refused.value.reason == "anonymous_or_system_actor"
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.record_review_disposition(
            case_id,
            review.review_id,
            analyst_id=REVIEWER,
            analyst_role="senior_analyst",
            outcome=ReviewOutcome.FILE_CONTINUING,
            rationale_codes=[],
        )
    assert refused.value.reason == "rationale_codes_required"
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.record_review_disposition(
            case_id,
            review.review_id,
            analyst_id=REVIEWER,
            analyst_role="senior_analyst",
            outcome=ReviewOutcome.FILE_CONTINUING,
            rationale_codes=["ACTIVITY_CEASED"],
        )
    assert refused.value.reason == "unknown_rationale_code"

    disposition = stack.reviews.record_review_disposition(
        case_id,
        review.review_id,
        analyst_id=REVIEWER,
        analyst_role="senior_analyst",
        outcome=ReviewOutcome.FILE_CONTINUING,
        rationale_codes=["STRUCTURING_SUSPECTED"],
    )
    assert disposition.case_disposition_id is not None
    case = stack.store.get_case(case_id)
    assert case.status is CaseStatus.SAR_PENDING
    assert (
        stack.reviews.review_status(review)
        == "decided_file_continuing"
    )

    # Answered, but not satisfied until the case files — and no
    # second cycle starts on a file-continuing answer.
    clocks = stack.clocks.case_clocks(
        case_id, as_of=determination + timedelta(days=95)
    )
    continuing = clocks.continuing_activity
    assert continuing.answered_by_review_id == review.review_id
    assert continuing.answered_outcome == "file_continuing"
    assert continuing.state is ClockState.ON_TRACK
    assert len(clocks.continuing_history) == 1

    # A cycle's decision is recorded exactly once.
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.record_review_disposition(
            case_id,
            review.review_id,
            analyst_id=REVIEWER,
            analyst_role="senior_analyst",
            outcome=ReviewOutcome.FILE_CONTINUING,
            rationale_codes=["STRUCTURING_SUSPECTED"],
        )
    assert refused.value.reason == "already_dispositioned"

    # The continuing narrative cites the review and the prior filing.
    narrative, verification = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    assert verification.all_verified
    activity = next(
        s for s in narrative.sections if s.key == "activity_summary"
    )
    opening = activity.statements[0]
    assert "continuing-activity review" in opening.text
    assert review.review_id in opening.text
    assert prior_id in opening.text
    assert any(
        c.case_id == prior_id for c in opening.citations
    ), "the continuing statement must cite the prior case's chain"

    stack.approvals.decide_narrative(
        case_id,
        approver_id="s.ike",
        approver_role="senior_analyst",
        outcome=ApprovalOutcome.APPROVED,
    )
    assert (
        stack.store.get_case(case_id).status is CaseStatus.FILED_SAR
    )
    clocks = stack.clocks.case_clocks(
        case_id, as_of=determination + timedelta(days=200)
    )
    assert clocks.continuing_activity.state is ClockState.SATISFIED
    assert (
        clocks.continuing_activity.answered_by_review_id
        == review.review_id
    )

    history = stack.reviews.history_for_customer(CUSTOMER)
    assert [r["review_id"] for r in history["reviews"]] == [
        review.review_id
    ]
    assert len(history["dispositions"]) == 1


# ------------------------------------------------------------------
# The no-file cycle and the rolling chain
# ------------------------------------------------------------------


def test_no_file_cycles_chain(tmp_path):
    stack = Stack(tmp_path, [identity_alert("ALRT-S-1")])
    prior_id, determination, case_id, record = stack.continuing_case(
        window_cadence
    )
    assert record.hypothesis.label == "no_adverse_pattern"

    review = stack.reviews.open_review(case_id, actor=REVIEWER)
    assert (
        review.continuation_assessment
        == "no_adverse_activity_in_window"
    )

    # No-file without coded rationale is refused — free text never
    # documents a cycle.
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.record_review_disposition(
            case_id,
            review.review_id,
            analyst_id=REVIEWER,
            analyst_role="senior_analyst",
            outcome=ReviewOutcome.NO_FILE_THIS_CYCLE,
            rationale_codes=[],
            note="looked fine to me",
        )
    assert refused.value.reason == "rationale_codes_required"
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.record_review_disposition(
            case_id,
            review.review_id,
            analyst_id=REVIEWER,
            analyst_role="senior_analyst",
            outcome=ReviewOutcome.NO_FILE_THIS_CYCLE,
            rationale_codes=["STRUCTURING_SUSPECTED"],
        )
    assert refused.value.reason == "unknown_rationale_code"

    disposition = stack.reviews.record_review_disposition(
        case_id,
        review.review_id,
        analyst_id=REVIEWER,
        analyst_role="senior_analyst",
        outcome=ReviewOutcome.NO_FILE_THIS_CYCLE,
        rationale_codes=["ACTIVITY_CEASED"],
        note="The cadence is the customer's payroll pattern.",
    )
    assert disposition.case_disposition_id is None
    decided_on = disposition.decided_at.date()

    clocks = stack.clocks.case_clocks(case_id, as_of=decided_on)
    assert len(clocks.continuing_history) == 2
    cycle1, cycle2 = clocks.continuing_history
    assert cycle1.cycle == 1
    assert cycle1.state is ClockState.CLOSED_NO_FILE
    assert cycle1.answered_by_review_id == review.review_id
    assert cycle1.answered_outcome == "no_file_this_cycle"
    assert cycle2.cycle == 2
    assert cycle2.determination_on == decided_on
    assert cycle2.review_due_on == decided_on + timedelta(days=90)
    assert cycle2.filing_due_on == decided_on + timedelta(days=120)
    assert cycle2.prior_review_id == review.review_id
    assert clocks.continuing_activity.cycle == 2

    # Cycle 2's review names the review that started its cycle.
    review2 = stack.reviews.open_review(case_id, actor=REVIEWER)
    assert review2.cycle == 2
    assert review2.prior_review_id == review.review_id
    assert review2.determination_on == decided_on

    stack.reviews.record_review_disposition(
        case_id,
        review2.review_id,
        analyst_id=REVIEWER,
        analyst_role="senior_analyst",
        outcome=ReviewOutcome.NO_FILE_THIS_CYCLE,
        rationale_codes=["NO_CONTINUATION_EVIDENCE"],
    )
    clocks = stack.clocks.case_clocks(case_id, as_of=decided_on)
    assert len(clocks.continuing_history) == 3
    assert clocks.continuing_history[1].answered_by_review_id == (
        review2.review_id
    )
    assert clocks.continuing_history[2].prior_review_id == (
        review2.review_id
    )


# ------------------------------------------------------------------
# Refusals and standing
# ------------------------------------------------------------------


def test_open_review_requires_a_continuing_clock(tmp_path):
    stack = Stack(tmp_path, [identity_alert("ALRT-S-1")])
    case_id, _record = stack.investigated_case(
        "ALRT-S-1", STRUCTURING_STREAM
    )
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.open_review(case_id, actor=REVIEWER)
    assert refused.value.reason == "no_continuing_clock"


def test_open_review_before_investigation_is_refused(tmp_path):
    stack = Stack(tmp_path, [identity_alert("ALRT-S-1")])
    _prior_id, determination = stack.filed_prior()
    stack.add_alert(
        window_alert("ALRT-R9-2", determination + timedelta(days=5))
    )
    case_id = stack.intake.open_case("ALRT-R9-2").case_id
    assert stack.clocks.continuing_link_for(case_id) is not None
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.open_review(case_id, actor=REVIEWER)
    assert refused.value.reason == "no_investigation_record"


def test_stale_review_is_superseded_never_edited(tmp_path):
    stack = Stack(tmp_path, [identity_alert("ALRT-S-1")])
    _prior, determination, case_id, _record = stack.continuing_case(
        window_structuring
    )
    review = stack.reviews.open_review(case_id, actor=REVIEWER)

    # New evidence arrives — another deposit in the window — the
    # typologies re-run and the record moves to version 2.
    stack.workflow.transition(
        case_id, CaseStatus.INVESTIGATING, actor="test"
    )
    stack.typologies.ingest_transactions(
        case_id,
        [
            txn(
                "T-W4",
                determination + timedelta(days=16),
                "9800",
                cash=True,
                channel="branch",
            )
        ],
        source_ref="test-feed-2",
        actor="test-feed",
    )
    stack.typologies.run_typologies(
        case_id, "test-pack", "1.0", actor="test-runner"
    )
    record2 = stack.investigations.run_investigation(
        case_id, actor="test"
    )
    assert record2.version == 2
    stack.workflow.transition(
        case_id, CaseStatus.AWAITING_ANALYST, actor="test"
    )
    assert stack.reviews.review_status(review) == "stale"
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.record_review_disposition(
            case_id,
            review.review_id,
            analyst_id=REVIEWER,
            analyst_role="senior_analyst",
            outcome=ReviewOutcome.NO_FILE_THIS_CYCLE,
            rationale_codes=["ACTIVITY_CEASED"],
        )
    assert refused.value.reason == "review_stale"

    fresh = stack.reviews.open_review(case_id, actor=REVIEWER)
    assert fresh.supersedes_review_id == review.review_id
    assert fresh.record_version == 2
    assert stack.reviews.review_status(review) == "superseded"
    assert stack.reviews.review_status(fresh) == "open"
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.record_review_disposition(
            case_id,
            review.review_id,
            analyst_id=REVIEWER,
            analyst_role="senior_analyst",
            outcome=ReviewOutcome.NO_FILE_THIS_CYCLE,
            rationale_codes=["ACTIVITY_CEASED"],
        )
    assert refused.value.reason == "review_superseded"


def test_file_continuing_requires_the_gate_state(tmp_path):
    stack = Stack(tmp_path, [identity_alert("ALRT-S-1")])
    _prior, _det, case_id, _record = stack.continuing_case(
        window_structuring
    )
    review = stack.reviews.open_review(case_id, actor=REVIEWER)
    # The case steps back to investigating: the gate no longer
    # stands where a routing disposition can be recorded.
    stack.workflow.transition(
        case_id, CaseStatus.INVESTIGATING, actor="test"
    )
    with pytest.raises(ContinuingReviewRefusedError) as refused:
        stack.reviews.record_review_disposition(
            case_id,
            review.review_id,
            analyst_id=REVIEWER,
            analyst_role="senior_analyst",
            outcome=ReviewOutcome.FILE_CONTINUING,
            rationale_codes=["STRUCTURING_SUSPECTED"],
        )
    assert refused.value.reason == "case_not_awaiting_analyst"


def test_undispositioned_review_escalates_as_overdue(tmp_path):
    stack = Stack(tmp_path, [identity_alert("ALRT-S-1")])
    _prior, determination, case_id, _record = stack.continuing_case(
        window_structuring
    )
    stack.reviews.open_review(case_id, actor=REVIEWER)
    filing_due = determination + timedelta(days=120)
    events = stack.clocks.refresh_escalations(
        case_id, as_of=filing_due + timedelta(days=1)
    )
    continuing = [
        e for e in events if e.clock_kind == "continuing_activity"
    ]
    assert continuing
    assert continuing[0].deadline_kind == "continuing_filing"
    clocks = stack.clocks.case_clocks(
        case_id, as_of=filing_due + timedelta(days=1)
    )
    assert clocks.continuing_activity.state is ClockState.OVERDUE
    assert clocks.continuing_activity.answered_by_review_id is None


def test_verify_gate_rejects_uncited_and_ungrounded_items(tmp_path):
    stack = Stack(tmp_path, [identity_alert("ALRT-S-1")])
    _prior, _det, case_id, _record = stack.continuing_case(
        window_structuring
    )
    review = stack.reviews.open_review(case_id, actor=REVIEWER)
    assert stack.reviews.verify_review(review) == []

    first = review.activity[0]
    uncited = review.model_copy(
        update={
            "activity": [
                first.model_copy(update={"citations": []}),
                *review.activity[1:],
            ]
        }
    )
    problems = stack.reviews.verify_review(uncited)
    assert any("no citations" in p for p in problems)

    finding_item = next(
        i for i in review.activity if i.kind == "typology_finding"
    )
    forged = review.model_copy(
        update={
            "activity": [
                finding_item.model_copy(
                    update={"figures": {"total_amount": "777777.77"}}
                )
                if item is finding_item
                else item
                for item in review.activity
            ]
        }
    )
    problems = stack.reviews.verify_review(forged)
    assert any(
        "does not appear in the records" in p for p in problems
    )


def test_scheduler_tick_opens_due_reviews(tmp_path):
    stack = Stack(tmp_path, [identity_alert("ALRT-S-1")])
    _prior, determination, case_id, _record = stack.continuing_case(
        window_structuring
    )
    review_due = determination + timedelta(days=90)
    assert (
        stack.reviews.open_due_reviews(
            as_of=review_due - timedelta(days=1)
        )
        == []
    )
    opened = stack.reviews.open_due_reviews(as_of=review_due)
    assert [r.case_id for r in opened] == [case_id]
    assert opened[0].opened_by == "clock-service"
    # A standing review is not opened twice.
    assert stack.reviews.open_due_reviews(as_of=review_due) == []


def test_review_over_sql_store(tmp_path):
    """The same flow over the SQL store: migration 0008's rows
    round-trip, and the clock derives its cycles from them."""
    store = SqlCaseStore.sqlite(
        tmp_path / "aml.db", REPO_ROOT / "migrations"
    )
    stack = Stack(
        tmp_path, [identity_alert("ALRT-S-1")], store=store
    )
    _prior, _det, case_id, _record = stack.continuing_case(
        window_structuring
    )
    review = stack.reviews.open_review(case_id, actor=REVIEWER)
    stack.reviews.record_review_disposition(
        case_id,
        review.review_id,
        analyst_id=REVIEWER,
        analyst_role="senior_analyst",
        outcome=ReviewOutcome.NO_FILE_THIS_CYCLE,
        rationale_codes=["ACTIVITY_CEASED"],
    )
    reread = store.get_review(review.review_id)
    assert reread is not None and reread.cycle == 1
    disposition = store.get_review_disposition_for(review.review_id)
    assert disposition is not None
    assert disposition.outcome is ReviewOutcome.NO_FILE_THIS_CYCLE
    clocks = stack.clocks.case_clocks(case_id, as_of=date.today())
    assert len(clocks.continuing_history) == 2
    assert (
        clocks.continuing_history[0].answered_by_review_id
        == review.review_id
    )
