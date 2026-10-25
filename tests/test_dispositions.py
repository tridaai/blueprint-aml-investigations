"""R5 disposition gate: named analyst, coded rationale, current
record, sanctions posture, dual control, staleness.

The gate is where Law 1 gets its depth: a disposition is an
artefact that must cite the investigation record it relied on, in
coded language, from a named human — and an adverse closure does
not take effect until a second, different human confirms it.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from aml_investigations.dispositions import (
    FLAG_DISPOSITION_STALE,
    DispositionService,
)
from aml_investigations.errors import (
    DispositionRefusedError,
    IllegalTransitionError,
)
from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.investigation import InvestigationService
from aml_investigations.models import (
    AccountProfile,
    Alert,
    CaseStatus,
    ConfirmationOutcome,
    DispositionConfirmation,
    DispositionOutcome,
    DispositionRecord,
    ListEntry,
    ListKind,
    ListSnapshot,
    RulePack,
    ScreeningSubject,
    Transaction,
)
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.screening import ScreeningService
from aml_investigations.stores import InMemoryCaseStore, SqlCaseStore
from aml_investigations.transactions import ListTransactionFeed
from aml_investigations.typologies import TypologyService
from aml_investigations.workflow import CaseWorkflow

REPO_ROOT = Path(__file__).resolve().parents[1]

ACCOUNT = "ACCT-T-1"
CUSTOMER = "CUST-T-1"
ANALYST = "a.okafor"
L2 = "m.osei"


def at(day: date, hour: int = 10) -> datetime:
    return datetime.combine(day, time(hour, 0), tzinfo=timezone.utc)


def txn(
    tid: str,
    day: date,
    amount: str,
    *,
    direction: str = "credit",
    cash: bool = False,
    channel: str = "wire",
    hour: int = 10,
) -> Transaction:
    return Transaction(
        transaction_id=tid,
        account_id=ACCOUNT,
        posted_at=at(day, hour),
        direction=direction,
        amount=Decimal(amount),
        channel=channel,
        cash=cash,
    )


def alert(alert_id: str = "ALRT-D-1") -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="TM-STRUCTURING-01",
        customer_id=CUSTOMER,
        account_id=ACCOUNT,
        severity="high",
        detected_on="2026-03-07",
        summary="Cash deposits clustering under the CTR threshold.",
    )


def profile() -> AccountProfile:
    return AccountProfile(
        account_id=ACCOUNT,
        customer_id=CUSTOMER,
        opened_on=date(2026, 2, 1),
        account_type="business_checking",
        expected_monthly_amount=Decimal("30000"),
        expected_monthly_count=40,
    )


SANCTIONS = ListSnapshot(
    list_kind=ListKind.SANCTIONS,
    version="2026.10.1",
    published_at="2026-10-01T00:00:00Z",
    source_note="test feed",
    entries=[
        ListEntry(
            entry_id="SDN-1", name="Viktor Petrov",
            dob="1962-04-11", identifiers=["PP-XK-4471"],
        )
    ],
)

CUSTOMER_SUBJECT = ScreeningSubject(
    subject_ref=f"customer:{CUSTOMER}",
    name="Daniel Okafor",
    role="customer",
    dob=date(1985, 3, 4),
    identifiers=["PP-NG-2210"],
)
LISTED_SUBJECT = ScreeningSubject(
    subject_ref=f"customer:{CUSTOMER}",
    name="Viktor Petrov",
    role="customer",
    dob=date(1962, 4, 11),
    identifiers=["PP-XK-4471"],
)

STRUCTURING_STREAM = [
    txn("T-S1", date(2026, 2, 10), "4200.00", channel="ach"),
    txn("T-1", date(2026, 3, 2), "9500", cash=True, channel="branch"),
    txn("T-2", date(2026, 3, 4), "9600", cash=True, channel="branch"),
    txn("T-3", date(2026, 3, 6), "9700", cash=True, channel="branch"),
    txn("T-S2", date(2026, 3, 10), "4200.00", channel="ach"),
]

CADENCE_STREAM = []
_day = date(2026, 1, 5)
for _i in range(9):
    CADENCE_STREAM.append(
        txn(f"T-C{_i}", _day, "9500", cash=True, channel="branch")
    )
    _day += timedelta(days=10)


class Stack:
    """One in-memory stack, every R1–R5 service over one store."""

    def __init__(self, tmp_path: Path, alerts: list[Alert]):
        self.store = InMemoryCaseStore()
        self.objects = LocalObjectStore(tmp_path / "objects")
        self.evidence = EvidenceService(self.store, self.objects)
        self.workflow = CaseWorkflow(self.store, screening_store=self.store)
        self.intake = IntakeService(self.store, ListAlertFeed(alerts), self.evidence)
        self.screening = ScreeningService(self.store, self.store, self.evidence)
        self.typologies = TypologyService(self.store, self.store, self.evidence)
        self.investigations = InvestigationService(
            self.store, self.store, self.store, self.store, self.evidence,
            disposition_store=self.store,
        )
        self.dispositions = DispositionService(
            self.store, self.store, self.store, self.store,
            self.evidence, self.workflow,
        )
        self.screening.ingest_snapshot(SANCTIONS, actor="test-feed")
        self.typologies.register_rule_pack(
            RulePack(pack_id="test-pack", version="1.0")
        )

    def open_case(
        self,
        alert_id: str,
        stream: list[Transaction],
        *,
        subject: ScreeningSubject = CUSTOMER_SUBJECT,
    ) -> str:
        case_id = self.intake.open_case(alert_id).case_id
        self.workflow.transition(case_id, CaseStatus.ASSEMBLING, actor="test")
        self.screening.screen_case(
            case_id,
            {ListKind.SANCTIONS: "2026.10.1"},
            actor="test",
            subjects=[subject],
        )
        feed = ListTransactionFeed([profile()], {ACCOUNT: stream})
        self.typologies.ingest_from_source(case_id, feed, actor="test-feed")
        self.typologies.run_typologies(
            case_id, "test-pack", "1.0", actor="test-runner"
        )
        self.workflow.transition(case_id, CaseStatus.INVESTIGATING, actor="test")
        return case_id

    def investigated_case(self, alert_id: str, stream, **kwargs) -> tuple[str, object]:
        """A case with a current investigation record, at the gate."""
        case_id = self.open_case(alert_id, stream, **kwargs)
        record = self.investigations.run_investigation(case_id, actor="test")
        self.workflow.transition(
            case_id, CaseStatus.AWAITING_ANALYST, actor="test"
        )
        return case_id, record

    def disposition(self, case_id: str, record, **overrides):
        kwargs = dict(
            analyst_id=ANALYST,
            analyst_role="analyst",
            outcome=DispositionOutcome.CLOSE_NO_ACTION,
            rationale_codes=["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"],
            record_id=record.record_id,
            record_version=record.version,
        )
        kwargs.update(overrides)
        return self.dispositions.record_disposition(case_id, **kwargs)


@pytest.fixture()
def stack(tmp_path: Path) -> Stack:
    return Stack(tmp_path, [alert()])


# ---------------------------------------------------------------------------
# The closing paths
# ---------------------------------------------------------------------------


def test_benign_close_takes_effect_immediately(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", CADENCE_STREAM)
    assert record.hypothesis.label == "no_adverse_pattern"
    decided = stack.disposition(case_id, record)
    assert decided.requires_confirmation is False
    assert decided.evidence_seq is not None
    case = stack.store.get_case(case_id)
    assert case.status is CaseStatus.CLOSED
    assert case.disposition is not None
    assert case.disposition.analyst == ANALYST
    assert case.disposition.decision == "close"
    assert stack.dispositions.status_of(decided) == "effective"


def test_adverse_close_parks_until_a_second_person_confirms(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", STRUCTURING_STREAM)
    assert record.hypothesis.label == "structuring"
    decided = stack.disposition(
        case_id, record, rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"]
    )
    assert decided.requires_confirmation is True

    case = stack.store.get_case(case_id)
    assert case.status is CaseStatus.PENDING_CONFIRMATION
    assert case.disposition is None, "the closure has not taken effect"
    assert stack.dispositions.status_of(decided) == "pending_confirmation"
    queue = stack.dispositions.confirmation_queue()
    assert [entry["case"]["case_id"] for entry in queue] == [case_id]
    assert queue[0]["disposition"]["disposition_id"] == decided.disposition_id

    confirmation = stack.dispositions.confirm_disposition(
        case_id,
        confirmer_id=L2,
        confirmer_role="l2_reviewer",
        outcome=ConfirmationOutcome.CONFIRMED,
    )
    assert confirmation.disposition_id == decided.disposition_id
    case = stack.store.get_case(case_id)
    assert case.status is CaseStatus.CLOSED
    # The closure on the case record is the dispositioning analyst's —
    # the confirmer confirmed it; they did not replace it.
    assert case.disposition.analyst == ANALYST
    assert case.disposition.decision == "close"
    assert stack.dispositions.status_of(decided) == "confirmed"
    assert stack.dispositions.confirmation_queue() == []


def test_self_confirmation_is_refused(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", STRUCTURING_STREAM)
    stack.disposition(case_id, record,
                      rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"])
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.dispositions.confirm_disposition(
            case_id,
            confirmer_id=ANALYST,
            confirmer_role="l2_reviewer",
            outcome=ConfirmationOutcome.CONFIRMED,
        )
    assert excinfo.value.reason == "self_confirmation"
    assert stack.store.get_case(case_id).status is CaseStatus.PENDING_CONFIRMATION


def test_confirmation_requires_the_l2_role(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", STRUCTURING_STREAM)
    stack.disposition(case_id, record,
                      rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"])
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.dispositions.confirm_disposition(
            case_id,
            confirmer_id=L2,
            confirmer_role="senior_analyst",
            outcome=ConfirmationOutcome.CONFIRMED,
        )
    assert excinfo.value.reason == "confirmer_role_not_l2"


def test_confirmation_without_a_pending_disposition_is_refused(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", CADENCE_STREAM)
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.dispositions.confirm_disposition(
            case_id,
            confirmer_id=L2,
            confirmer_role="l2_reviewer",
            outcome=ConfirmationOutcome.CONFIRMED,
        )
    assert excinfo.value.reason == "no_pending_confirmation"


def test_decline_sends_the_case_back_and_history_is_kept(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", STRUCTURING_STREAM)
    first = stack.disposition(
        case_id, record, rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"]
    )
    first_dump = first.model_dump()
    stack.dispositions.confirm_disposition(
        case_id,
        confirmer_id=L2,
        confirmer_role="l2_reviewer",
        outcome=ConfirmationOutcome.DECLINED,
        note="Source of funds is still unexplained.",
    )
    assert stack.store.get_case(case_id).status is CaseStatus.INVESTIGATING
    assert stack.dispositions.status_of(first) == "declined"

    # Re-investigation over unchanged inputs returns the same record;
    # a fresh disposition supersedes the declined one — and the
    # declined record itself is byte-for-byte what it was.
    same = stack.investigations.run_investigation(case_id, actor="test")
    assert same.record_id == record.record_id
    stack.workflow.transition(case_id, CaseStatus.AWAITING_ANALYST, actor="test")
    second = stack.disposition(
        case_id,
        record,
        outcome=DispositionOutcome.ESCALATE_L2,
        rationale_codes=["CONFLICTING_EVIDENCE"],
    )
    assert stack.store.get_case(case_id).status is CaseStatus.ESCALATED
    history = stack.dispositions.history(case_id)
    assert [d.disposition_id for d in history] == [
        first.disposition_id,
        second.disposition_id,
    ]
    assert history[0].model_dump() == first_dump, "history is never edited"
    assert stack.dispositions.status_of(history[0]) == "superseded"
    assert stack.dispositions.status_of(second) == "effective"


# ---------------------------------------------------------------------------
# The gates
# ---------------------------------------------------------------------------


def test_anonymous_and_system_actors_are_refused(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", CADENCE_STREAM)
    for bad_actor in ("", "   ", "system", "investigation-service", "agent"):
        with pytest.raises(DispositionRefusedError) as excinfo:
            stack.disposition(case_id, record, analyst_id=bad_actor)
        assert excinfo.value.reason == "anonymous_or_system_actor"
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.disposition(case_id, record, analyst_role="manager")
    assert excinfo.value.reason == "unknown_role"
    events = [e.event for e in stack.store.list_audit(case_id)]
    assert events.count("disposition_refused") >= 6
    assert stack.dispositions.history(case_id) == []


def test_free_text_only_rationale_is_refused(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", CADENCE_STREAM)
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.disposition(
            case_id, record, rationale_codes=[], note="Looks fine to me."
        )
    assert excinfo.value.reason == "rationale_codes_required"
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.disposition(case_id, record, rationale_codes=["LOOKS_FINE"])
    assert excinfo.value.reason == "unknown_rationale_code"
    # A real code, but from another outcome's set.
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.disposition(case_id, record, rationale_codes=["STRUCTURING_SUSPECTED"])
    assert excinfo.value.reason == "unknown_rationale_code"


def test_disposition_without_an_investigation_record_is_refused(stack: Stack):
    case_id = stack.intake.open_case("ALRT-D-1").case_id
    for target in (
        CaseStatus.ASSEMBLING,
        CaseStatus.INVESTIGATING,
        CaseStatus.AWAITING_ANALYST,
    ):
        stack.workflow.transition(case_id, target, actor="test")
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.dispositions.record_disposition(
            case_id,
            analyst_id=ANALYST,
            analyst_role="analyst",
            outcome=DispositionOutcome.CLOSE_NO_ACTION,
            rationale_codes=["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"],
            record_id="INV-none",
            record_version=1,
        )
    assert excinfo.value.reason == "no_investigation_record"


def test_disposition_before_the_gate_is_refused(stack: Stack):
    case_id = stack.open_case("ALRT-D-1", CADENCE_STREAM)
    record = stack.investigations.run_investigation(case_id, actor="test")
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.disposition(case_id, record)
    assert excinfo.value.reason == "case_not_awaiting_analyst"


def test_sanctions_hit_blocks_both_closing_outcomes(stack: Stack):
    case_id, record = stack.investigated_case(
        "ALRT-D-1", CADENCE_STREAM, subject=LISTED_SUBJECT
    )
    assert record.hypothesis.label == "sanctions_match"
    for outcome, extra in (
        (DispositionOutcome.CLOSE_NO_ACTION, {}),
        (
            DispositionOutcome.CLOSE_MONITOR,
            {"review_period_days": 30},
        ),
    ):
        with pytest.raises(DispositionRefusedError) as excinfo:
            stack.disposition(
                case_id,
                record,
                outcome=outcome,
                rationale_codes=(
                    ["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"]
                    if outcome is DispositionOutcome.CLOSE_NO_ACTION
                    else ["EMERGING_PATTERN_WATCH"]
                ),
                **extra,
            )
        assert excinfo.value.reason == "unresolved_sanctions_hit"
    # The lawful exit works, and the case joins the SAR queue.
    decided = stack.disposition(
        case_id,
        record,
        outcome=DispositionOutcome.ESCALATE_SAR,
        rationale_codes=["SANCTIONS_MATCH_SUSPECTED"],
    )
    assert stack.store.get_case(case_id).status is CaseStatus.SAR_PENDING
    queue = stack.dispositions.escalation_queue()
    assert [entry["case"]["case_id"] for entry in queue] == [case_id]
    assert queue[0]["disposition"]["disposition_id"] == decided.disposition_id


# ---------------------------------------------------------------------------
# The other outcomes
# ---------------------------------------------------------------------------


def test_close_monitor_records_the_review_period(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", CADENCE_STREAM)
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.disposition(
            case_id,
            record,
            outcome=DispositionOutcome.CLOSE_MONITOR,
            rationale_codes=["EMERGING_PATTERN_WATCH"],
        )
    assert excinfo.value.reason == "missing_review_period"
    decided = stack.disposition(
        case_id,
        record,
        outcome=DispositionOutcome.CLOSE_MONITOR,
        rationale_codes=["EMERGING_PATTERN_WATCH"],
        review_period_days=30,
    )
    assert decided.review_period_days == 30
    assert decided.review_due_on == decided.decided_at.date() + timedelta(days=30)
    case = stack.store.get_case(case_id)
    assert case.status is CaseStatus.MONITORING
    # Monitoring is not a closing state: it re-opens, it never closes.
    with pytest.raises(IllegalTransitionError):
        stack.workflow.transition(
            case_id, CaseStatus.CLOSED, actor="analyst:x"
        )
    back = stack.workflow.transition(
        case_id, CaseStatus.INVESTIGATING, actor="monitoring-review"
    )
    assert back.status is CaseStatus.INVESTIGATING


def test_request_more_evidence_names_what_is_missing(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", STRUCTURING_STREAM)
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.disposition(
            case_id,
            record,
            outcome=DispositionOutcome.REQUEST_MORE_EVIDENCE,
            rationale_codes=["SOURCE_OF_FUNDS_MISSING"],
        )
    assert excinfo.value.reason == "missing_evidence_required"
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.disposition(
            case_id,
            record,
            outcome=DispositionOutcome.REQUEST_MORE_EVIDENCE,
            rationale_codes=["SOURCE_OF_FUNDS_MISSING"],
            missing_evidence=["a_hunch"],
        )
    assert excinfo.value.reason == "unknown_evidence_type"
    decided = stack.disposition(
        case_id,
        record,
        outcome=DispositionOutcome.REQUEST_MORE_EVIDENCE,
        rationale_codes=["SOURCE_OF_FUNDS_MISSING"],
        missing_evidence=["source_of_funds_documentation"],
    )
    assert decided.missing_evidence == ["source_of_funds_documentation"]
    assert stack.store.get_case(case_id).status is CaseStatus.INVESTIGATING


def test_escalate_l2_carries_the_legacy_escalation_record(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", STRUCTURING_STREAM)
    stack.disposition(
        case_id,
        record,
        outcome=DispositionOutcome.ESCALATE_L2,
        rationale_codes=["CONFLICTING_EVIDENCE"],
    )
    case = stack.store.get_case(case_id)
    assert case.status is CaseStatus.ESCALATED
    assert case.disposition is not None
    assert case.disposition.decision == "escalate"
    queue = stack.dispositions.escalation_queue()
    assert [entry["case"]["case_id"] for entry in queue] == [case_id]


# ---------------------------------------------------------------------------
# Staleness: the record moves after the decision
# ---------------------------------------------------------------------------


def test_superseded_record_flags_the_disposition_stale(stack: Stack):
    case_id, record_v1 = stack.investigated_case("ALRT-D-1", STRUCTURING_STREAM)
    stack.disposition(
        case_id,
        record_v1,
        outcome=DispositionOutcome.CLOSE_MONITOR,
        rationale_codes=["PATTERN_EXPLAINED_MONITOR_ACTIVITY"],
        review_period_days=30,
    )
    assert stack.store.get_case(case_id).status is CaseStatus.MONITORING

    # New evidence arrives; the monitoring review re-opens the case
    # and the investigation produces version 2.
    stack.workflow.transition(case_id, CaseStatus.INVESTIGATING, actor="test")
    extra = [
        txn(f"T-R{i}", date(2026, 3, 12) + timedelta(days=i), "10000")
        for i in range(8)
    ]
    stack.typologies.ingest_transactions(
        case_id, extra, source_ref="core-banking:ACCT-T-1:delta", actor="test"
    )
    stack.typologies.run_typologies(case_id, "test-pack", "1.0", actor="test")
    record_v2 = stack.investigations.run_investigation(case_id, actor="test")
    assert record_v2.version == 2

    case = stack.store.get_case(case_id)
    assert FLAG_DISPOSITION_STALE in case.flags
    events = [e.event for e in stack.store.list_audit(case_id)]
    assert "disposition_stale_flagged" in events

    # A disposition citing the superseded version is refused; one
    # citing the current record lands and clears the flag.
    stack.workflow.transition(case_id, CaseStatus.AWAITING_ANALYST, actor="test")
    with pytest.raises(DispositionRefusedError) as excinfo:
        stack.disposition(case_id, record_v1)
    assert excinfo.value.reason == "record_citation_not_current"
    stack.disposition(case_id, record_v2)
    case = stack.store.get_case(case_id)
    assert FLAG_DISPOSITION_STALE not in case.flags


# ---------------------------------------------------------------------------
# Chain-of-custody + the new states' edges
# ---------------------------------------------------------------------------


def test_dispositions_sit_on_the_evidence_chain(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", STRUCTURING_STREAM)
    stack.disposition(case_id, record,
                      rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"])
    stack.dispositions.confirm_disposition(
        case_id,
        confirmer_id=L2,
        confirmer_role="l2_reviewer",
        outcome=ConfirmationOutcome.CONFIRMED,
    )
    kinds = [i.kind for i in stack.store.list_evidence(case_id)]
    assert "disposition" in kinds
    assert "disposition_confirmation" in kinds
    assert stack.evidence.verify_chain(case_id)
    events = [e.event for e in stack.store.list_audit(case_id)]
    assert "disposition_recorded" in events
    assert "disposition_confirmed" in events


def test_new_states_refuse_unlawful_exits(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-D-1", STRUCTURING_STREAM)
    stack.disposition(case_id, record,
                      rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"])
    assert stack.store.get_case(case_id).status is CaseStatus.PENDING_CONFIRMATION
    for target in (CaseStatus.FILED_SAR, CaseStatus.SAR_PENDING,
                   CaseStatus.MONITORING, CaseStatus.OPENED):
        with pytest.raises(IllegalTransitionError):
            stack.workflow.transition(case_id, target, actor="analyst:x")


# ---------------------------------------------------------------------------
# SQL store round-trip (migration 0005)
# ---------------------------------------------------------------------------


def test_sql_store_round_trips_dispositions(tmp_path: Path):
    store = SqlCaseStore.sqlite(
        tmp_path / "aml.db", REPO_ROOT / "migrations"
    )
    decided = stack_record()
    store.add_disposition(decided)
    confirmation = DispositionConfirmation(
        disposition_id=decided.disposition_id,
        case_id=decided.case_id,
        confirmer_id=L2,
        confirmer_role="l2_reviewer",
        outcome=ConfirmationOutcome.CONFIRMED,
    )
    store.add_confirmation(confirmation)
    assert store.list_dispositions(decided.case_id) == [decided]
    assert store.get_disposition(decided.disposition_id) == decided
    assert store.list_confirmations(decided.case_id) == [confirmation]
    assert store.get_confirmation_for(decided.disposition_id) == confirmation


def stack_record() -> DispositionRecord:
    return DispositionRecord(
        case_id="case-sql-1",
        analyst_id=ANALYST,
        analyst_role="analyst",
        outcome=DispositionOutcome.CLOSE_NO_ACTION,
        rationale_codes=["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"],
        rationale_vocabulary_version="2026.10.1",
        record_id="INV-case-sql-1-V1",
        record_version=1,
    )


def test_disposition_service_works_over_the_sql_store(tmp_path: Path):
    """The full gate, end to end, over the production-shaped store."""
    store = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects)
    workflow = CaseWorkflow(store, screening_store=store)
    intake = IntakeService(store, ListAlertFeed([alert()]), evidence)
    screening = ScreeningService(store, store, evidence)
    typologies = TypologyService(store, store, evidence)
    investigations = InvestigationService(
        store, store, store, store, evidence, disposition_store=store
    )
    dispositions = DispositionService(
        store, store, store, store, evidence, workflow
    )
    screening.ingest_snapshot(SANCTIONS, actor="test-feed")
    typologies.register_rule_pack(RulePack(pack_id="test-pack", version="1.0"))
    case_id = intake.open_case("ALRT-D-1").case_id
    workflow.transition(case_id, CaseStatus.ASSEMBLING, actor="test")
    screening.screen_case(
        case_id, {ListKind.SANCTIONS: "2026.10.1"}, actor="test",
        subjects=[CUSTOMER_SUBJECT],
    )
    feed = ListTransactionFeed([profile()], {ACCOUNT: STRUCTURING_STREAM})
    typologies.ingest_from_source(case_id, feed, actor="test-feed")
    typologies.run_typologies(case_id, "test-pack", "1.0", actor="test")
    workflow.transition(case_id, CaseStatus.INVESTIGATING, actor="test")
    record = investigations.run_investigation(case_id, actor="test")
    workflow.transition(case_id, CaseStatus.AWAITING_ANALYST, actor="test")
    decided = dispositions.record_disposition(
        case_id,
        analyst_id=ANALYST,
        analyst_role="analyst",
        outcome=DispositionOutcome.CLOSE_NO_ACTION,
        rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"],
        record_id=record.record_id,
        record_version=record.version,
    )
    assert store.get_case(case_id).status is CaseStatus.PENDING_CONFIRMATION
    dispositions.confirm_disposition(
        case_id,
        confirmer_id=L2,
        confirmer_role="l2_reviewer",
        outcome=ConfirmationOutcome.CONFIRMED,
    )
    assert store.get_case(case_id).status is CaseStatus.CLOSED
    assert dispositions.status_of(decided) == "confirmed"
    assert evidence.verify_chain(case_id)
