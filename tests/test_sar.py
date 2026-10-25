"""R6 SAR narrative drafting + the citation verifier: Law 2.

Drafting is lawful only in sar_pending, only over the current
investigation record, only on the standing of the escalate_sar
disposition that routed the case — and a draft may stand as
VERIFIED only when the citation verifier, in code, resolves every
factual statement to its cited evidence. Nothing here is approved,
and nothing is ever filed: the round ends at a verified draft.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from aml_investigations.dispositions import DispositionService
from aml_investigations.errors import (
    ModelProfileNotConfiguredError,
    SarNarrativeRefusedError,
)
from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.investigation import InvestigationService
from aml_investigations.models import (
    AccountProfile,
    Alert,
    CaseStatus,
    DispositionOutcome,
    ListEntry,
    ListKind,
    ListSnapshot,
    NarrativeVerification,
    RulePack,
    SarNarrative,
    ScreeningSubject,
    Transaction,
)
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.sar import SarNarrativeService
from aml_investigations.screening import ScreeningService
from aml_investigations.stores import InMemoryCaseStore, SqlCaseStore
from aml_investigations.transactions import ListTransactionFeed
from aml_investigations.typologies import TypologyService
from aml_investigations.workflow import CaseWorkflow

REPO_ROOT = Path(__file__).resolve().parents[1]

ACCOUNT = "ACCT-T-1"
CUSTOMER = "CUST-T-1"
ANALYST = "a.okafor"


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


def identity_alert(alert_id: str = "ALRT-S-1") -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="TM-STRUCTURING-01",
        customer_id=CUSTOMER,
        account_id=ACCOUNT,
        severity="high",
        detected_on="2026-03-07",
        summary="Cash deposits clustering under the CTR threshold.",
        raw={
            "customer_name": "Daniel Okafor",
            "customer_dob": "1985-03-04",
            "customer_identifiers": ["PP-NG-2210"],
            "counterparties": [],
        },
    )


def anonymous_alert(alert_id: str = "ALRT-S-2") -> Alert:
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

ROUND_STREAM = [
    txn(f"T-R{i}", date(2026, 3, 12) + timedelta(days=i), "10000",
        channel="wire")
    for i in range(8)
]


class Stack:
    """One in-memory stack, every R1–R6 service over one store."""

    def __init__(self, tmp_path: Path, alerts: list[Alert]):
        self.store = InMemoryCaseStore()
        self.objects = LocalObjectStore(tmp_path / "objects")
        self.evidence = EvidenceService(self.store, self.objects)
        self.workflow = CaseWorkflow(self.store, screening_store=self.store)
        self.intake = IntakeService(
            self.store, ListAlertFeed(alerts), self.evidence
        )
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
        self.sar = SarNarrativeService(
            self.store, self.store, self.store, self.store, self.evidence
        )
        self.screening.ingest_snapshot(SANCTIONS, actor="test-feed")
        self.typologies.register_rule_pack(
            RulePack(pack_id="test-pack", version="1.0")
        )

    def open_case(self, alert_id: str, stream: list[Transaction]) -> str:
        case_id = self.intake.open_case(alert_id).case_id
        self.workflow.transition(case_id, CaseStatus.ASSEMBLING, actor="test")
        self.screening.screen_case(
            case_id,
            {ListKind.SANCTIONS: "2026.10.1"},
            actor="test",
            subjects=[CUSTOMER_SUBJECT],
        )
        feed = ListTransactionFeed([profile()], {ACCOUNT: stream})
        self.typologies.ingest_from_source(case_id, feed, actor="test-feed")
        self.typologies.run_typologies(
            case_id, "test-pack", "1.0", actor="test-runner"
        )
        self.workflow.transition(case_id, CaseStatus.INVESTIGATING, actor="test")
        return case_id

    def investigated_case(self, alert_id: str, stream):
        case_id = self.open_case(alert_id, stream)
        record = self.investigations.run_investigation(case_id, actor="test")
        self.workflow.transition(
            case_id, CaseStatus.AWAITING_ANALYST, actor="test"
        )
        return case_id, record

    def sar_pending_case(self, alert_id: str = "ALRT-S-1", stream=None):
        """A case routed to SAR drafting by the analyst gate."""
        case_id, record = self.investigated_case(
            alert_id, STRUCTURING_STREAM if stream is None else stream
        )
        decided = self.dispositions.record_disposition(
            case_id,
            analyst_id=ANALYST,
            analyst_role="analyst",
            outcome=DispositionOutcome.ESCALATE_SAR,
            rationale_codes=["STRUCTURING_SUSPECTED"],
            record_id=record.record_id,
            record_version=record.version,
        )
        assert self.store.get_case(case_id).status is CaseStatus.SAR_PENDING
        return case_id, record, decided


@pytest.fixture()
def stack(tmp_path: Path) -> Stack:
    return Stack(tmp_path, [identity_alert(), anonymous_alert()])


# ---------------------------------------------------------------------------
# The positive path
# ---------------------------------------------------------------------------


def test_seed_flow_drafts_and_verifies(stack: Stack):
    case_id, record, decided = stack.sar_pending_case()
    narrative, verification = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    assert narrative.version == 1
    assert narrative.record_id == record.record_id
    assert narrative.record_version == record.version
    assert narrative.disposition_id == decided.disposition_id
    assert narrative.model_profile == "offline"
    assert narrative.evidence_seq is not None
    assert [s.key for s in narrative.sections] == [
        "subject_identification",
        "activity_summary",
        "chronology",
        "amounts_and_instruments",
        "branch_office_facts",
        "what_remains_unknown",
    ]
    assert verification.all_verified is True
    assert all(v.verified for v in verification.statement_verdicts)
    assert verification.narrative_problems == []
    assert stack.sar.status_of(narrative) == "verified"
    # The draft and its verification sit on the case's hash chain.
    kinds = [i.kind for i in stack.store.list_evidence(case_id)]
    assert "sar_narrative" in kinds
    assert "sar_narrative_verification" in kinds
    assert stack.evidence.verify_chain(case_id)
    # The amounts section states the finding's total, exactly.
    amounts = next(
        s for s in narrative.sections if s.key == "amounts_and_instruments"
    )
    assert any(
        st.figures.get("total_amount") == "28800"
        for st in amounts.statements
    )
    # The unknowns section carries the record's open question.
    unknown = next(
        s for s in narrative.sections if s.key == "what_remains_unknown"
    )
    assert any(
        st.values.get("evidence_needed") == "source_of_funds_documentation"
        for st in unknown.statements
    )
    # Nothing is approved, nothing is filed: the case still stands
    # in sar_pending and the narrative's standing is only "verified".
    assert stack.store.get_case(case_id).status is CaseStatus.SAR_PENDING


def test_redraft_without_new_evidence_returns_the_standing_draft(
    stack: Stack,
):
    case_id, _, _ = stack.sar_pending_case()
    first, _ = stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    second, _ = stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    assert second.narrative_id == first.narrative_id
    assert second.version == 1
    assert len(stack.sar.narrative_history(case_id)) == 1


def test_verify_narrative_reruns_and_records_each_run(stack: Stack):
    case_id, _, _ = stack.sar_pending_case()
    narrative, first = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    second = stack.sar.verify_narrative(case_id)
    assert second.verification_id != first.verification_id
    assert second.all_verified is True
    runs = stack.store.list_verifications(case_id)
    assert len(runs) == 2
    assert stack.sar.latest_verification(narrative.narrative_id) == second


# ---------------------------------------------------------------------------
# The drafting gates
# ---------------------------------------------------------------------------


def test_draft_refused_when_case_is_not_sar_pending(stack: Stack):
    case_id, _record = stack.investigated_case("ALRT-S-1", STRUCTURING_STREAM)
    with pytest.raises(SarNarrativeRefusedError) as excinfo:
        stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    assert excinfo.value.reason == "case_not_sar_pending"
    assert stack.sar.narrative_history(case_id) == []


def test_draft_refused_without_a_gate_disposition(stack: Stack):
    """The case reaches sar_pending by a raw workflow transition —
    no analyst ever decided to file. Drafting refuses to proceed
    on the drafting service's own initiative."""
    case_id, _record = stack.investigated_case("ALRT-S-1", STRUCTURING_STREAM)
    stack.workflow.transition(case_id, CaseStatus.SAR_PENDING, actor="test")
    with pytest.raises(SarNarrativeRefusedError) as excinfo:
        stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    assert excinfo.value.reason == "sar_disposition_missing"


def test_draft_refused_when_disposition_cites_a_superseded_record(
    stack: Stack,
):
    case_id, _record, _decided = stack.sar_pending_case()
    # New evidence, a new record version — the routing disposition
    # now stands on a superseded basis.
    stack.workflow.transition(case_id, CaseStatus.INVESTIGATING, actor="test")
    stack.typologies.ingest_transactions(
        case_id, ROUND_STREAM,
        source_ref="core-banking:delta", actor="test-feed",
    )
    stack.typologies.run_typologies(case_id, "test-pack", "1.0", actor="test")
    record_v2 = stack.investigations.run_investigation(case_id, actor="test")
    assert record_v2.version == 2
    stack.workflow.transition(
        case_id, CaseStatus.AWAITING_ANALYST, actor="test"
    )
    stack.workflow.transition(case_id, CaseStatus.SAR_PENDING, actor="test")
    with pytest.raises(SarNarrativeRefusedError) as excinfo:
        stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    assert excinfo.value.reason == "sar_disposition_not_current"


def test_draft_refused_without_subject_identification(stack: Stack):
    case_id, record = stack.investigated_case("ALRT-S-2", STRUCTURING_STREAM)
    stack.dispositions.record_disposition(
        case_id,
        analyst_id=ANALYST,
        analyst_role="analyst",
        outcome=DispositionOutcome.ESCALATE_SAR,
        rationale_codes=["STRUCTURING_SUSPECTED"],
        record_id=record.record_id,
        record_version=record.version,
    )
    with pytest.raises(SarNarrativeRefusedError) as excinfo:
        stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    assert excinfo.value.reason == "subject_identification_missing"


def test_draft_refused_when_flagged_amounts_cannot_be_stated(
    stack: Stack,
):
    """The cadence control fires no typology: there is no finding
    total for the narrative to state, and the drafting service may
    not total the transactions itself (Law 4)."""
    case_id, record = stack.investigated_case("ALRT-S-1", CADENCE_STREAM)
    stack.dispositions.record_disposition(
        case_id,
        analyst_id=ANALYST,
        analyst_role="analyst",
        outcome=DispositionOutcome.ESCALATE_SAR,
        rationale_codes=["ACTIVITY_UNEXPLAINED"],
        record_id=record.record_id,
        record_version=record.version,
    )
    with pytest.raises(SarNarrativeRefusedError) as excinfo:
        stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    assert excinfo.value.reason == "flagged_amounts_not_statable"


def test_live_profile_refuses_loudly_and_stores_nothing(stack: Stack):
    case_id, _, _ = stack.sar_pending_case()
    with pytest.raises(ModelProfileNotConfiguredError):
        stack.sar.draft_narrative(
            case_id, actor="sar-drafting-service", profile="hosted-frontier"
        )
    assert stack.sar.narrative_history(case_id) == []


# ---------------------------------------------------------------------------
# The verifier: tampered drafts cannot verify
# ---------------------------------------------------------------------------


def _amounts_statement(narrative: SarNarrative):
    section = next(
        s for s in narrative.sections if s.key == "amounts_and_instruments"
    )
    return next(
        st for st in section.statements if "total_amount" in st.figures
    )


def _with_statement(narrative: SarNarrative, statement_id: str, **updates):
    """A deep copy of the narrative with one statement replaced."""
    sections = []
    for section in narrative.sections:
        statements = [
            st.model_copy(update=updates)
            if st.statement_id == statement_id
            else st
            for st in section.statements
        ]
        sections.append(section.model_copy(update={"statements": statements}))
    return narrative.model_copy(update={"sections": sections})


def test_verifier_refuses_a_tampered_figure(stack: Stack):
    case_id, _, _ = stack.sar_pending_case()
    narrative, _ = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    target = _amounts_statement(narrative)
    tampered = _with_statement(
        narrative,
        target.statement_id,
        text=target.text.replace("28800", "28801"),
        figures={"total_amount": "28801"},
    )
    verdict = stack.sar.check_narrative(tampered)
    assert verdict.all_verified is False
    failed = [v for v in verdict.statement_verdicts if not v.verified]
    assert [v.statement_id for v in failed] == [target.statement_id]
    assert any("does not appear in the cited records" in p for p in failed[0].problems)
    # The stored draft is untouched and still stands verified.
    stored = stack.sar.current_narrative(case_id)
    assert stack.sar.status_of(stored) == "verified"


def test_verifier_refuses_a_statement_with_dropped_citations(
    stack: Stack,
):
    case_id, _, _ = stack.sar_pending_case()
    narrative, _ = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    target = _amounts_statement(narrative)
    tampered = _with_statement(narrative, target.statement_id, citations=[])
    verdict = stack.sar.check_narrative(tampered)
    assert verdict.all_verified is False
    failed = {v.statement_id: v for v in verdict.statement_verdicts}
    assert failed[target.statement_id].verified is False
    assert any(
        "no citations" in p for p in failed[target.statement_id].problems
    )


def test_verifier_refuses_an_invented_subject(stack: Stack):
    case_id, _, _ = stack.sar_pending_case()
    narrative, _ = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    subject_section = narrative.sections[0]
    target = subject_section.statements[0]
    tampered = _with_statement(
        narrative,
        target.statement_id,
        text="The subject of this report is Someone Else (customer CUST-T-1).",
        values={"subject_name": "Someone Else", "customer_id": CUSTOMER},
    )
    verdict = stack.sar.check_narrative(tampered)
    assert verdict.all_verified is False
    failed = {v.statement_id: v for v in verdict.statement_verdicts}
    assert failed[target.statement_id].verified is False


def test_verifier_refuses_a_narrative_that_hides_open_questions(
    stack: Stack,
):
    case_id, _, _ = stack.sar_pending_case()
    narrative, _ = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    hidden = narrative.model_copy(
        update={
            "sections": [
                s for s in narrative.sections
                if s.key != "what_remains_unknown"
            ]
        }
    )
    verdict = stack.sar.check_narrative(hidden)
    assert verdict.all_verified is False
    assert any(
        "source_of_funds_documentation" in p
        for p in verdict.narrative_problems
    )


def test_verifier_refuses_a_binding_to_an_unknown_finding(stack: Stack):
    case_id, _, _ = stack.sar_pending_case()
    narrative, _ = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    target = _amounts_statement(narrative)
    tampered = _with_statement(
        narrative, target.statement_id, finding_ids=["invf-does-not-exist"]
    )
    verdict = stack.sar.check_narrative(tampered)
    assert verdict.all_verified is False
    failed = {v.statement_id: v for v in verdict.statement_verdicts}
    assert failed[target.statement_id].verified is False
    assert any(
        "not in the cited investigation record" in p
        for p in failed[target.statement_id].problems
    )


# ---------------------------------------------------------------------------
# Staleness and supersession
# ---------------------------------------------------------------------------


def test_verified_narrative_goes_stale_then_is_superseded(stack: Stack):
    case_id, _, _ = stack.sar_pending_case()
    first, _ = stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    assert stack.sar.status_of(first) == "verified"

    # New evidence supersedes the record the narrative cites: the
    # verified draft drops back to stale — it cannot proceed to
    # approval on a moved basis.
    stack.workflow.transition(case_id, CaseStatus.INVESTIGATING, actor="test")
    stack.typologies.ingest_transactions(
        case_id, ROUND_STREAM,
        source_ref="core-banking:delta", actor="test-feed",
    )
    stack.typologies.run_typologies(case_id, "test-pack", "1.0", actor="test")
    record_v2 = stack.investigations.run_investigation(case_id, actor="test")
    assert record_v2.version == 2
    assert stack.sar.status_of(first) == "stale"

    # A fresh disposition on the current record routes the case
    # again; the re-draft is version 2, superseding the first.
    stack.workflow.transition(
        case_id, CaseStatus.AWAITING_ANALYST, actor="test"
    )
    stack.dispositions.record_disposition(
        case_id,
        analyst_id=ANALYST,
        analyst_role="analyst",
        outcome=DispositionOutcome.ESCALATE_SAR,
        rationale_codes=["STRUCTURING_SUSPECTED"],
        record_id=record_v2.record_id,
        record_version=record_v2.version,
    )
    second, verification = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    assert second.version == 2
    assert second.supersedes_narrative_id == first.narrative_id
    assert verification.all_verified is True
    assert stack.sar.status_of(second) == "verified"
    assert stack.sar.status_of(first) == "superseded"
    assert len(stack.sar.narrative_history(case_id)) == 2
    assert stack.evidence.verify_chain(case_id)


# ---------------------------------------------------------------------------
# SQL store round-trip (migration 0006)
# ---------------------------------------------------------------------------


def test_sql_store_round_trips_narratives_and_verifications(
    tmp_path: Path,
):
    store = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    narrative = SarNarrative(
        case_id="case-sql-1",
        version=1,
        record_id="inv-sql-1",
        record_version=1,
        disposition_id="disp-sql-1",
        drafted_by="sar-drafting-service",
    )
    verification = NarrativeVerification(
        narrative_id=narrative.narrative_id,
        case_id="case-sql-1",
        all_verified=True,
    )
    store.add_narrative(narrative)
    store.add_verification(verification)
    assert store.list_narratives("case-sql-1") == [narrative]
    assert store.get_narrative(narrative.narrative_id) == narrative
    assert store.list_verifications("case-sql-1") == [verification]
    assert store.get_verification_for(narrative.narrative_id) == verification


def test_sar_service_works_over_the_sql_store(tmp_path: Path):
    """The full drafting path, end to end, over the
    production-shaped store (migration 0006 applied by the runner)."""
    store = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects)
    workflow = CaseWorkflow(store, screening_store=store)
    intake = IntakeService(store, ListAlertFeed([identity_alert()]), evidence)
    screening = ScreeningService(store, store, evidence)
    typologies = TypologyService(store, store, evidence)
    investigations = InvestigationService(
        store, store, store, store, evidence, disposition_store=store
    )
    dispositions = DispositionService(
        store, store, store, store, evidence, workflow
    )
    sar = SarNarrativeService(store, store, store, store, evidence)
    screening.ingest_snapshot(SANCTIONS, actor="test-feed")
    typologies.register_rule_pack(RulePack(pack_id="test-pack", version="1.0"))
    case_id = intake.open_case("ALRT-S-1").case_id
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
    dispositions.record_disposition(
        case_id,
        analyst_id=ANALYST,
        analyst_role="analyst",
        outcome=DispositionOutcome.ESCALATE_SAR,
        rationale_codes=["STRUCTURING_SUSPECTED"],
        record_id=record.record_id,
        record_version=record.version,
    )
    narrative, verification = sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    assert verification.all_verified is True
    assert sar.status_of(narrative) == "verified"
    assert store.get_narrative(narrative.narrative_id) == narrative
    assert evidence.verify_chain(case_id)
