"""R4 investigation graph: cited findings, hypothesis discipline,
the counter-evidence search, and versioned records.

The record-time gate is the point of the round: a finding whose
citations do not resolve — including a citation to a real evidence
item naming an element that is not inside it — is refused, and a
statement carrying a figure its citations do not ground is refused
twice over (composer first, verifier second).
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from aml_investigations.composer import (
    OfflineComposer,
    StatementDraft,
    get_composer,
)
from aml_investigations.errors import (
    CaseNotFoundError,
    ComposerRefusalError,
    InvestigationRefusedError,
    InvestigationStateError,
    ModelProfileNotConfiguredError,
)
from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.investigation import (
    CitationResolver,
    InvestigationService,
)
from aml_investigations.models import (
    AccountProfile,
    Alert,
    CaseStatus,
    Citation,
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


def alert(alert_id: str = "ALRT-I-1", rule_id: str = "TM-STRUCTURING-01") -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        customer_id=CUSTOMER,
        account_id=ACCOUNT,
        severity="high",
        detected_on="2026-03-07",
        summary="Cash deposits clustering under the CTR threshold.",
    )


def profile(**overrides) -> AccountProfile:
    base = dict(
        account_id=ACCOUNT,
        customer_id=CUSTOMER,
        opened_on=date(2026, 2, 1),
        account_type="business_checking",
        expected_monthly_amount=Decimal("30000"),
        expected_monthly_count=40,
    )
    base.update(overrides)
    return AccountProfile(**base)


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


class Stack:
    """One in-memory stack with every service wired over one store."""

    def __init__(self, tmp_path: Path, alerts: list[Alert]):
        self.store = InMemoryCaseStore()
        self.objects = LocalObjectStore(tmp_path / "objects")
        self.evidence = EvidenceService(self.store, self.objects)
        self.workflow = CaseWorkflow(self.store, screening_store=self.store)
        self.intake = IntakeService(self.store, ListAlertFeed(alerts), self.evidence)
        self.screening = ScreeningService(self.store, self.store, self.evidence)
        self.typologies = TypologyService(self.store, self.store, self.evidence)
        self.investigations = InvestigationService(
            self.store, self.store, self.store, self.store, self.evidence
        )
        self.resolver = CitationResolver(self.store, self.evidence)
        self.screening.ingest_snapshot(SANCTIONS, actor="test-feed")
        self.typologies.register_rule_pack(
            RulePack(pack_id="test-pack", version="1.0")
        )

    def open_case(
        self,
        alert_id: str,
        stream: list[Transaction],
        *,
        prof: AccountProfile | None = None,
        screen: bool = True,
    ) -> str:
        case_id = self.intake.open_case(alert_id).case_id
        self.workflow.transition(case_id, CaseStatus.ASSEMBLING, actor="test")
        if screen:
            self.screening.screen_case(
                case_id,
                {ListKind.SANCTIONS: "2026.10.1"},
                actor="test",
                subjects=[
                    ScreeningSubject(
                        subject_ref=f"customer:{CUSTOMER}",
                        name="Daniel Okafor",
                        role="customer",
                        dob=date(1985, 3, 4),
                        identifiers=["PP-NG-2210"],
                    )
                ],
            )
        feed = ListTransactionFeed(
            [prof or profile()], {ACCOUNT: stream}
        )
        self.typologies.ingest_from_source(case_id, feed, actor="test-feed")
        self.typologies.run_typologies(
            case_id, "test-pack", "1.0", actor="test-runner"
        )
        self.workflow.transition(case_id, CaseStatus.INVESTIGATING, actor="test")
        return case_id


STRUCTURING_STREAM = [
    txn("T-S1", date(2026, 2, 10), "4200.00", channel="ach"),
    txn("T-1", date(2026, 3, 2), "9500", cash=True, channel="branch"),
    txn("T-2", date(2026, 3, 4), "9600", cash=True, channel="branch"),
    txn("T-3", date(2026, 3, 6), "9700", cash=True, channel="branch"),
    txn("T-S2", date(2026, 3, 10), "4200.00", channel="ach"),
]


@pytest.fixture()
def stack(tmp_path: Path) -> Stack:
    return Stack(tmp_path, [alert()])


# ---------------------------------------------------------------------------
# The record itself
# ---------------------------------------------------------------------------


def test_structuring_record_end_to_end(stack: Stack):
    case_id = stack.open_case("ALRT-I-1", STRUCTURING_STREAM)
    record = stack.investigations.run_investigation(case_id, actor="analyst")

    assert record.version == 1
    assert record.model_profile == "offline"
    assert record.hypothesis.label == "structuring"
    assert record.hypothesis.supporting_finding_ids, "typology finding must support"

    # Every finding cites, and every citation resolves.
    assert record.findings
    for finding in record.findings:
        assert finding.citations, finding.finding_id
        for citation in finding.citations:
            resolved = stack.resolver.resolve(citation, case_id)
            assert resolved is not None

    # The typology finding's statement carries the engine's figures.
    typo = next(f for f in record.findings if f.origin == "typology")
    assert typo.direction == "supports"
    assert typo.figures["total_amount"] == "28800"
    assert "28800" in typo.statement

    # Counter-search ran, recorded its checks, found nothing here —
    # and said what it covered.
    counter = record.counter_search
    assert counter.ran and counter.coverage
    assert {c.name for c in counter.checks} == {
        "regular_cadence",
        "documented_expectation",
    }
    assert all(
        c.outcome == "no_counter_evidence" for c in counter.checks
    )
    assert record.hypothesis.counter_finding_ids == []

    # The structuring case carries the source-of-funds open question.
    assert any(
        q.evidence_needed == "source_of_funds_documentation"
        for q in record.open_questions
    )

    # The record is on the evidence chain, and the chain verifies.
    assert record.evidence_seq is not None
    item = stack.store.get_evidence_item(case_id, record.evidence_seq)
    assert item.kind == "investigation_record"
    assert stack.evidence.verify_chain(case_id)
    events = [e.event for e in stack.store.list_audit(case_id)]
    assert "investigation_recorded" in events


def test_record_requires_investigating_state(stack: Stack):
    case_id = stack.intake.open_case("ALRT-I-1").case_id
    with pytest.raises(InvestigationStateError):
        stack.investigations.run_investigation(case_id, actor="analyst")
    with pytest.raises(CaseNotFoundError):
        stack.investigations.run_investigation("case-nope", actor="analyst")


def test_counter_evidence_found_for_cadence_beyond_cluster(tmp_path: Path):
    """The innocent explanation, present in the data: the same
    in-band deposits recur every ten days for months beyond the
    flagged cluster. The counter-search must find and cite it."""
    stack = Stack(tmp_path, [alert()])
    stream = []
    day = date(2026, 1, 5)
    for i in range(8):
        stream.append(
            txn(f"C-{i}", day, "9500", cash=True, channel="branch")
        )
        day += timedelta(days=10)
    stream += [
        txn("K-1", date(2026, 3, 28), "9400", cash=True, channel="branch"),
        txn("K-2", date(2026, 3, 30), "9600", cash=True, channel="branch"),
        txn("K-3", date(2026, 4, 1), "9800", cash=True, channel="branch"),
    ]
    prof = profile(opened_on=date(2025, 12, 1))
    case_id = stack.open_case("ALRT-I-1", stream, prof=prof)
    record = stack.investigations.run_investigation(case_id, actor="analyst")

    assert record.hypothesis.label == "structuring"
    assert record.hypothesis.counter_finding_ids, (
        "the cadence beyond the cluster must cut against the hypothesis"
    )
    counter_finding = next(
        f
        for f in record.findings
        if f.finding_id == record.hypothesis.counter_finding_ids[0]
    )
    assert counter_finding.origin == "counter_search"
    assert counter_finding.direction == "against"
    assert counter_finding.figures["count"] == "8"
    assert counter_finding.figures["span_days"] == "70"
    cadence = next(
        c for c in record.counter_search.checks if c.name == "regular_cadence"
    )
    assert cadence.outcome == "counter_evidence_found"
    assert cadence.counter_finding_ids == [counter_finding.finding_id]
    for citation in counter_finding.citations:
        assert stack.resolver.resolve(citation, case_id) is not None


# ---------------------------------------------------------------------------
# The record-time gate
# ---------------------------------------------------------------------------


def _record(stack: Stack) -> object:
    case_id = stack.open_case("ALRT-I-1", STRUCTURING_STREAM)
    return stack.investigations.run_investigation(case_id, actor="analyst")


def test_gate_refuses_citation_to_real_item_fake_element(stack: Stack):
    record = _record(stack)
    typo = next(f for f in record.findings if f.origin == "typology")
    poisoned_finding = typo.model_copy(
        update={
            "citations": [
                typo.citations[0].model_copy(
                    update={"element": "finding:find-does-not-exist"}
                )
            ]
        }
    )
    poisoned = record.model_copy(
        update={
            "findings": [
                poisoned_finding if f.finding_id == typo.finding_id else f
                for f in record.findings
            ]
        }
    )
    with pytest.raises(InvestigationRefusedError):
        stack.investigations.verify_record(poisoned)


def test_gate_refuses_missing_item_and_uncited_finding(stack: Stack):
    record = _record(stack)
    typo = next(f for f in record.findings if f.origin == "typology")
    for citations in (
        [typo.citations[0].model_copy(update={"evidence_seq": 999})],
        [],
    ):
        poisoned = record.model_copy(
            update={
                "findings": [
                    typo.model_copy(update={"citations": citations})
                    if f.finding_id == typo.finding_id
                    else f
                    for f in record.findings
                ]
            }
        )
        with pytest.raises(InvestigationRefusedError):
            stack.investigations.verify_record(poisoned)


def test_gate_refuses_invented_figures(stack: Stack):
    record = _record(stack)
    typo = next(f for f in record.findings if f.origin == "typology")
    # A figure in the figures dict that the cited records do not hold.
    poisoned = record.model_copy(
        update={
            "findings": [
                typo.model_copy(
                    update={
                        "figures": {**typo.figures, "total_amount": "777777.55"}
                    }
                )
                if f.finding_id == typo.finding_id
                else f
                for f in record.findings
            ]
        }
    )
    with pytest.raises(InvestigationRefusedError):
        stack.investigations.verify_record(poisoned)
    # A figure smuggled into the statement text only.
    poisoned = record.model_copy(
        update={
            "findings": [
                typo.model_copy(
                    update={"statement": typo.statement + " Another 77777 moved."}
                )
                if f.finding_id == typo.finding_id
                else f
                for f in record.findings
            ]
        }
    )
    with pytest.raises(InvestigationRefusedError):
        stack.investigations.verify_record(poisoned)


def test_composer_refuses_a_figure_not_in_its_inputs():
    composer = OfflineComposer()
    draft = StatementDraft(
        template="A total of {total} moved.",
        values={"total": "12345"},
        allowed={Decimal("999")},
    )
    with pytest.raises(ComposerRefusalError):
        composer.compose(draft)
    grounded = StatementDraft(
        template="A total of {total} moved.",
        values={"total": "999"},
        allowed={Decimal("999")},
    )
    assert composer.compose(grounded) == "A total of 999 moved."


def test_live_profile_is_a_loud_refusal_not_a_fallback(stack: Stack):
    case_id = stack.open_case("ALRT-I-1", STRUCTURING_STREAM)
    with pytest.raises(ModelProfileNotConfiguredError):
        stack.investigations.run_investigation(
            case_id, actor="analyst", profile="hosted-frontier"
        )
    assert stack.investigations.current_record(case_id) is None
    with pytest.raises(Exception):
        get_composer("no-such-profile")


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------


def test_rerun_is_idempotent_and_new_evidence_versions(stack: Stack):
    case_id = stack.open_case("ALRT-I-1", STRUCTURING_STREAM)
    v1 = stack.investigations.run_investigation(case_id, actor="analyst")
    again = stack.investigations.run_investigation(case_id, actor="analyst")
    assert again.record_id == v1.record_id and again.version == 1

    extra = [
        txn(
            f"R-{i}", date(2026, 3, 12) + timedelta(days=i), "10000",
            channel="wire",
        )
        for i in range(8)
    ]
    stack.typologies.ingest_transactions(
        case_id, extra, source_ref="core-banking:delta", actor="test-feed"
    )
    stack.typologies.run_typologies(
        case_id, "test-pack", "1.0", actor="test-runner"
    )
    v2 = stack.investigations.run_investigation(case_id, actor="analyst")
    assert v2.version == 2
    assert v2.supersedes_record_id == v1.record_id
    assert v2.diff is not None and v2.diff.from_version == 1
    assert any(
        key.startswith("typology:round_amount") for key in v2.diff.added
    )
    assert not any(
        key.startswith("typology:structuring") for key in v2.diff.added
    )
    assert v2.hypothesis.label == "structuring"

    history = stack.investigations.record_history(case_id)
    assert [r.version for r in history] == [1, 2]
    assert stack.investigations.current_record(case_id).record_id == v2.record_id
    record_items = [
        i for i in stack.store.list_evidence(case_id)
        if i.kind == "investigation_record"
    ]
    assert len(record_items) == 2, "v1 stays on the chain"
    assert stack.evidence.verify_chain(case_id)


# ---------------------------------------------------------------------------
# Prior cases
# ---------------------------------------------------------------------------


def test_prior_case_is_referenced_and_cited(tmp_path: Path):
    first = alert("ALRT-I-1", rule_id="TM-VELOCITY-03")
    second = alert("ALRT-I-2", rule_id="TM-STRUCTURING-01")
    stack = Stack(tmp_path, [first, second])
    prior_id = stack.intake.open_case("ALRT-I-1").case_id
    case_id = stack.open_case("ALRT-I-2", STRUCTURING_STREAM)
    record = stack.investigations.run_investigation(case_id, actor="analyst")

    assert [r.case_id for r in record.prior_case_refs] == [prior_id]
    prior_findings = [f for f in record.findings if f.origin == "prior_case"]
    assert len(prior_findings) == 1
    citation = prior_findings[0].citations[0]
    assert citation.case_id == prior_id
    assert stack.resolver.resolve(citation, case_id) == "TM-VELOCITY-03"


# ---------------------------------------------------------------------------
# SQL store persistence
# ---------------------------------------------------------------------------


def test_record_persists_through_the_sql_store(tmp_path: Path):
    store = SqlCaseStore.sqlite(
        tmp_path / "aml.db", REPO_ROOT / "migrations"
    )
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects)
    workflow = CaseWorkflow(store, screening_store=store)
    intake = IntakeService(store, ListAlertFeed([alert()]), evidence)
    typologies = TypologyService(store, store, evidence)
    investigations = InvestigationService(
        store, store, store, store, evidence
    )
    typologies.register_rule_pack(RulePack(pack_id="test-pack", version="1.0"))
    case_id = intake.open_case("ALRT-I-1").case_id
    workflow.transition(case_id, CaseStatus.ASSEMBLING, actor="test")
    feed = ListTransactionFeed([profile()], {ACCOUNT: STRUCTURING_STREAM})
    typologies.ingest_from_source(case_id, feed, actor="test-feed")
    typologies.run_typologies(case_id, "test-pack", "1.0", actor="test-runner")
    workflow.transition(case_id, CaseStatus.INVESTIGATING, actor="test")
    record = investigations.run_investigation(case_id, actor="analyst")

    reopened = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    stored = reopened.list_investigation_records(case_id)
    assert len(stored) == 1
    assert stored[0].record_id == record.record_id
    assert stored[0].hypothesis.label == "structuring"
    assert reopened.get_investigation_record(record.record_id) is not None
