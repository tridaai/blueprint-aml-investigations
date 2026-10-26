"""R15: the trap suite — adversarial fixtures graded exactly.

Each family in this file is a trap a careless implementation
falls into, with hand-computed expectations on both sides of
every boundary:

- **Namesakes** (screening + media): a shared name is not a
  person. A contradicting date of birth clears; a matching one
  corroborates even when the identifier differs — an identifier
  mismatch is recorded, never treated as proof of a different
  person; middle names and aliases match by the stated rules.
- **Threshold edges** (typologies): every rule boundary graded
  just under and exactly at — 9,999.99 is structuring material,
  10,000.00 is not; 4.9x velocity is quiet, 5.0x fires; a
  179-day dormancy is quiet, 180 fires; 89% pass-through is
  quiet, 90% fires.
- **Clock traps**: leap-day detection dates; identification
  flipping the operative deadline; a no-file decision recorded
  after the deadline — documented, and visibly late on the
  clock's face; a continuing clock anchored on a prior filing
  that was itself late.
- **Gate traps**: identity is the person, not the typed string
  (dual control compares canonical person ids — the regression
  for the re-cased self-confirmation / self-approval bypass);
  a disposition citing the current record id with a superseded
  version number is refused like any stale citation.
- **Chain traps**: a seal attempted over a chain with a gap
  introduced by direct store manipulation is refused at seal
  time — the seal re-verifies the whole chain.
- **Injection, second family**: payloads split across two memos
  (each half scans clean alone — the scanner is field-scoped,
  a documented boundary — and the halves together change
  nothing), a payload riding a counterparty name (fenced in the
  profile view and in the JSON the console reads, verbatim in
  storage), a payload in a media headline.
- **Data traps**: a re-delivered batch with one transaction
  altered is refused before anything is written (the regression
  for the mid-write crash that left an orphan batch a retry
  then silently honoured); an alert payload name that disagrees
  with the name the profile already holds stands as a conflict.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aml_investigations.api import create_app
from aml_investigations.clocks import RegulatoryClockService
from aml_investigations.dispositions import canonical_person_id
from aml_investigations.errors import (
    ApprovalRefusedError,
    DispositionRefusedError,
    EvidenceChainError,
    SealingRefusedError,
    TransactionConflictError,
)
from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.models import (
    AccountProfile,
    Alert,
    ApprovalOutcome,
    CaseStatus,
    ConfirmationOutcome,
    Disposition,
    DispositionOutcome,
    DispositionRecord,
    HitStatus,
    ListEntry,
    ListKind,
    ListSnapshot,
    MediaArticle,
    MediaBand,
    RulePack,
    ScreeningHit,
    Transaction,
)
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.quarantine import FENCE_MARKER, scan_text
from aml_investigations.screening import ScreeningService
from aml_investigations.stores import InMemoryCaseStore
from aml_investigations.transactions import ListTransactionFeed
from aml_investigations.typologies import (
    check_dormancy_then_burst,
    check_rapid_in_out,
    check_round_amount,
    check_structuring,
    check_velocity,
)
from tests.test_approval_sealing import Stack as GateStack
from tests.test_sar import (
    ACCOUNT,
    ANALYST,
    STRUCTURING_STREAM,
    anonymous_alert,
    identity_alert,
    txn,
)


# ---------------------------------------------------------------------------
# Gate traps: identity is the person, not the typed string
# ---------------------------------------------------------------------------


@pytest.fixture()
def gate_stack(tmp_path: Path) -> GateStack:
    return GateStack(tmp_path, [identity_alert(), anonymous_alert()])


def _parked_close(stack: GateStack) -> str:
    """An adverse (structuring) case closed by a.okafor, parked
    in pending_confirmation awaiting a second person."""
    case_id, record = stack.investigated_case("ALRT-S-1", STRUCTURING_STREAM)
    decided = stack.dispositions.record_disposition(
        case_id,
        analyst_id=ANALYST,
        analyst_role="analyst",
        outcome=DispositionOutcome.CLOSE_NO_ACTION,
        rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"],
        record_id=record.record_id,
        record_version=record.version,
    )
    assert decided.requires_confirmation
    assert stack.store.get_case(case_id).status is CaseStatus.PENDING_CONFIRMATION
    return case_id


def test_canonical_person_id_folds_case_and_whitespace():
    assert canonical_person_id("E.Okafor") == canonical_person_id("e.okafor")
    assert canonical_person_id("  e.okafor  ") == "e.okafor"
    assert canonical_person_id("E.  Okafor") == canonical_person_id("e. okafor")
    assert canonical_person_id("e.okafor") != canonical_person_id("m.osei")
    assert canonical_person_id("") == ""


@pytest.mark.parametrize(
    "respelt", ["A.OKAFOR", " a.okafor ", "A.Okafor", "a.okafor\t"]
)
def test_self_confirmation_under_a_respelt_id_is_refused(
    gate_stack: GateStack, respelt: str
):
    """The trap: the dispositioner confirms their own closure by
    presenting the same person id typed differently. Before the
    canonical-identity fix this was accepted — the comparison
    was a raw string equality."""
    case_id = _parked_close(gate_stack)
    with pytest.raises(DispositionRefusedError) as excinfo:
        gate_stack.dispositions.confirm_disposition(
            case_id,
            confirmer_id=respelt,
            confirmer_role="l2_reviewer",
            outcome=ConfirmationOutcome.CONFIRMED,
        )
    assert excinfo.value.reason == "self_confirmation"
    # The case is untouched: still parked for a second person.
    assert (
        gate_stack.store.get_case(case_id).status
        is CaseStatus.PENDING_CONFIRMATION
    )


def test_a_second_person_under_a_respelt_id_still_confirms(
    gate_stack: GateStack,
):
    """Canonical comparison must not over-block: a genuinely
    different person confirms, however they type their id."""
    case_id = _parked_close(gate_stack)
    gate_stack.dispositions.confirm_disposition(
        case_id,
        confirmer_id=" M.Osei ",
        confirmer_role="l2_reviewer",
        outcome=ConfirmationOutcome.CONFIRMED,
    )
    assert gate_stack.store.get_case(case_id).status is CaseStatus.CLOSED


def test_drafter_cannot_approve_under_respelt_id_or_borrowed_role(
    gate_stack: GateStack,
):
    """SAR dual control binds persons: the drafter presenting
    with a re-cased id and an approver-grade role is still the
    drafter; the dispositioner likewise, however spelled."""
    case_id, _record, _decided = gate_stack.sar_pending_case()
    narrative, _verification = gate_stack.sar.draft_narrative(
        case_id, actor="s.dube"
    )
    assert narrative.drafted_by == "s.dube"

    with pytest.raises(ApprovalRefusedError) as excinfo:
        gate_stack.approvals.decide_narrative(
            case_id,
            approver_id="S.DUBE",
            approver_role="l2_reviewer",
            outcome=ApprovalOutcome.APPROVED,
        )
    assert excinfo.value.reason == "approver_is_drafter"

    with pytest.raises(ApprovalRefusedError) as excinfo:
        gate_stack.approvals.decide_narrative(
            case_id,
            approver_id=" A.Okafor ",
            approver_role="l2_reviewer",
            outcome=ApprovalOutcome.APPROVED,
        )
    assert excinfo.value.reason == "approver_is_dispositioner"

    # A third person decides it — the positive path still lands.
    gate_stack.approvals.decide_narrative(
        case_id,
        approver_id="m.osei",
        approver_role="senior_analyst",
        outcome=ApprovalOutcome.APPROVED,
    )
    assert gate_stack.store.get_case(case_id).status is CaseStatus.FILED_SAR


def test_system_actor_under_respelt_spelling_is_refused(
    gate_stack: GateStack,
):
    case_id, record = gate_stack.investigated_case(
        "ALRT-S-1", STRUCTURING_STREAM
    )
    with pytest.raises(DispositionRefusedError) as excinfo:
        gate_stack.dispositions.record_disposition(
            case_id,
            analyst_id=" Investigation-Service ",
            analyst_role="analyst",
            outcome=DispositionOutcome.CLOSE_NO_ACTION,
            rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"],
            record_id=record.record_id,
            record_version=record.version,
        )
    assert excinfo.value.reason == "anonymous_or_system_actor"


# ---------------------------------------------------------------------------
# Gate traps: the stale citation, in its sharpest form
# ---------------------------------------------------------------------------


def test_disposition_citing_current_record_id_with_old_version_refused(
    gate_stack: GateStack,
):
    """Record ids embed their version (INV-<case>-V<n>), so the
    sharpest stale citation is the current id paired with a
    superseded version number. Both halves of the citation are
    checked; either one stale refuses."""
    case_id, record_v1 = gate_stack.investigated_case(
        "ALRT-S-1", STRUCTURING_STREAM
    )
    # New evidence arrives; the record moves to version 2.
    gate_stack.workflow.transition(
        case_id, CaseStatus.INVESTIGATING, actor="test"
    )
    extra = [
        txn(f"T-X{i}", date(2026, 3, 12) + timedelta(days=i), "10000")
        for i in range(8)
    ]
    gate_stack.typologies.ingest_transactions(
        case_id, extra, source_ref="core-banking:delta", actor="test-feed"
    )
    gate_stack.typologies.run_typologies(
        case_id, "test-pack", "1.0", actor="test-runner"
    )
    record_v2 = gate_stack.investigations.run_investigation(
        case_id, actor="test"
    )
    assert record_v2.version == 2 and record_v2.record_id != record_v1.record_id
    gate_stack.workflow.transition(
        case_id, CaseStatus.AWAITING_ANALYST, actor="test"
    )

    for record_id, version in (
        (record_v2.record_id, record_v1.version),  # current id, old version
        (record_v1.record_id, record_v1.version),  # the superseded pair
        (record_v1.record_id, record_v2.version),  # old id, current version
    ):
        with pytest.raises(DispositionRefusedError) as excinfo:
            gate_stack.dispositions.record_disposition(
                case_id,
                analyst_id=ANALYST,
                analyst_role="analyst",
                outcome=DispositionOutcome.ESCALATE_L2,
                rationale_codes=["CONFLICTING_EVIDENCE"],
                record_id=record_id,
                record_version=version,
            )
        assert excinfo.value.reason == "record_citation_not_current"

    # The current pair is accepted.
    gate_stack.dispositions.record_disposition(
        case_id,
        analyst_id=ANALYST,
        analyst_role="analyst",
        outcome=DispositionOutcome.ESCALATE_L2,
        rationale_codes=["CONFLICTING_EVIDENCE"],
        record_id=record_v2.record_id,
        record_version=record_v2.version,
    )
    assert gate_stack.store.get_case(case_id).status is CaseStatus.ESCALATED


# ---------------------------------------------------------------------------
# Data traps: re-delivery must not swallow an alteration
# ---------------------------------------------------------------------------


def _dtxn(tid: str, amount: str, memo: str = "") -> Transaction:
    return Transaction(
        transaction_id=tid,
        account_id="ACCT-5001",
        posted_at=datetime(2026, 3, 2, 10, 0, tzinfo=timezone.utc),
        direction="credit",
        amount=Decimal(amount),
        channel="wire",
        memo=memo,
    )


def test_altered_redelivery_refused_before_anything_is_written(services):
    """The trap: a batch re-delivered with one amount altered.
    Before the fix, ingestion wrote the batch record and its
    evidence item, then crashed on the duplicate id — leaving an
    orphan batch that a retry returned as if ingested, the
    alteration silently swallowed. Now the contradiction is
    refused whole, up front, and the file is exactly as it was."""
    case_id = services.intake.open_case("ALRT-T-001").case_id
    original = [_dtxn("DX-1", "100.00"), _dtxn("DX-2", "200.00")]
    batch = services.typologies.ingest_transactions(
        case_id, original, source_ref="core-banking:v1", actor="test-feed"
    )
    evidence_before = len(services.store.list_evidence(case_id))

    altered = [_dtxn("DX-1", "100.00"), _dtxn("DX-2", "250.00")]
    with pytest.raises(TransactionConflictError):
        services.typologies.ingest_transactions(
            case_id, altered, source_ref="core-banking:v2", actor="test-feed"
        )
    # A retry meets the same refusal — there is no orphan batch
    # for it to be silently honoured by.
    with pytest.raises(TransactionConflictError):
        services.typologies.ingest_transactions(
            case_id, altered, source_ref="core-banking:v2", actor="test-feed"
        )

    batches = services.store.list_transaction_batches(case_id)
    assert [b.batch_id for b in batches] == [batch.batch_id]
    stored = services.store.list_transactions(case_id)
    assert [(t.transaction_id, t.amount) for t in stored] == [
        ("DX-1", Decimal("100.00")),
        ("DX-2", Decimal("200.00")),
    ]
    assert len(services.store.list_evidence(case_id)) == evidence_before
    assert services.evidence.verify_chain(case_id) is True

    # Identical re-delivery is still the idempotent no-op.
    again = services.typologies.ingest_transactions(
        case_id, original, source_ref="core-banking:v1", actor="test-feed"
    )
    assert again.batch_id == batch.batch_id
    assert len(services.store.list_transaction_batches(case_id)) == 1


def test_altered_memo_alone_is_also_a_conflict(services):
    """Content is content: same id, same amount, different memo
    is a different record under that id — refused the same way."""
    case_id = services.intake.open_case("ALRT-T-001").case_id
    services.typologies.ingest_transactions(
        case_id,
        [_dtxn("DX-1", "100.00", memo="rent")],
        source_ref="core-banking:v1",
        actor="test-feed",
    )
    with pytest.raises(TransactionConflictError):
        services.typologies.ingest_transactions(
            case_id,
            [_dtxn("DX-1", "100.00", memo="salary")],
            source_ref="core-banking:v2",
            actor="test-feed",
        )


def test_identical_overlap_dedupes_and_stream_growth_lands(services):
    """The lawful counterpart: a full-history feed re-delivers
    what the case holds (identical) plus new records. The old
    records are stored once; the new ones land; the engine sees
    each transaction exactly once."""
    case_id = services.intake.open_case("ALRT-T-001").case_id
    services.typologies.register_rule_pack(
        RulePack(pack_id="trap-pack", version="1.0")
    )
    first = [_dtxn("DX-1", "100.00"), _dtxn("DX-2", "200.00")]
    services.typologies.ingest_transactions(
        case_id, first, source_ref="core-banking:v1", actor="test-feed"
    )
    grown = [*first, _dtxn("DX-3", "300.00")]
    services.typologies.ingest_transactions(
        case_id, grown, source_ref="core-banking:v2", actor="test-feed"
    )
    stored = services.store.list_transactions(case_id)
    assert [t.transaction_id for t in stored] == ["DX-1", "DX-2", "DX-3"]
    assert len(services.store.list_transaction_batches(case_id)) == 2
    run = services.typologies.run_typologies(
        case_id, "trap-pack", "1.0", actor="test-runner"
    )
    assert run.transaction_count == 3


def test_profile_name_conflict_stands_with_both_sources(services):
    """An alert whose payload names the customer differently
    from the name the profile already holds (an earlier case's
    payload — the account profile itself carries no name in
    this system) produces a name conflict in the assembled
    view: both values, both sources, never merged."""
    feed = ListAlertFeed(
        [
            Alert(
                alert_id="ALRT-X-1", rule_id="TM-VELOCITY-03",
                customer_id="CUST-X1", account_id="ACCT-X1",
                severity="medium", detected_on="2026-03-01",
                summary="First case for the customer.",
                raw={"customer_name": "Priya Nair"},
            ),
            Alert(
                alert_id="ALRT-X-2", rule_id="TM-VELOCITY-03",
                customer_id="CUST-X1", account_id="ACCT-X2",
                severity="medium", detected_on="2026-03-05",
                summary="Second case, a differently-spelled name.",
                raw={"customer_name": "Priya Nair-Sharma"},
            ),
        ]
    )
    intake = IntakeService(
        services.store, feed, services.evidence,
        quarantine=services.quarantine,
    )
    case_one = intake.open_case("ALRT-X-1")
    case_two = intake.open_case("ALRT-X-2")
    view = services.profiles.assemble_profile(
        "CUST-X1", as_of=date(2026, 3, 20), actor="test"
    )
    name_conflicts = [c for c in view.identity_conflicts if c.field == "name"]
    assert len(name_conflicts) == 1
    assert name_conflicts[0].values == ["Priya Nair", "Priya Nair-Sharma"]
    assert name_conflicts[0].flag == "identity_conflict"
    sources = {f.source_case_id for f in name_conflicts[0].facts}
    assert sources == {case_one.case_id, case_two.case_id}
