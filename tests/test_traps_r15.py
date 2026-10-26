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


# ---------------------------------------------------------------------------
# Namesake traps: screening
# ---------------------------------------------------------------------------

TRAP_SANCTIONS = ListSnapshot(
    list_kind=ListKind.SANCTIONS,
    version="2026.10.1",
    published_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
    source_note="trap screening feed",
    entries=[
        ListEntry(
            entry_id="SDN-T1", name="Amara Chen",
            dob=date(1990, 4, 2), identifiers=["PP-SG-100"],
        ),
        ListEntry(
            entry_id="SDN-T2", name="Ravi Menon",
            dob=date(1988, 11, 30), identifiers=["PP-IN-999"],
        ),
        ListEntry(entry_id="SDN-T3", name="Daniel Okafor"),
        ListEntry(
            entry_id="SDN-T4", name="Tomas Lindqvist",
            aliases=["Tom Lindqvist"],
        ),
    ],
)


def _screened_case(services, alert_id, customer_id, account_id, raw):
    intake = IntakeService(
        services.store,
        ListAlertFeed(
            [
                Alert(
                    alert_id=alert_id, rule_id="TM-STRUCT-01",
                    customer_id=customer_id, account_id=account_id,
                    severity="high", detected_on="2026-10-20",
                    summary="Trap subject.",
                    raw=raw,
                )
            ]
        ),
        services.evidence,
        quarantine=services.quarantine,
    )
    case = intake.open_case(alert_id)
    services.workflow.transition(
        case.case_id, CaseStatus.ASSEMBLING, actor="test"
    )
    services.screening.ingest_snapshot(TRAP_SANCTIONS, actor="test")
    services.screening.screen_case(
        case.case_id,
        pins={ListKind.SANCTIONS: "2026.10.1"},
        actor="test",
    )
    return case.case_id


def test_namesake_same_name_and_city_different_dob_clears(services):
    """Same name, same city — and a date of birth that says a
    different person. The hit is recorded and CLEARED with the
    reason; it neither stands open nor vanishes."""
    case_id = _screened_case(
        services, "ALRT-NS-1", "CUST-NS-1", "ACCT-NS-1",
        {
            "customer_name": "Amara Chen",
            "customer_dob": "1992-07-19",
            "customer_city": "Singapore",
            "customer_identifiers": ["PP-SG-777"],
        },
    )
    hits = services.store.list_hits(case_id)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.entry_id == "SDN-T1"
    assert hit.status is HitStatus.CLEARED
    assert hit.cleared_reason == "date_of_birth_mismatch"
    assert hit.strength == "potential"


def test_same_name_and_dob_different_identifier_stays_strong(services):
    """The counter-trap: an identifier that merely differs is
    NOT a contradiction. Screening cannot prove two records
    are different people because their passport numbers differ
    — a matching DOB corroborates, and the hit stands strong
    and open for a human."""
    case_id = _screened_case(
        services, "ALRT-NS-2", "CUST-NS-2", "ACCT-NS-2",
        {
            "customer_name": "Ravi Menon",
            "customer_dob": "1988-11-30",
            "customer_identifiers": ["PP-IN-555"],
        },
    )
    hits = services.store.list_hits(case_id)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.entry_id == "SDN-T2"
    assert hit.status is HitStatus.OPEN
    assert hit.strength == "strong"
    assert "dob_match" in hit.basis
    assert "identifier_match" not in hit.basis


def test_middle_name_variant_matches_by_token_subset(services):
    """'Daniel Chuka Okafor' against the entry 'Daniel Okafor':
    the entry's tokens are a subset of the subject's — a
    potential hit by the stated rule, open, and graded as the
    weaker match it is (never promoted to strong)."""
    case_id = _screened_case(
        services, "ALRT-NS-3", "CUST-NS-3", "ACCT-NS-3",
        {"customer_name": "Daniel Chuka Okafor"},
    )
    hits = services.store.list_hits(case_id)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.entry_id == "SDN-T3"
    assert hit.status is HitStatus.OPEN
    assert hit.strength == "potential"
    assert hit.score == 0.85
    assert "name_token_subset" in hit.basis


def test_counterparty_alias_surface_reaches_the_entry(services):
    """The counterparty 'Tom Lindqvist' matches the entry
    'Tomas Lindqvist' through the entry's declared alias — the
    alias is a surface of the entry, and the hit names it."""
    case_id = _screened_case(
        services, "ALRT-NS-4", "CUST-NS-4", "ACCT-NS-4",
        {
            "customer_name": "Sara Lindqvist",
            "counterparties": [{"name": "Tom Lindqvist"}],
        },
    )
    hits = services.store.list_hits(case_id)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.entry_id == "SDN-T4"
    assert hit.subject_name == "Tom Lindqvist"
    assert hit.subject_role == "counterparty"
    assert "entry alias" in hit.basis


def test_hit_existing_only_in_v2_flags_stale_and_waits(services):
    """The case was screened on list v1; the subject's entry
    exists only in v2. Ingesting v2 must flag the case
    STALE_SCREENING — not silently clear the subject, not
    silently add the hit. The hit appears when a human
    re-screens against v2."""
    pep_v1 = ListSnapshot(
        list_kind=ListKind.PEP, version="2026.10.1",
        published_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
        source_note="trap pep feed",
        entries=[ListEntry(entry_id="PEP-T1", name="Someone Else")],
    )
    pep_v2 = ListSnapshot(
        list_kind=ListKind.PEP, version="2026.10.2",
        published_at=datetime(2026, 10, 24, tzinfo=timezone.utc),
        source_note="trap pep feed",
        entries=[
            ListEntry(
                entry_id="PEP-T9", name="Nadia Rahman",
                dob=date(1993, 2, 14),
            )
        ],
    )
    intake = IntakeService(
        services.store,
        ListAlertFeed(
            [
                Alert(
                    alert_id="ALRT-NS-5", rule_id="TM-STRUCT-01",
                    customer_id="CUST-NS-5", account_id="ACCT-NS-5",
                    severity="high", detected_on="2026-10-20",
                    summary="Subject added to the PEP list later.",
                    raw={
                        "customer_name": "Nadia Rahman",
                        "customer_dob": "1993-02-14",
                    },
                )
            ]
        ),
        services.evidence,
        quarantine=services.quarantine,
    )
    case_id = intake.open_case("ALRT-NS-5").case_id
    services.workflow.transition(case_id, CaseStatus.ASSEMBLING, actor="t")
    services.screening.ingest_snapshot(pep_v1, actor="test")
    services.screening.screen_case(
        case_id, pins={ListKind.PEP: "2026.10.1"}, actor="test"
    )
    assert services.store.list_hits(case_id) == []

    services.screening.ingest_snapshot(pep_v2, actor="test")
    after = services.store.get_case(case_id)
    assert after.screening_stale is True
    assert "STALE_SCREENING" in after.flags
    pep_pins = {e.list_kind: e.version for e in after.screened_against}
    assert pep_pins[ListKind.PEP] == "2026.10.1"
    # Nothing was silently screened: still no hits on the file.
    assert services.store.list_hits(case_id) == []

    services.screening.screen_case(
        case_id, pins={ListKind.PEP: "2026.10.2"}, actor="test"
    )
    hits = services.store.list_hits(case_id)
    assert len(hits) == 1
    assert hits[0].entry_id == "PEP-T9"
    assert hits[0].status is HitStatus.OPEN
    assert hits[0].strength == "strong"
    assert services.store.get_case(case_id).screening_stale is False


# ---------------------------------------------------------------------------
# Namesake traps: adverse media
# ---------------------------------------------------------------------------


def _media_service(services, articles):
    from aml_investigations.media import (
        AdverseMediaService,
        ListMediaFeed,
    )

    return AdverseMediaService(
        services.store,
        media_store=services.store,
        evidence=services.evidence,
        source=ListMediaFeed(articles),
        seal_store=services.store,
        quarantine=services.quarantine,
        profile_service=services.profiles,
        typology_store=services.store,
    )


def _weber_case(services) -> str:
    intake = IntakeService(
        services.store,
        ListAlertFeed(
            [
                Alert(
                    alert_id="ALRT-MW-1", rule_id="TM-VELOCITY-03",
                    customer_id="CUST-MW", account_id="ACCT-MW",
                    severity="medium", detected_on="2026-10-20",
                    summary="Media namesake subject.",
                    raw={
                        "customer_name": "Jonas Weber",
                        "customer_dob": "1985-06-11",
                        "customer_identifiers": ["PP-DE-4711"],
                        "customer_city": "Munich",
                        "customer_state": "Bavaria",
                        "customer_occupation": "brewer",
                    },
                )
            ]
        ),
        services.evidence,
        quarantine=services.quarantine,
    )
    case_id = intake.open_case("ALRT-MW-1").case_id
    services.workflow.transition(case_id, CaseStatus.ASSEMBLING, actor="t")
    return case_id


def _weber_article(article_id: str, **overrides) -> MediaArticle:
    fields = dict(
        article_id=article_id,
        outlet="Bavarian Ledger",
        headline="Weber charged in fraud case",
        published_on=date(2026, 9, 14),
        body=(
            "Prosecutors charged Jonas Weber with wire fraud "
            "after an investigation into falsified invoices."
        ),
        subjects_named=["Jonas Weber"],
        locations=["Munich"],
        raw={"feed": "trap-media"},
    )
    fields.update(overrides)
    return MediaArticle(**fields)


def test_media_same_dob_different_identifier_is_strong(services):
    """A non-matching identifier in an article is recorded as
    absent evidence, never as a contradiction: with the DOB
    corroborating, the article stands STRONG."""
    case_id = _weber_case(services)
    media = _media_service(
        services,
        [
            _weber_article(
                "MW-1",
                subject_dob=date(1985, 6, 11),
                identifiers=["PP-DE-9999"],
            )
        ],
    )
    (assessment,) = media.search_case_media(
        case_id, actor="test", as_of=date(2026, 10, 25)
    )
    assert assessment.band is MediaBand.STRONG
    identifier = next(
        s for s in assessment.signals if s.signal == "identifier"
    )
    assert identifier.outcome == "absent"
    dob = next(s for s in assessment.signals if s.signal == "dob")
    assert dob.outcome == "supports"


def test_media_same_city_contradicting_dob_is_namesake_cleared(services):
    """Same name, same city — and a date of birth thirty years
    off. Geography corroborates and still loses: the hard
    contradiction clears the article as a namesake, with the
    contradiction on the record."""
    case_id = _weber_case(services)
    media = _media_service(
        services,
        [_weber_article("MW-2", subject_dob=date(1955, 3, 2))],
    )
    (assessment,) = media.search_case_media(
        case_id, actor="test", as_of=date(2026, 10, 25)
    )
    assert assessment.band is MediaBand.NAMESAKE_CLEARED
    assert "namesake" in assessment.band_basis
    geography = next(
        s for s in assessment.signals if s.signal == "geography"
    )
    assert geography.outcome == "supports"
    dob = next(s for s in assessment.signals if s.signal == "dob")
    assert dob.outcome == "contradicts"


def test_media_identifier_match_prevails_over_dob_contradiction(services):
    """The article carries the subject's own identifier AND a
    contradicting DOB (a typo'd birth date in the press, say).
    The identifier prevails — the article stands STRONG — and
    the contradiction is recorded on the assessment, exactly
    as at screening."""
    case_id = _weber_case(services)
    media = _media_service(
        services,
        [
            _weber_article(
                "MW-3",
                subject_dob=date(1955, 3, 2),
                identifiers=["PP-DE-4711"],
            )
        ],
    )
    (assessment,) = media.search_case_media(
        case_id, actor="test", as_of=date(2026, 10, 25)
    )
    assert assessment.band is MediaBand.STRONG
    assert "identifier corroboration" in assessment.band_basis
    assert "hard contradiction is also recorded" in assessment.band_basis


# ---------------------------------------------------------------------------
# Threshold-edge traps: every boundary graded on both sides
# ---------------------------------------------------------------------------

EDGE_PACK = RulePack(pack_id="trap-pack", version="1.0")


def _etxn(tid, day, amount, *, direction="credit", cash=False, hour=10):
    return Transaction(
        transaction_id=tid,
        account_id="ACCT-EDGE",
        posted_at=datetime.combine(
            day, time(hour, 0), tzinfo=timezone.utc
        ),
        direction=direction,
        amount=Decimal(amount),
        channel="wire",
        cash=cash,
    )


def test_structuring_band_edges():
    day = date(2026, 3, 3)
    in_band = [
        _etxn(f"S{i}", day, "9999.99", cash=True, hour=8 + i)
        for i in range(3)
    ]
    drafts = check_structuring(in_band, EDGE_PACK)
    assert len(drafts) == 1
    assert drafts[0].figures["total_amount"] == "29999.97"
    assert drafts[0].figures["transaction_count"] == "3"

    # 10,000.00 is at the CTR threshold, not under it: not
    # structuring material, however many arrive the same day.
    at_threshold = [
        _etxn(f"S{i}", day, "10000.00", cash=True, hour=8 + i)
        for i in range(3)
    ]
    assert check_structuring(at_threshold, EDGE_PACK) == []

    # Below the band entirely.
    below = [
        _etxn(f"S{i}", day, "8999.00", cash=True, hour=8 + i)
        for i in range(3)
    ]
    assert check_structuring(below, EDGE_PACK) == []

    # In band, but only two of them: the count boundary binds.
    two = in_band[:2]
    assert check_structuring(two, EDGE_PACK) == []

    # Spread across three days inside the window: multi-day.
    spread = [
        _etxn("S0", date(2026, 3, 2), "9999.99", cash=True),
        _etxn("S1", date(2026, 3, 3), "9999.99", cash=True),
        _etxn("S2", date(2026, 3, 4), "9999.99", cash=True),
    ]
    drafts = check_structuring(spread, EDGE_PACK)
    assert len(drafts) == 1
    assert drafts[0].variant == "multi_day"


def _velocity_stream(observation_count: int) -> list[Transaction]:
    base = date(2026, 1, 1)
    txns: list[Transaction] = []
    n = 0
    for i in range(30):  # days 0..29: two a day
        for _ in range(2):
            txns.append(_etxn(f"B{n}", base + timedelta(days=i), "111.11"))
            n += 1
    for i in range(30, 70):  # days 30..69: one a day
        txns.append(_etxn(f"B{n}", base + timedelta(days=i), "111.11"))
        n += 1
    assert n == 100
    last = base + timedelta(days=76)  # observation window: days 70..76
    for i in range(observation_count):
        txns.append(
            _etxn(f"O{i}", last - timedelta(days=i % 7), "222.22")
        )
    return txns


def test_velocity_multiple_edges():
    # 49 in 7 days against 100 in 70 days: 49*70/(100*7) = 4.9.
    assert check_velocity(_velocity_stream(49), EDGE_PACK) == []
    # 50: exactly 5.0 — the rule fires at its stated multiple.
    drafts = check_velocity(_velocity_stream(50), EDGE_PACK)
    assert len(drafts) == 1
    assert drafts[0].figures["count_multiple"] == "5.0000"
    assert drafts[0].figures["observation_count"] == "50"
    assert drafts[0].figures["baseline_count"] == "100"
    assert drafts[0].figures["baseline_days"] == "70"


def test_dormancy_gap_edges():
    profile = AccountProfile(
        customer_id="CUST-EDGE", account_id="ACCT-EDGE",
        opened_on=date(2026, 1, 1),
        account_type="personal_checking",
    )
    # First activity on day 179: quiet, even with a burst after.
    gap_179 = [
        _etxn("D0", date(2026, 6, 29), "3000.50"),
        _etxn("D1", date(2026, 6, 30), "2500.25"),
    ]
    assert check_dormancy_then_burst(gap_179, profile, EDGE_PACK) == []
    # First activity on day 180 exactly: the rule fires.
    gap_180 = [
        _etxn("D0", date(2026, 6, 30), "3000.50"),
        _etxn("D1", date(2026, 7, 1), "2500.25"),
    ]
    drafts = check_dormancy_then_burst(gap_180, profile, EDGE_PACK)
    assert len(drafts) == 1
    assert drafts[0].figures["gap_days"] == "180"
    assert drafts[0].figures["burst_amount"] == "5500.75"
    assert drafts[0].figures["burst_count"] == "2"


def test_round_amount_share_edges():
    day = date(2026, 3, 3)
    rounds = [
        _etxn(f"R{i}", day + timedelta(days=i), "5000.00") for i in range(5)
    ]
    smalls = [
        _etxn(f"N{i}", day + timedelta(days=i), "123.45") for i in range(6)
    ]
    # 5 round of 11 total: share 0.4545 — under the half.
    assert check_round_amount([*rounds, *smalls], EDGE_PACK) == []
    # 5 of 10: share exactly 0.5 — fires at the stated share.
    drafts = check_round_amount([*rounds, *smalls[:5]], EDGE_PACK)
    assert len(drafts) == 1
    assert drafts[0].figures["round_share"] == "0.5000"
    assert drafts[0].figures["round_total"] == "25000.00"
    assert drafts[0].figures["round_count"] == "5"


def test_rapid_in_out_pass_through_edges():
    day = date(2026, 3, 3)
    inbound = [_etxn("I0", day, "20000.00", hour=10)]

    # 17,800 of 20,000 out within the window: 89% — quiet.
    out_89 = [
        _etxn("O0", day, "17800.00", direction="debit", hour=20)
    ]
    assert check_rapid_in_out([*inbound, *out_89], EDGE_PACK) == []

    # 18,000 out: exactly 90% — fires at the stated fraction.
    out_90 = [
        _etxn("O0", day, "18000.00", direction="debit", hour=20)
    ]
    drafts = check_rapid_in_out([*inbound, *out_90], EDGE_PACK)
    assert len(drafts) == 1
    assert drafts[0].figures["pass_through"] == "0.9000"
    assert drafts[0].figures["disbursed_amount"] == "18000.00"
    assert drafts[0].figures["retained_amount"] == "2000.00"
