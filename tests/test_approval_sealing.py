"""R7: dual-control SAR approval + case sealing / export / hold.

The approval gate is Law 2's second half: the analyst who routed
the case to SAR drafting cannot approve the narrative, the actor
who drafted it cannot approve it, and only a verified narrative
over the current record can be decided at all. Sealing is Law 5's
completion: a terminal case file is certified by a manifest over
every evidence item, made read-only, exportable as one package
that an offline verifier re-checks — and unsealable only by a
named officer with a coded reason, with the history intact.
"""

from __future__ import annotations

import base64
from datetime import date
from pathlib import Path

import pytest

from aml_investigations.approval import SarApprovalService
from aml_investigations.dispositions import DispositionService
from aml_investigations.errors import (
    ApprovalRefusedError,
    CaseSealedError,
    SealingRefusedError,
)
from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.investigation import InvestigationService
from aml_investigations.models import (
    ApprovalOutcome,
    CaseSeal,
    CaseSealManifest,
    CaseStatus,
    CaseUnseal,
    DispositionOutcome,
    LegalHoldEvent,
    RulePack,
    SarApproval,
)
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.sar import SarNarrativeService
from aml_investigations.sealing import (
    CaseSealingService,
    seal_hash_for,
    verify_export_package,
)
from aml_investigations.screening import ScreeningService
from aml_investigations.stores import InMemoryCaseStore, SqlCaseStore
from aml_investigations.transactions import ListTransactionFeed
from aml_investigations.typologies import TypologyService
from aml_investigations.workflow import CaseWorkflow
from tests.test_sar import (
    ACCOUNT,
    ANALYST,
    CADENCE_STREAM,
    CUSTOMER_SUBJECT,
    ROUND_STREAM,
    SANCTIONS,
    STRUCTURING_STREAM,
    anonymous_alert,
    identity_alert,
    profile,
    txn,
)
from aml_investigations.models import ListKind

APPROVER = "m.osei"
OFFICER = "o.reyes"


class Stack:
    """One in-memory stack with the full R7 wiring: every service
    shares the seal store, so a sealed case refuses everywhere."""

    def __init__(self, tmp_path: Path, alerts):
        self.store = InMemoryCaseStore()
        self.objects = LocalObjectStore(tmp_path / "objects")
        self.evidence = EvidenceService(
            self.store, self.objects, seal_store=self.store
        )
        self.workflow = CaseWorkflow(self.store, screening_store=self.store)
        self.intake = IntakeService(
            self.store, ListAlertFeed(alerts), self.evidence
        )
        self.screening = ScreeningService(
            self.store, self.store, self.evidence, seal_store=self.store
        )
        self.typologies = TypologyService(
            self.store, self.store, self.evidence, seal_store=self.store
        )
        self.investigations = InvestigationService(
            self.store, self.store, self.store, self.store, self.evidence,
            disposition_store=self.store,
            seal_store=self.store,
        )
        self.dispositions = DispositionService(
            self.store, self.store, self.store, self.store,
            self.evidence, self.workflow, seal_store=self.store,
        )
        self.sar = SarNarrativeService(
            self.store, self.store, self.store, self.store, self.evidence,
            approval_store=self.store,
            seal_store=self.store,
        )
        self.approvals = SarApprovalService(
            self.store, self.store, self.store, self.store,
            self.sar, self.evidence, self.workflow,
            seal_store=self.store,
        )
        self.sealing = CaseSealingService(
            self.store, self.store, self.store, self.store,
            self.store, self.evidence, self.store,
        )
        self.screening.ingest_snapshot(SANCTIONS, actor="test-feed")
        self.typologies.register_rule_pack(
            RulePack(pack_id="test-pack", version="1.0")
        )

    def open_case(self, alert_id: str, stream) -> str:
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

    def sar_pending_case(self, alert_id: str = "ALRT-S-1"):
        case_id, record = self.investigated_case(alert_id, STRUCTURING_STREAM)
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

    def closed_case(self, alert_id: str = "ALRT-S-2"):
        """A benign case closed at the gate — the non-SAR terminal
        path a seal also certifies."""
        case_id, record = self.investigated_case(alert_id, CADENCE_STREAM)
        self.dispositions.record_disposition(
            case_id,
            analyst_id=ANALYST,
            analyst_role="analyst",
            outcome=DispositionOutcome.CLOSE_NO_ACTION,
            rationale_codes=["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"],
            record_id=record.record_id,
            record_version=record.version,
        )
        assert self.store.get_case(case_id).status is CaseStatus.CLOSED
        return case_id

    def approved_case(self, alert_id: str = "ALRT-S-1"):
        case_id, _record, _decided = self.sar_pending_case(alert_id)
        narrative, _ = self.sar.draft_narrative(
            case_id, actor="sar-drafting-service"
        )
        approval = self.approvals.decide_narrative(
            case_id,
            approver_id=APPROVER,
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
        return case_id, narrative, approval


@pytest.fixture()
def stack(tmp_path: Path) -> Stack:
    return Stack(tmp_path, [identity_alert(), anonymous_alert()])


# ---------------------------------------------------------------------------
# The approval gate: positive path
# ---------------------------------------------------------------------------


def test_second_person_approval_completes_the_case_file(stack: Stack):
    case_id, _record, _decided = stack.sar_pending_case()
    narrative, _verification = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    assert stack.sar.status_of(narrative) == "verified"

    approval = stack.approvals.decide_narrative(
        case_id,
        approver_id=APPROVER,
        approver_role="senior_analyst",
        outcome=ApprovalOutcome.APPROVED,
    )
    assert approval.approver_id == APPROVER
    assert approval.narrative_id == narrative.narrative_id
    assert approval.disposition_id == narrative.disposition_id
    assert approval.evidence_seq is not None
    # The case file is complete — and nothing was filed anywhere:
    # the state records the approval outcome, no more.
    case = stack.store.get_case(case_id)
    assert case.status is CaseStatus.FILED_SAR
    assert case.disposition is not None
    assert case.disposition.decision == "file_sar"
    assert case.disposition.analyst == ANALYST
    # The approval is on the hash chain and in the store.
    item = stack.store.get_evidence_item(case_id, approval.evidence_seq)
    assert item.kind == "sar_approval"
    assert stack.store.get_approval_for(narrative.narrative_id) == approval
    assert stack.evidence.verify_chain(case_id) is True
    stored = stack.sar.current_narrative(case_id)
    assert stack.sar.status_of(stored) == "approved"
    assert stack.approvals.current_approval(case_id) == approval


# ---------------------------------------------------------------------------
# The approval gate: dual control and its neighbours
# ---------------------------------------------------------------------------


def test_dispositioning_analyst_cannot_approve(stack: Stack):
    case_id, _record, _decided = stack.sar_pending_case()
    stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            case_id,
            approver_id=ANALYST,  # recorded the escalate_sar disposition
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
    assert refused.value.reason == "approver_is_dispositioner"
    assert stack.store.get_case(case_id).status is CaseStatus.SAR_PENDING
    assert stack.store.list_approvals(case_id) == []


def test_drafter_cannot_approve_their_own_narrative(stack: Stack):
    case_id, _record, _decided = stack.sar_pending_case()
    stack.sar.draft_narrative(case_id, actor="j.doe")
    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            case_id,
            approver_id="j.doe",
            approver_role="analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
    assert refused.value.reason == "approver_is_drafter"


def test_anonymous_system_and_roleless_approvers_refused(stack: Stack):
    case_id, _record, _decided = stack.sar_pending_case()
    stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    for approver in ("", "system", "aml-agent"):
        with pytest.raises(ApprovalRefusedError) as refused:
            stack.approvals.decide_narrative(
                case_id,
                approver_id=approver,
                approver_role="senior_analyst",
                outcome=ApprovalOutcome.APPROVED,
            )
        assert refused.value.reason == "anonymous_or_system_actor"
    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            case_id,
            approver_id=APPROVER,
            approver_role="wizard",
            outcome=ApprovalOutcome.APPROVED,
        )
    assert refused.value.reason == "unknown_role"


def test_unverified_narrative_cannot_be_decided(stack: Stack):
    case_id, _record, _decided = stack.sar_pending_case()
    narrative, _ = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    # A second version whose statements were altered after drafting
    # has no passing verification behind it.
    tampered = narrative.model_copy(
        update={
            "narrative_id": "narr-tampered",
            "version": 2,
            "sections": [
                s.model_copy(
                    update={
                        "statements": [
                            s.statements[0].model_copy(
                                update={"text": "The subject moved $1.00."}
                            )
                        ]
                        + list(s.statements[1:])
                    }
                )
                if s.key == "amounts_and_instruments"
                else s
                for s in narrative.sections
            ],
        }
    )
    stack.store.add_narrative(tampered)
    assert stack.sar.status_of(tampered) == "draft"
    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            case_id,
            approver_id=APPROVER,
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
    assert refused.value.reason == "narrative_not_verified"


def test_stale_narrative_cannot_be_decided(stack: Stack):
    case_id, _record, _decided = stack.sar_pending_case()
    narrative, _ = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    assert stack.sar.status_of(narrative) == "verified"
    # New evidence supersedes the record the narrative cites.
    stack.workflow.transition(case_id, CaseStatus.INVESTIGATING, actor="test")
    stack.typologies.ingest_transactions(
        case_id, ROUND_STREAM,
        source_ref="core-banking:delta", actor="test-feed",
    )
    stack.typologies.run_typologies(case_id, "test-pack", "1.0", actor="test")
    stack.investigations.run_investigation(case_id, actor="test")
    assert stack.sar.status_of(narrative) == "stale"
    stack.workflow.transition(
        case_id, CaseStatus.AWAITING_ANALYST, actor="test"
    )
    stack.workflow.transition(case_id, CaseStatus.SAR_PENDING, actor="test")
    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            case_id,
            approver_id=APPROVER,
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
    assert refused.value.reason == "narrative_not_verified"
    assert "stale" in str(refused.value)


def test_approval_before_any_draft_and_on_wrong_state(stack: Stack):
    case_id, _record, _decided = stack.sar_pending_case()
    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            case_id,
            approver_id=APPROVER,
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
    assert refused.value.reason == "no_narrative"

    other_id, _rec = stack.investigated_case("ALRT-S-2", CADENCE_STREAM)
    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            other_id,
            approver_id=APPROVER,
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
    assert refused.value.reason == "case_not_sar_pending"


def test_approval_carries_no_reason_codes(stack: Stack):
    case_id, _record, _decided = stack.sar_pending_case()
    stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            case_id,
            approver_id=APPROVER,
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
            reason_codes=["NARRATIVE_INACCURATE"],
        )
    assert refused.value.reason == "approval_reason_codes_not_applicable"


def test_rejection_is_coded_and_returns_the_narrative_to_drafting(
    stack: Stack,
):
    case_id, _record, _decided = stack.sar_pending_case()
    first, _ = stack.sar.draft_narrative(case_id, actor="sar-drafting-service")

    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            case_id,
            approver_id=APPROVER,
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.REJECTED,
        )
    assert refused.value.reason == "rejection_codes_required"
    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            case_id,
            approver_id=APPROVER,
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.REJECTED,
            reason_codes=["NOT_A_CODE"],
        )
    assert refused.value.reason == "unknown_rejection_code"

    rejection = stack.approvals.decide_narrative(
        case_id,
        approver_id=APPROVER,
        approver_role="senior_analyst",
        outcome=ApprovalOutcome.REJECTED,
        reason_codes=["CHRONOLOGY_WRONG"],
        note="The branch dates are out of order.",
    )
    assert rejection.outcome is ApprovalOutcome.REJECTED
    assert rejection.reason_vocabulary_version == "2026.10.1"
    # The case stays at drafting; the narrative stands rejected.
    assert stack.store.get_case(case_id).status is CaseStatus.SAR_PENDING
    assert stack.sar.status_of(first) == "rejected"

    # The same version cannot be decided twice — the answer to a
    # rejection is a re-draft, never a second decision.
    with pytest.raises(ApprovalRefusedError) as refused:
        stack.approvals.decide_narrative(
            case_id,
            approver_id="k.osei",
            approver_role="l2_reviewer",
            outcome=ApprovalOutcome.APPROVED,
        )
    assert refused.value.reason == "already_decided"

    second, _ = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    assert second.version == 2
    assert stack.sar.status_of(second) == "verified"
    stack.approvals.decide_narrative(
        case_id,
        approver_id=APPROVER,
        approver_role="senior_analyst",
        outcome=ApprovalOutcome.APPROVED,
    )
    assert stack.store.get_case(case_id).status is CaseStatus.FILED_SAR
    assert len(stack.approvals.history(case_id)) == 2


# ---------------------------------------------------------------------------
# Sealing: the positive path and the manifest
# ---------------------------------------------------------------------------


def test_seal_approved_case_and_export_verifies(stack: Stack):
    case_id, narrative, approval = stack.approved_case()
    items_before = len(stack.store.list_evidence(case_id))

    seal = stack.sealing.seal_case(
        case_id, officer_id=OFFICER, officer_role="l2_reviewer"
    )
    assert seal.version == 1
    assert seal.manifest.case_id == case_id
    # The manifest certifies every evidence item that existed when
    # the seal was computed — no more, no fewer.
    assert len(seal.manifest.items) == items_before
    assert [i.seq for i in seal.manifest.items] == list(
        range(1, items_before + 1)
    )
    assert seal.manifest.chain_head_hash == (
        stack.store.list_evidence(case_id)[items_before - 1].chain_hash
    )
    assert seal.seal_hash == seal_hash_for(seal.manifest)
    pins = {(p.kind, p.artefact_id) for p in seal.manifest.artefacts}
    assert ("sar_narrative", narrative.narrative_id) in pins
    assert ("sar_approval", approval.approval_id) in pins
    assert seal.retention_until is not None
    assert "five-year" in seal.retention_basis
    assert stack.sealing.is_sealed(case_id) is True

    package = stack.sealing.export_case_file(case_id)
    result = verify_export_package(package)
    assert result.ok, result.problems
    assert result.items_checked == items_before
    assert result.seal_id == seal.seal_id


def test_seal_closed_non_sar_case(stack: Stack):
    case_id = stack.closed_case()
    seal = stack.sealing.seal_case(
        case_id, officer_id=OFFICER, officer_role="senior_analyst"
    )
    pin_kinds = {p.kind for p in seal.manifest.artefacts}
    assert "disposition" in pin_kinds
    assert "sar_narrative" not in pin_kinds
    result = verify_export_package(stack.sealing.export_case_file(case_id))
    assert result.ok, result.problems


def test_seal_refusals(stack: Stack):
    case_id, _record = stack.investigated_case("ALRT-S-1", STRUCTURING_STREAM)
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.seal_case(
            case_id, officer_id=OFFICER, officer_role="l2_reviewer"
        )
    assert refused.value.reason == "case_not_terminal"
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.seal_case(
            case_id, officer_id=OFFICER, officer_role="analyst"
        )
    assert refused.value.reason == "officer_role_required"
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.seal_case(
            case_id, officer_id="system", officer_role="l2_reviewer"
        )
    assert refused.value.reason == "anonymous_or_system_actor"

    sealed_id = stack.closed_case("ALRT-S-2")
    stack.sealing.seal_case(
        sealed_id, officer_id=OFFICER, officer_role="l2_reviewer"
    )
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.seal_case(
            sealed_id, officer_id=OFFICER, officer_role="l2_reviewer"
        )
    assert refused.value.reason == "already_sealed"
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.export_case_file(case_id)
    assert refused.value.reason == "case_not_sealed"


# ---------------------------------------------------------------------------
# A sealed case is read-only — every mutating path refuses
# ---------------------------------------------------------------------------


def test_sealed_case_refuses_every_mutation(stack: Stack):
    case_id, _narrative, _approval = stack.approved_case()
    stack.sealing.seal_case(
        case_id, officer_id=OFFICER, officer_role="l2_reviewer"
    )
    items_at_seal = len(stack.store.list_evidence(case_id))

    with pytest.raises(CaseSealedError):
        stack.evidence.add_item(
            case_id,
            kind="analyst_note",
            content=b"late note",
            source_ref="test",
            captured_by="analyst:a.okafor",
        )
    with pytest.raises(CaseSealedError):
        stack.screening.screen_case(
            case_id,
            {ListKind.SANCTIONS: "2026.10.1"},
            actor="test",
            subjects=[CUSTOMER_SUBJECT],
        )
    with pytest.raises(CaseSealedError):
        stack.typologies.ingest_transactions(
            case_id,
            [txn("T-LATE", date(2026, 4, 1), "100")],
            source_ref="core-banking:late",
            actor="test-feed",
        )
    with pytest.raises(CaseSealedError):
        stack.typologies.run_typologies(
            case_id, "test-pack", "1.0", actor="test"
        )
    with pytest.raises(CaseSealedError):
        stack.investigations.run_investigation(case_id, actor="test")
    with pytest.raises(CaseSealedError):
        stack.dispositions.record_disposition(
            case_id,
            analyst_id=ANALYST,
            analyst_role="analyst",
            outcome=DispositionOutcome.CLOSE_NO_ACTION,
            rationale_codes=["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"],
            record_id="INV-x",
            record_version=1,
        )
    with pytest.raises(CaseSealedError):
        stack.sar.draft_narrative(case_id, actor="sar-drafting-service")
    with pytest.raises(CaseSealedError):
        stack.approvals.decide_narrative(
            case_id,
            approver_id=APPROVER,
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
    # Nothing landed: the file is exactly as sealed.
    assert len(stack.store.list_evidence(case_id)) == items_at_seal
    assert stack.evidence.verify_chain(case_id) is True


# ---------------------------------------------------------------------------
# Export verification catches tampering, by item
# ---------------------------------------------------------------------------


def test_tampered_export_fails_and_names_the_item(stack: Stack):
    case_id, _narrative, _approval = stack.approved_case()
    stack.sealing.seal_case(
        case_id, officer_id=OFFICER, officer_role="l2_reviewer"
    )
    package = stack.sealing.export_case_file(case_id)

    target = package["items"][2]
    forged = dict(package)
    forged_items = [dict(i) for i in package["items"]]
    forged_items[2] = dict(
        target,
        content_b64=base64.b64encode(b"forged content").decode("ascii"),
    )
    forged["items"] = forged_items
    result = verify_export_package(forged)
    assert result.ok is False
    assert any(f"seq {target['seq']}" in p for p in result.problems)

    dropped = dict(package)
    dropped["items"] = [
        i for i in package["items"] if i["seq"] != target["seq"]
    ]
    result = verify_export_package(dropped)
    assert result.ok is False
    assert any(
        f"seq {target['seq']}" in p and "missing" in p
        for p in result.problems
    )

    extra = dict(package)
    extra["items"] = list(package["items"]) + [
        dict(target, seq=9999)
    ]
    result = verify_export_package(extra)
    assert result.ok is False
    assert any("9999" in p for p in result.problems)

    resealed = dict(package)
    resealed["seal"] = dict(package["seal"], seal_hash="0" * 64)
    result = verify_export_package(resealed)
    assert result.ok is False
    assert any("seal hash" in p for p in result.problems)


# ---------------------------------------------------------------------------
# Legal hold + unseal / reseal
# ---------------------------------------------------------------------------


def test_legal_hold_lifecycle(stack: Stack):
    case_id, _narrative, _approval = stack.approved_case()
    hold = stack.sealing.place_hold(
        case_id,
        officer_id=OFFICER,
        officer_role="l2_reviewer",
        reason_code="LITIGATION_PENDING",
    )
    assert hold.action == "placed"
    assert hold.evidence_seq is not None
    assert stack.store.get_case(case_id).legal_hold is True
    assert stack.sealing.hold_in_force(case_id) is True

    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.place_hold(
            case_id,
            officer_id=OFFICER,
            officer_role="l2_reviewer",
            reason_code="COURT_ORDER",
        )
    assert refused.value.reason == "already_on_hold"
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.seal_case(
            case_id,
            officer_id=OFFICER,
            officer_role="l2_reviewer",
            purpose="archive",
        )
    assert refused.value.reason == "legal_hold_blocks_archive"

    # A custody seal still lands — and states the hold on its face.
    seal = stack.sealing.seal_case(
        case_id, officer_id=OFFICER, officer_role="l2_reviewer"
    )
    assert seal.legal_hold is True

    released = stack.sealing.release_hold(
        case_id,
        officer_id=OFFICER,
        officer_role="l2_reviewer",
        reason_code="MATTER_RESOLVED",
    )
    assert released.action == "released"
    assert stack.sealing.hold_in_force(case_id) is False
    assert stack.store.get_case(case_id).legal_hold is False
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.release_hold(
            case_id,
            officer_id=OFFICER,
            officer_role="l2_reviewer",
            reason_code="MATTER_RESOLVED",
        )
    assert refused.value.reason == "not_on_hold"
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.place_hold(
            case_id,
            officer_id=OFFICER,
            officer_role="l2_reviewer",
            reason_code="WHIMSY",
        )
    assert refused.value.reason == "unknown_hold_reason"


def test_unseal_and_reseal_keep_the_full_history(stack: Stack):
    case_id = stack.closed_case()
    first = stack.sealing.seal_case(
        case_id, officer_id=OFFICER, officer_role="l2_reviewer"
    )
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.unseal_case(
            case_id,
            officer_id=OFFICER,
            officer_role="analyst",
            reason_code="INVESTIGATION_REOPENED",
        )
    assert refused.value.reason == "officer_role_required"
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.unseal_case(
            case_id,
            officer_id=OFFICER,
            officer_role="l2_reviewer",
            reason_code="JUST_BECAUSE",
        )
    assert refused.value.reason == "unknown_unseal_reason"

    unseal = stack.sealing.unseal_case(
        case_id,
        officer_id=OFFICER,
        officer_role="l2_reviewer",
        reason_code="INVESTIGATION_REOPENED",
    )
    assert unseal.seal_id == first.seal_id
    assert stack.sealing.is_sealed(case_id) is False
    # Mutable again — the unseal is what re-opens the file.
    stack.evidence.add_item(
        case_id,
        kind="analyst_note",
        content=b"reopened for review",
        source_ref="test",
        captured_by="analyst:a.okafor",
    )
    with pytest.raises(SealingRefusedError) as refused:
        stack.sealing.unseal_case(
            case_id,
            officer_id=OFFICER,
            officer_role="l2_reviewer",
            reason_code="INVESTIGATION_REOPENED",
        )
    assert refused.value.reason == "case_not_sealed"

    second = stack.sealing.seal_case(
        case_id, officer_id=OFFICER, officer_role="l2_reviewer"
    )
    assert second.version == 2
    assert second.seal_id != first.seal_id
    history = stack.sealing.seal_history(case_id)
    assert [h["record"] for h in history] == ["seal", "unseal", "seal"]
    assert history[0]["seal_id"] == first.seal_id
    assert history[2]["seal_id"] == second.seal_id
    assert stack.sealing.view(second)["operative"] is True
    assert stack.sealing.view(first)["operative"] is False
    # The reseal certifies the note added while unsealed.
    assert len(second.manifest.items) > len(first.manifest.items)


# ---------------------------------------------------------------------------
# The SQL store carries the R7 records
# ---------------------------------------------------------------------------


def test_sql_store_round_trips_r7_records(tmp_path: Path):
    store = SqlCaseStore.sqlite(
        tmp_path / "aml.db",
        Path(__file__).resolve().parents[1] / "migrations",
    )
    approval = SarApproval(
        case_id="case-sql-7",
        narrative_id="narr-sql-7",
        narrative_version=1,
        record_id="INV-case-sql-7-V1",
        record_version=1,
        disposition_id="disp-sql-7",
        approver_id=APPROVER,
        approver_role="senior_analyst",
        outcome=ApprovalOutcome.REJECTED,
        reason_codes=["CHRONOLOGY_WRONG"],
        reason_vocabulary_version="2026.10.1",
        evidence_seq=9,
    )
    store.add_approval(approval)
    assert store.get_approval(approval.approval_id) == approval
    assert store.get_approval_for("narr-sql-7") == approval
    assert store.list_approvals("case-sql-7") == [approval]

    manifest = CaseSealManifest(
        case_id="case-sql-7", chain_head_hash="ab" * 32, items=[]
    )
    seal = CaseSeal(
        case_id="case-sql-7",
        version=1,
        sealed_by=OFFICER,
        sealed_role="l2_reviewer",
        manifest=manifest,
        seal_hash=seal_hash_for(manifest),
        retention_basis="BSA five-year retention posture.",
        retention_until=date(2031, 10, 25),
        evidence_seq=10,
    )
    store.add_seal(seal)
    assert store.get_seal(seal.seal_id) == seal
    assert store.list_seals("case-sql-7") == [seal]

    unseal = CaseUnseal(
        case_id="case-sql-7",
        seal_id=seal.seal_id,
        unsealed_by=OFFICER,
        unsealed_role="l2_reviewer",
        reason_code="COURT_ORDER",
        evidence_seq=11,
    )
    store.add_unseal(unseal)
    assert store.list_unseals("case-sql-7") == [unseal]

    hold = LegalHoldEvent(
        case_id="case-sql-7",
        action="placed",
        officer_id=OFFICER,
        officer_role="l2_reviewer",
        reason_code="COURT_ORDER",
        evidence_seq=12,
    )
    store.add_hold_event(hold)
    assert store.list_hold_events("case-sql-7") == [hold]
