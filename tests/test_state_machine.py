"""Law 1 and the lawful-transition table, tested exhaustively."""

from __future__ import annotations

import pytest

from aml_investigations.errors import (
    DispositionRequiredError,
    IllegalTransitionError,
)
from aml_investigations.models import CaseStatus, Disposition
from aml_investigations.workflow import TRANSITIONS

CLOSE = Disposition(
    analyst="j.rivera", decision="close", reason_code="BENIGN_EXPLANATION_DOCUMENTED"
)
FILE_SAR = Disposition(
    analyst="j.rivera", decision="file_sar", reason_code="STRUCTURING_CONFIRMED"
)


def _walk_to(services, case_id: str, target: CaseStatus) -> None:
    """Walk a fresh case along lawful edges to ``target``."""
    path = {
        CaseStatus.OPENED: [],
        CaseStatus.ASSEMBLING: [CaseStatus.ASSEMBLING],
        CaseStatus.INVESTIGATING: [CaseStatus.ASSEMBLING, CaseStatus.INVESTIGATING],
        CaseStatus.AWAITING_ANALYST: [
            CaseStatus.ASSEMBLING,
            CaseStatus.INVESTIGATING,
            CaseStatus.AWAITING_ANALYST,
        ],
        CaseStatus.ESCALATED: [
            CaseStatus.ASSEMBLING,
            CaseStatus.INVESTIGATING,
            CaseStatus.ESCALATED,
        ],
    }[target]
    for step in path:
        services.workflow.transition(case_id, step, actor="investigation-service")


_counter = [0]


def _open(services) -> str:
    """Open a FRESH case (intake is idempotent per alert, so each call
    mints a unique alert through the same intake path)."""
    from aml_investigations.models import Alert

    _counter[0] += 1
    alert = Alert(
        alert_id=f"ALRT-T-WALK-{_counter[0]:03d}",
        rule_id="TM-STRUCTURING-01",
        customer_id="CUST-1001",
        account_id="ACCT-5001",
        severity="high",
        detected_on="2026-10-20",
        summary="Walk case.",
    )
    return services.intake.open_case_from_alert(alert).case_id


def test_happy_path_to_closed(services):
    case_id = _open(services)
    _walk_to(services, case_id, CaseStatus.AWAITING_ANALYST)
    case = services.workflow.transition(
        case_id, CaseStatus.CLOSED, actor="analyst:j.rivera", disposition=CLOSE
    )
    assert case.status is CaseStatus.CLOSED
    assert case.disposition is not None
    assert case.disposition.analyst == "j.rivera"


def test_happy_path_to_filed_sar(services):
    case_id = _open(services)
    _walk_to(services, case_id, CaseStatus.AWAITING_ANALYST)
    case = services.workflow.transition(
        case_id, CaseStatus.FILED_SAR, actor="analyst:j.rivera", disposition=FILE_SAR
    )
    assert case.status is CaseStatus.FILED_SAR
    assert case.disposition.decision == "file_sar"


def test_every_unlawful_pair_is_refused(services):
    """Exhaustive: for every (from, to) not in the table, a refusal."""
    for source in CaseStatus:
        case_id = _open(services)
        if source in (CaseStatus.CLOSED, CaseStatus.FILED_SAR):
            _walk_to(services, case_id, CaseStatus.AWAITING_ANALYST)
            disp = CLOSE if source is CaseStatus.CLOSED else FILE_SAR
            services.workflow.transition(
                case_id, source, actor="analyst:j.rivera", disposition=disp
            )
        else:
            _walk_to(services, case_id, source)
        for target in CaseStatus:
            if target in TRANSITIONS[source]:
                continue
            disp = None
            if target is CaseStatus.CLOSED:
                disp = CLOSE
            elif target is CaseStatus.FILED_SAR:
                disp = FILE_SAR
            with pytest.raises(IllegalTransitionError):
                services.workflow.transition(
                    case_id, target, actor="analyst:x", disposition=disp
                )


def test_close_without_disposition_is_refused(services):
    case_id = _open(services)
    _walk_to(services, case_id, CaseStatus.AWAITING_ANALYST)
    with pytest.raises(DispositionRequiredError):
        services.workflow.transition(case_id, CaseStatus.CLOSED, actor="analyst:j.rivera")
    with pytest.raises(DispositionRequiredError):
        services.workflow.transition(case_id, CaseStatus.FILED_SAR, actor="analyst:j.rivera")
    case = services.store.get_case(case_id)
    assert case.status is CaseStatus.AWAITING_ANALYST
    assert case.disposition is None


def test_close_from_investigating_is_refused_even_with_disposition(services):
    """The gate cannot be skipped: investigating -> closed has no edge."""
    case_id = _open(services)
    _walk_to(services, case_id, CaseStatus.INVESTIGATING)
    with pytest.raises(IllegalTransitionError):
        services.workflow.transition(
            case_id, CaseStatus.CLOSED, actor="analyst:j.rivera", disposition=CLOSE
        )


def test_mismatched_disposition_decision_is_refused(services):
    case_id = _open(services)
    _walk_to(services, case_id, CaseStatus.AWAITING_ANALYST)
    with pytest.raises(IllegalTransitionError):
        services.workflow.transition(
            case_id, CaseStatus.CLOSED, actor="analyst:j.rivera", disposition=FILE_SAR
        )


def test_terminal_states_have_no_exits(services):
    case_id = _open(services)
    _walk_to(services, case_id, CaseStatus.AWAITING_ANALYST)
    services.workflow.transition(
        case_id, CaseStatus.CLOSED, actor="analyst:j.rivera", disposition=CLOSE
    )
    for target in CaseStatus:
        with pytest.raises(IllegalTransitionError):
            services.workflow.transition(case_id, target, actor="analyst:j.rivera")


def test_refused_transition_is_audited(services):
    case_id = _open(services)
    with pytest.raises(IllegalTransitionError):
        services.workflow.transition(case_id, CaseStatus.CLOSED, actor="analyst:j.rivera")
    events = [e.event for e in services.store.list_audit(case_id)]
    assert "transition_refused" in events


def test_send_back_and_escalation_round_trip(services):
    case_id = _open(services)
    _walk_to(services, case_id, CaseStatus.AWAITING_ANALYST)
    case = services.workflow.transition(
        case_id, CaseStatus.INVESTIGATING, actor="analyst:j.rivera"
    )
    assert case.status is CaseStatus.INVESTIGATING
    case = services.workflow.transition(
        case_id, CaseStatus.ESCALATED, actor="investigation-service"
    )
    assert case.status is CaseStatus.ESCALATED
    case = services.workflow.transition(
        case_id, CaseStatus.AWAITING_ANALYST, actor="senior:m.osei"
    )
    assert case.status is CaseStatus.AWAITING_ANALYST


def test_disposition_requires_named_analyst_and_reason_code():
    with pytest.raises(Exception):
        Disposition(analyst="", decision="close", reason_code="X")
    with pytest.raises(Exception):
        Disposition(analyst="j.rivera", decision="close", reason_code="")
