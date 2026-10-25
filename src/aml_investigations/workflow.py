"""The case state machine, built on LangGraph.

The graph's nodes are the case states. One invocation applies exactly
one transition: the entry router sends the run to the node for the
case's current state, that node validates the requested target
against the lawful transition table below and applies the guards,
and the run exits. The compiled graph is the executor — the service
layer never mutates a case's status directly.

Law 1 lives here: the only entries into ``closed`` and ``filed_sar``
in the table start at ``awaiting_analyst``, and both demand a
recorded :class:`~aml_investigations.models.Disposition` whose
decision matches the target. There is no path — in the graph or
anywhere else — by which a case closes without a named analyst's
disposition.

Law 3's consequence lives here too (R2): when a screening store is
wired, a plain ``closed`` transition is refused for any case with an
unresolved sanctions hit, whatever the disposition says — the case
must escalate, file a SAR, or have the hit cleared by an analyst
with a recorded reason first.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from .errors import (
    CaseNotFoundError,
    DispositionRequiredError,
    IllegalTransitionError,
    SanctionsHitBlocksCloseError,
)
from .logging_config import get_logger
from .models import AuditEvent, Case, CaseStatus, Disposition, HitStatus, ListKind
from .ports import CaseStore, ScreeningStore

logger = get_logger(__name__)

#: The lawful transition table. Terminal states map to the empty set.
TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPENED: frozenset({CaseStatus.ASSEMBLING}),
    CaseStatus.ASSEMBLING: frozenset({CaseStatus.INVESTIGATING}),
    CaseStatus.INVESTIGATING: frozenset(
        {CaseStatus.AWAITING_ANALYST, CaseStatus.ESCALATED}
    ),
    CaseStatus.AWAITING_ANALYST: frozenset(
        {
            CaseStatus.INVESTIGATING,  # analyst sends the case back for more work
            CaseStatus.ESCALATED,
            CaseStatus.CLOSED,
            CaseStatus.FILED_SAR,
        }
    ),
    CaseStatus.ESCALATED: frozenset(
        {CaseStatus.INVESTIGATING, CaseStatus.AWAITING_ANALYST}
    ),
    CaseStatus.CLOSED: frozenset(),
    CaseStatus.FILED_SAR: frozenset(),
}

#: Closing targets and the disposition decision each one requires.
_CLOSING_DECISIONS = {
    CaseStatus.CLOSED: "close",
    CaseStatus.FILED_SAR: "file_sar",
}


def apply_transition(
    case: Case, target: CaseStatus, disposition: Disposition | None
) -> Case:
    """Validate and apply one transition to ``case`` in place.

    Raises IllegalTransitionError (or its DispositionRequiredError
    subclass) for anything the table does not allow.
    """
    current = case.status
    if target not in TRANSITIONS[current]:
        raise IllegalTransitionError(current.value, target.value)
    if target in _CLOSING_DECISIONS:
        if disposition is None:
            raise DispositionRequiredError(current.value, target.value)
        if disposition.decision != _CLOSING_DECISIONS[target]:
            raise IllegalTransitionError(
                current.value,
                target.value,
                reason=(
                    f"disposition decision {disposition.decision!r} does not "
                    f"match target {target.value!r}"
                ),
            )
        case.disposition = disposition
    elif target == CaseStatus.ESCALATED and disposition is not None:
        # An escalation may also carry the analyst's recorded decision.
        case.disposition = disposition
    case.status = target
    case.updated_at = datetime.now(timezone.utc)
    return case


class _GraphState(TypedDict):
    case: Case
    target: CaseStatus
    disposition: Disposition | None


def _make_node(current: CaseStatus):
    def node(state: _GraphState) -> _GraphState:
        case = state["case"]
        if case.status != current:
            # The entry router guarantees this; keep the invariant loud.
            raise IllegalTransitionError(case.status.value, current.value)
        apply_transition(case, state["target"], state["disposition"])
        return state

    return node


def build_graph():
    """Compile the case state machine as a LangGraph graph.

    Structure: START routes to the node named by the case's current
    status; that node applies (or refuses) the one requested
    transition; every node then routes to END. One invocation, one
    transition — the case store persists the result between
    invocations, which is what makes the workflow resumable and
    auditable step by step.
    """
    graph = StateGraph(_GraphState)
    for status in CaseStatus:
        graph.add_node(status.value, _make_node(status))
    graph.add_conditional_edges(
        START,
        lambda state: state["case"].status.value,
        {status.value: status.value for status in CaseStatus},
    )
    for status in CaseStatus:
        graph.add_edge(status.value, END)
    return graph.compile()


class CaseWorkflow:
    """Applies guarded transitions to stored cases via the graph.

    When a screening store is wired, a second guard sits in front of
    the graph for the ``closed`` target: a case with an unresolved
    sanctions hit (Law 3) is in a must-escalate posture and a plain
    close is refused even with a well-formed disposition — the
    lawful dispositions are escalate or file_sar, or an analyst
    clears the hit first with a recorded reason.
    """

    def __init__(
        self, store: CaseStore, screening_store: ScreeningStore | None = None
    ) -> None:
        self._store = store
        self._screening = screening_store
        self._graph = build_graph()

    def _guard_sanctions_close(self, case: Case, actor: str) -> None:
        if self._screening is None:
            return
        unresolved = [
            h
            for h in self._screening.list_hits(case.case_id)
            if h.list_kind is ListKind.SANCTIONS and h.status is not HitStatus.CLEARED
        ]
        if not unresolved:
            return
        exc = SanctionsHitBlocksCloseError(
            case.status.value, [h.hit_id for h in unresolved]
        )
        self._store.append_audit(
            AuditEvent(
                case_id=case.case_id,
                actor=actor,
                event="transition_refused",
                detail={
                    "from": case.status.value,
                    "to": CaseStatus.CLOSED.value,
                    "reason": str(exc),
                },
            )
        )
        raise exc

    def transition(
        self,
        case_id: str,
        target: CaseStatus,
        *,
        actor: str,
        disposition: Disposition | None = None,
    ) -> Case:
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        current = case.status
        if target is CaseStatus.CLOSED:
            self._guard_sanctions_close(case, actor)
        try:
            result = self._graph.invoke(
                {"case": case, "target": target, "disposition": disposition}
            )
        except IllegalTransitionError as exc:
            self._store.append_audit(
                AuditEvent(
                    case_id=case_id,
                    actor=actor,
                    event="transition_refused",
                    detail={
                        "from": current.value,
                        "to": target.value,
                        "reason": str(exc),
                    },
                )
            )
            raise
        updated: Case = result["case"]
        self._store.update_case(updated)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="transition",
                detail={"from": current.value, "to": target.value},
            )
        )
        logger.info(
            "case transition",
            extra={"case_id": case_id, "event": "transition", "actor": actor},
        )
        return updated


def lawful_targets(status: CaseStatus) -> frozenset[CaseStatus]:
    return TRANSITIONS[status]
