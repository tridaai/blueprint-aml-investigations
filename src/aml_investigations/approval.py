"""The dual-control approval gate (R7): Law 2, second half.

R6 drafts the SAR narrative and verifies every statement against
its citations. This gate is where a second person decides it. The
discipline mirrors the disposition gate (R5) because it is the
same law seen from the other side:

- **A named human, mechanically.** Approver id and a coded role
  are required; blank, anonymous, and system actors are refused
  before anything else is looked at. The drafting service — any
  service — cannot approve its own output, including by borrowing
  this gate.
- **Dual control, mechanically.** The approver may not be the
  analyst who recorded the ``escalate_sar`` disposition that
  routed the case, and may not be the actor who drafted the
  narrative. Either identity match is a named refusal, not a
  warning. There is no override. Identity matches are computed
  on the canonical person id (``canonical_person_id`` in
  dispositions.py): dual control binds the person, so the
  drafter presenting with a re-cased spelling of their id and
  an approver's role is still the drafter.
- **Only a verified narrative may be decided.** The gate reads
  the narrative's derived standing from the drafting service: a
  draft that has not passed the citation verifier, or whose
  record has since been superseded (stale), cannot be approved
  or rejected-into-history here — it is refused, with its standing
  named. And a narrative version is decided exactly once: a
  decision stands forever, and the answer to a rejection is a
  re-draft (the next version), never a second decision on the
  same text.
- **Rejection is coded.** A rejection requires reason codes from
  a versioned vocabulary; free text supplements, never
  substitutes. An approval carries no codes at all — the codes
  exist to say what was wrong, and an approval has nothing to
  code.

On approval, the case file is complete: the service records the
approval on the case's hash chain (kind ``sar_approval``), then
drives the case along the state machine's ``sar_pending ->
filed_sar`` edge with the closing disposition minted from the
escalate_sar record — the R1 closing-token rule, met at the
moment the closure takes effect. On rejection, the case stays in
``sar_pending`` and the narrative's standing becomes ``rejected``:
it is back at drafting standing, awaiting a re-draft.

And the boundary, stated plainly one more time: **no SAR is ever
filed by this system.** Approval ends at a complete case file,
ready to be sealed — nothing here transmits anything anywhere.
"""

from __future__ import annotations

import threading

from .dispositions import ANALYST_ROLES, SYSTEM_ACTORS, canonical_person_id
from .errors import ApprovalRefusedError, CaseNotFoundError
from .evidence import EvidenceService, ensure_case_mutable
from .logging_config import get_logger
from .models import (
    ApprovalOutcome,
    AuditEvent,
    Case,
    CaseStatus,
    Disposition,
    SarApproval,
    SarNarrative,
)
from .ports import (
    ApprovalStore,
    CaseStore,
    DispositionStore,
    SarNarrativeStore,
    SealStore,
)
from .sar import SarNarrativeService
from .workflow import CaseWorkflow

logger = get_logger(__name__)

#: The rejection vocabulary's version. An approval decision records
#: the version its codes were drawn from, so a later revision never
#: silently re-reads an old rejection.
REJECTION_VOCABULARY_VERSION = "2026.10.1"

#: Coded rejection reasons. A rejection must name at least one; the
#: narrative goes back to drafting with these as its worklist.
REJECTION_CODES = frozenset(
    {
        "NARRATIVE_INACCURATE",
        "CITATIONS_INSUFFICIENT",
        "SUBJECT_DETAILS_WRONG",
        "ACTIVITY_DESCRIPTION_INCOMPLETE",
        "AMOUNTS_MISSTATED",
        "OPEN_QUESTIONS_UNADDRESSED",
        "CHRONOLOGY_WRONG",
    }
)


class SarApprovalService:
    """Decides verified SAR narratives at the second-person gate."""

    def __init__(
        self,
        store: CaseStore,
        dispositions: DispositionStore,
        approvals: ApprovalStore,
        narratives: SarNarrativeStore,
        sar: SarNarrativeService,
        evidence: EvidenceService,
        workflow: CaseWorkflow,
        seal_store: SealStore | None = None,
    ) -> None:
        self._store = store
        self._dispositions = dispositions
        self._approvals = approvals
        self._narratives = narratives
        self._sar = sar
        self._evidence = evidence
        self._workflow = workflow
        self._seals = seal_store
        # R19: the decision is check-then-act (read the case,
        # check no decision stands, verify, transition, record).
        # Two approvers racing could both pass the checks and
        # decide the same narrative version twice. The act
        # serialises on this lock within the app process; the
        # loser re-reads and meets the already_decided refusal.
        self._gate_lock = threading.RLock()

    # -- refusals -----------------------------------------------------

    def _refuse(
        self, case_id: str, actor: str, reason: str, message: str
    ) -> ApprovalRefusedError:
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="sar_approval_refused",
                detail={"reason": reason, "message": message},
            )
        )
        return ApprovalRefusedError(reason, message)

    def _require_case(self, case_id: str) -> Case:
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        return case

    # -- the gate -------------------------------------------------------

    def decide_narrative(
        self,
        case_id: str,
        *,
        approver_id: str,
        approver_role: str,
        outcome: ApprovalOutcome,
        reason_codes: list[str] | None = None,
        note: str = "",
    ) -> SarApproval:
        """Record the second person's decision on the case's
        current SAR narrative. See the module docstring for the
        gate's rules; every one of them refuses by name. The act
        is serialised on the service's gate lock (R19), so a
        narrative version is decided exactly once even when two
        approvers submit concurrently."""
        with self._gate_lock:
            return self._decide_narrative(
                case_id,
                approver_id=approver_id,
                approver_role=approver_role,
                outcome=outcome,
                reason_codes=reason_codes,
                note=note,
            )

    def _decide_narrative(
        self,
        case_id: str,
        *,
        approver_id: str,
        approver_role: str,
        outcome: ApprovalOutcome,
        reason_codes: list[str] | None = None,
        note: str = "",
    ) -> SarApproval:
        case = self._require_case(case_id)
        ensure_case_mutable(self._seals, case_id)
        actor = f"analyst:{approver_id}"

        approver = approver_id or ""
        if not approver.strip() or canonical_person_id(approver) in SYSTEM_ACTORS:
            raise self._refuse(
                case_id,
                approver or "anonymous",
                "anonymous_or_system_actor",
                f"approver must be a named person; {approver_id!r} is "
                "anonymous or a system actor, and the system never "
                "approves its own narrative",
            )
        if approver_role not in ANALYST_ROLES:
            raise self._refuse(
                case_id,
                actor,
                "unknown_role",
                f"approver role {approver_role!r} is not in the coded "
                f"role vocabulary ({', '.join(sorted(ANALYST_ROLES))})",
            )

        if case.status is not CaseStatus.SAR_PENDING:
            raise self._refuse(
                case_id,
                actor,
                "case_not_sar_pending",
                f"case is {case.status.value}; a narrative is decided "
                "while the case stands in sar_pending, and only then",
            )

        narratives = self._narratives.list_narratives(case_id)
        narrative = narratives[-1] if narratives else None
        if narrative is None:
            raise self._refuse(
                case_id,
                actor,
                "no_narrative",
                "the case holds no SAR narrative; there is nothing "
                "for a second person to decide",
            )

        existing = self._approvals.get_approval_for(narrative.narrative_id)
        if existing is not None:
            raise self._refuse(
                case_id,
                actor,
                "already_decided",
                f"narrative {narrative.narrative_id} (version "
                f"{narrative.version}) was already decided "
                f"({existing.outcome.value} by {existing.approver_id}); "
                "a version is decided exactly once — a rejection is "
                "answered by a re-draft, not a second decision",
            )

        standing = self._sar.status_of(narrative)
        if standing != "verified":
            raise self._refuse(
                case_id,
                actor,
                "narrative_not_verified",
                f"narrative {narrative.narrative_id} stands "
                f"{standing!r}, not 'verified'; only a narrative "
                "whose every statement passed the citation "
                "verifier, over the case's current record, may be "
                "decided",
            )

        routing = self._dispositions.get_disposition(narrative.disposition_id)
        if routing is None:
            raise self._refuse(
                case_id,
                actor,
                "routing_disposition_missing",
                f"the disposition {narrative.disposition_id} that "
                "routed this case to SAR drafting is not on record; "
                "dual control cannot be checked, so nothing is decided",
            )
        # Dual control is about persons: the comparisons run on
        # the canonical person id (see dispositions.py), so a
        # re-cased or re-spaced spelling of the dispositioner's
        # or drafter's own id is still that person, whatever role
        # they present at this gate.
        if canonical_person_id(approver) == canonical_person_id(
            routing.analyst_id
        ):
            raise self._refuse(
                case_id,
                actor,
                "approver_is_dispositioner",
                f"{approver} recorded the escalate_sar disposition "
                "that routed this case; Law 2's dual control bars "
                "the dispositioning analyst from approving the "
                "narrative — a second person must decide it",
            )
        if canonical_person_id(approver) == canonical_person_id(
            narrative.drafted_by
        ):
            raise self._refuse(
                case_id,
                actor,
                "approver_is_drafter",
                f"{approver} drafted this narrative; the drafter "
                "cannot approve their own draft — a second person "
                "must decide it",
            )

        codes = list(reason_codes or [])
        if outcome is ApprovalOutcome.REJECTED:
            if not codes:
                raise self._refuse(
                    case_id,
                    actor,
                    "rejection_codes_required",
                    "a rejection requires at least one coded reason "
                    f"from vocabulary {REJECTION_VOCABULARY_VERSION}; "
                    "free text may supplement the codes, never "
                    "replace them — the codes are the drafting "
                    "worklist the narrative goes back with",
                )
            for code in codes:
                if code not in REJECTION_CODES:
                    raise self._refuse(
                        case_id,
                        actor,
                        "unknown_rejection_code",
                        f"rejection code {code!r} is not in "
                        f"vocabulary {REJECTION_VOCABULARY_VERSION}",
                    )
        elif codes:
            raise self._refuse(
                case_id,
                actor,
                "approval_reason_codes_not_applicable",
                "an approval carries no reason codes; codes exist "
                "to say what was wrong in a rejection",
            )

        decided = SarApproval(
            case_id=case_id,
            narrative_id=narrative.narrative_id,
            narrative_version=narrative.version,
            record_id=narrative.record_id,
            record_version=narrative.record_version,
            disposition_id=narrative.disposition_id,
            approver_id=approver,
            approver_role=approver_role,
            outcome=outcome,
            reason_codes=codes if outcome is ApprovalOutcome.REJECTED else [],
            reason_vocabulary_version=(
                REJECTION_VOCABULARY_VERSION
                if outcome is ApprovalOutcome.REJECTED
                else ""
            ),
            note=note,
        )

        if outcome is ApprovalOutcome.APPROVED:
            # The case file is complete. Meet the state machine's
            # closing-token rule at the moment the closure takes
            # effect: the token is minted from the routing
            # disposition (the analyst's recorded file_sar decision),
            # and the approval recorded below is the second person's
            # act that lets it take effect. Nothing is filed.
            self._workflow.transition(
                case_id,
                CaseStatus.FILED_SAR,
                actor=actor,
                disposition=Disposition(
                    analyst=routing.analyst_id,
                    decision="file_sar",
                    reason_code=routing.rationale_codes[0],
                    rationale=(
                        f"SAR narrative {narrative.narrative_id} "
                        f"approved under dual control by {approver}; "
                        "the case file is complete. No SAR is filed "
                        "by this system."
                    ),
                ),
            )

        item = self._evidence.add_item(
            case_id=case_id,
            kind="sar_approval",
            content=decided.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"sar-approval:{decided.approval_id}",
            captured_by=actor,
        )
        final = decided.model_copy(update={"evidence_seq": item.seq})
        self._approvals.add_approval(final)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event=f"sar_narrative_{outcome.value}",
                detail={
                    "approval_id": final.approval_id,
                    "narrative_id": narrative.narrative_id,
                    "narrative_version": str(narrative.version),
                    "disposition_id": narrative.disposition_id,
                    "dispositioning_analyst": routing.analyst_id,
                    "reason_codes": codes,
                    "case_status": self._store.get_case(case_id).status.value,
                },
            )
        )
        logger.info(
            "SAR narrative %s for case %s: %s by %s",
            narrative.narrative_id,
            case_id,
            outcome.value,
            approver,
        )
        return final

    # -- views ----------------------------------------------------------

    def approval_for(
        self, narrative: SarNarrative
    ) -> SarApproval | None:
        return self._approvals.get_approval_for(narrative.narrative_id)

    def current_approval(self, case_id: str) -> SarApproval | None:
        """The decision on the case's current narrative, if any."""
        self._require_case(case_id)
        narratives = self._narratives.list_narratives(case_id)
        if not narratives:
            return None
        return self._approvals.get_approval_for(narratives[-1].narrative_id)

    def history(self, case_id: str) -> list[SarApproval]:
        self._require_case(case_id)
        return self._approvals.list_approvals(case_id)

    def view(self, approval: SarApproval) -> dict:
        return approval.model_dump(mode="json")
