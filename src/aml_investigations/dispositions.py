"""The disposition gate (R5): Law 1, with depth.

R1 gave the state machine its closing token — no case closes
without a named analyst's disposition. R5 builds the gate itself:
the service an analyst's decision passes through before it moves a
case anywhere.

A disposition here is an artefact, not a form field:

- **A named human, mechanically.** Analyst id and a coded role are
  required; blank, anonymous, and service/system actors are refused
  before anything else is looked at. The agent — any agent — cannot
  disposition a case, including by borrowing this service.
- **A current investigation record (R4).** No record, no
  disposition; and the disposition must cite the record id *and
  version* it relied on, which must be the case's current record.
  When a newer record version later supersedes the cited one, the
  case is flagged ``DISPOSITION_STALE`` — the decision's basis has
  moved, visibly, until a fresh disposition answers it.
- **Coded rationale, from a versioned vocabulary.** Every outcome
  carries its own set of reason codes; at least one code is
  mandatory. Free text (the note) may supplement the codes, never
  substitute for them.
- **The sanctions posture (Law 3) binds here too.** The same
  unresolved-hits definition the workflow's close guard uses
  refuses close_no_action and close_monitor at this gate; the
  lawful exits are escalate_sar, escalate_l2, or
  request_more_evidence (or an analyst clearing the hit first).
- **Dual control on adverse closures.** A close_no_action over an
  adverse hypothesis (anything but ``no_adverse_pattern``) does not
  close the case: it parks it in ``pending_confirmation`` until an
  L2 reviewer — a different named analyst — confirms. The
  dispositioning analyst confirming their own closure is refused
  mechanically. Identity is compared as a person, not as a string:
  ids compare in canonical form (case-folded, whitespace
  collapsed — ``canonical_person_id``), so re-casing or re-spacing
  one's own id does not mint a "second person". A decline sends
  the case back to investigation.

Every disposition and confirmation is stored append-only *and*
captured as a hash-chained evidence item on the case, so the
gate's history sits on the same chain-of-custody as the evidence
it judged. State moves go through the case workflow — the
transition table remains the single source of which moves exist.
"""

from __future__ import annotations

import threading
from datetime import timedelta

from .errors import CaseNotFoundError, DispositionRefusedError
from .evidence import EvidenceService, ensure_case_mutable
from .logging_config import get_logger
from .models import (
    AuditEvent,
    Case,
    CaseStatus,
    ConfirmationOutcome,
    Disposition,
    DispositionConfirmation,
    DispositionOutcome,
    DispositionRecord,
)
from .ports import (
    CaseStore,
    DispositionStore,
    InvestigationStore,
    ScreeningStore,
    SealStore,
)
from .workflow import CaseWorkflow, unresolved_sanctions_hits

logger = get_logger(__name__)

#: Case flag raised when an investigation record supersedes the
#: version a standing disposition relied on.
FLAG_DISPOSITION_STALE = "DISPOSITION_STALE"

#: The rationale vocabulary's version. A disposition records the
#: version it was coded under, so a later vocabulary revision never
#: silently re-reads an old decision.
RATIONALE_VOCABULARY_VERSION = "2026.10.1"

#: The coded analyst roles. Dispositions may be recorded by any of
#: them; confirmations only by the L2 role.
ANALYST_ROLES = frozenset({"analyst", "senior_analyst", "l2_reviewer"})
L2_ROLE = "l2_reviewer"

def canonical_person_id(person_id: str) -> str:
    """The canonical form of a person id — the identity the gates
    compare. Person ids are hand-typed at the console, the CLI, and
    the API, and the same person types theirs differently from one
    sitting to the next ('E.Okafor', ' e.okafor ', 'e.  okafor').
    Dual control is about persons, not strings: two spellings of
    one id are one person, and a raw string comparison would let
    a dispositioning analyst confirm their own closure — or
    approve their own narrative — by re-casing their id. Every
    identity comparison in the gates (this module and the SAR
    approval gate) is made on this form: stripped, internal
    whitespace collapsed, case-folded. The id is still *recorded*
    exactly as presented; only comparison canonicalises."""
    return " ".join((person_id or "").split()).casefold()


#: Actors that are the system, not a person. A disposition from one
#: of these is refused as anonymous_or_system_actor — the gate is a
#: human gate, and services route work; they never decide it.
SYSTEM_ACTORS = frozenset(
    {
        "system",
        "agent",
        "anonymous",
        "unknown",
        "none",
        "aml-agent",
        "intake-service",
        "screening-service",
        "typology-service",
        "investigation-service",
    }
)

#: Coded rationale per outcome. Free text supplements; codes decide.
RATIONALE_CODES: dict[DispositionOutcome, frozenset[str]] = {
    DispositionOutcome.CLOSE_NO_ACTION: frozenset(
        {
            "BENIGN_EXPLANATION_DOCUMENTED",
            "ACTIVITY_CONSISTENT_WITH_PROFILE",
            "NAMESAKE_FALSE_POSITIVE",
            "NO_SUSPICIOUS_ACTIVITY_IDENTIFIED",
            "DUPLICATE_ALERT_ALREADY_DECIDED",
        }
    ),
    DispositionOutcome.CLOSE_MONITOR: frozenset(
        {
            "PATTERN_EXPLAINED_MONITOR_ACTIVITY",
            "CUSTOMER_RISK_ELEVATED_UNRESOLVED",
            "EMERGING_PATTERN_WATCH",
        }
    ),
    DispositionOutcome.ESCALATE_SAR: frozenset(
        {
            "STRUCTURING_SUSPECTED",
            "SANCTIONS_MATCH_SUSPECTED",
            "FUNNEL_OR_CONDUIT_SUSPECTED",
            "ACTIVITY_UNEXPLAINED",
            "OTHER_SUSPICIOUS_ACTIVITY",
        }
    ),
    DispositionOutcome.ESCALATE_L2: frozenset(
        {
            "POLICY_EXCEPTION_REQUIRED",
            "HIGH_VALUE_OR_COMPLEX",
            "CONFLICTING_EVIDENCE",
            "SANCTIONS_HIT_UNRESOLVED",
        }
    ),
    DispositionOutcome.REQUEST_MORE_EVIDENCE: frozenset(
        {
            "SOURCE_OF_FUNDS_MISSING",
            "IDENTIFICATION_MISSING",
            "TRANSACTION_RECORDS_INCOMPLETE",
            "PROFILE_BASELINE_MISSING",
            "SCREENING_NOT_RUN",
        }
    ),
}

#: The named evidence types a request_more_evidence disposition may
#: ask for — the R4 open-question vocabulary, so a request and the
#: record's own open questions speak the same names.
EVIDENCE_TYPES = frozenset(
    {
        "source_of_funds_documentation",
        "customer_documentation",
        "customer_identification_documentation",
        "screening_run",
        "typology_run",
        "transaction_records",
        "account_profile",
    }
)

#: Where each outcome takes the case (close_no_action is special: it
#: lands in pending_confirmation when the hypothesis is adverse).
_OUTCOME_TARGETS = {
    DispositionOutcome.CLOSE_MONITOR: CaseStatus.MONITORING,
    DispositionOutcome.ESCALATE_SAR: CaseStatus.SAR_PENDING,
    DispositionOutcome.ESCALATE_L2: CaseStatus.ESCALATED,
    DispositionOutcome.REQUEST_MORE_EVIDENCE: CaseStatus.INVESTIGATING,
}


def flag_dispositions_stale(
    store: CaseStore,
    dispositions: DispositionStore,
    case_id: str,
    *,
    current_record_version: int,
    actor: str,
) -> list[str]:
    """Flag a case DISPOSITION_STALE when a record version newer
    than the one a standing disposition relied on now exists.

    Called by the investigation graph when it persists a new record
    version (R4's persist step): the disposition's basis has moved,
    and the case says so on its face until a fresh disposition —
    which must cite the current record — answers it. Returns the
    stale disposition ids.
    """
    stale = [
        d.disposition_id
        for d in dispositions.list_dispositions(case_id)
        if d.record_version < current_record_version
    ]
    if not stale:
        return []
    case = store.get_case(case_id)
    if case is None or FLAG_DISPOSITION_STALE in case.flags:
        return stale
    case.flags = [*case.flags, FLAG_DISPOSITION_STALE]
    store.update_case(case)
    store.append_audit(
        AuditEvent(
            case_id=case_id,
            actor=actor,
            event="disposition_stale_flagged",
            detail={
                "current_record_version": str(current_record_version),
                "stale_disposition_ids": stale,
            },
        )
    )
    return stale


class DispositionService:
    """Records dispositions and confirmations at the analyst gate."""

    def __init__(
        self,
        store: CaseStore,
        screening_store: ScreeningStore,
        records: InvestigationStore,
        dispositions: DispositionStore,
        evidence: EvidenceService,
        workflow: CaseWorkflow,
        seal_store: SealStore | None = None,
    ) -> None:
        self._store = store
        self._screening = screening_store
        self._records = records
        self._dispositions = dispositions
        self._evidence = evidence
        self._workflow = workflow
        self._seals = seal_store
        # R19: the gate's acts are check-then-act sequences (read
        # the case, run the gate's checks, transition, record).
        # Two concurrent submissions could both read the pre-gate
        # state and both land — two dispositions for one gate
        # pass. The acts serialise on this lock within the app
        # process; the loser then re-reads the case under the
        # lock and meets the gate's own refusal.
        self._gate_lock = threading.RLock()

    # -- refusals -----------------------------------------------------

    def _refuse(
        self, case_id: str, actor: str, reason: str, message: str
    ) -> DispositionRefusedError:
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="disposition_refused",
                detail={"reason": reason, "message": message},
            )
        )
        return DispositionRefusedError(reason, message)

    def _require_case(self, case_id: str) -> Case:
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        return case

    def _validate_identity(
        self, case_id: str, actor_id: str, role: str, *, who: str
    ) -> None:
        """The gate is a human gate: a named person with a coded role."""
        actor = actor_id or ""
        if not actor.strip() or canonical_person_id(actor) in SYSTEM_ACTORS:
            raise self._refuse(
                case_id,
                actor or "anonymous",
                "anonymous_or_system_actor",
                f"{who} must be a named analyst; {actor_id!r} is "
                "anonymous or a system actor, and the system never "
                "dispositions a case",
            )
        if role not in ANALYST_ROLES:
            raise self._refuse(
                case_id,
                actor,
                "unknown_role",
                f"{who} role {role!r} is not in the coded role "
                f"vocabulary ({', '.join(sorted(ANALYST_ROLES))})",
            )

    # -- dispositions ---------------------------------------------------

    def record_disposition(
        self,
        case_id: str,
        *,
        analyst_id: str,
        analyst_role: str,
        outcome: DispositionOutcome,
        rationale_codes: list[str],
        record_id: str,
        record_version: int,
        note: str = "",
        review_period_days: int | None = None,
        missing_evidence: list[str] | None = None,
    ) -> DispositionRecord:
        """Record one analyst disposition at the gate. The act is
        serialised on the service's gate lock (R19): a concurrent
        duplicate submission lands exactly once, and the second
        caller meets the gate's refusal over the landed state."""
        with self._gate_lock:
            return self._record_disposition(
                case_id,
                analyst_id=analyst_id,
                analyst_role=analyst_role,
                outcome=outcome,
                rationale_codes=rationale_codes,
                record_id=record_id,
                record_version=record_version,
                note=note,
                review_period_days=review_period_days,
                missing_evidence=missing_evidence,
            )

    def _record_disposition(
        self,
        case_id: str,
        *,
        analyst_id: str,
        analyst_role: str,
        outcome: DispositionOutcome,
        rationale_codes: list[str],
        record_id: str,
        record_version: int,
        note: str = "",
        review_period_days: int | None = None,
        missing_evidence: list[str] | None = None,
    ) -> DispositionRecord:
        case = self._require_case(case_id)
        ensure_case_mutable(self._seals, case_id)
        actor = f"analyst:{analyst_id}"
        self._validate_identity(case_id, analyst_id, analyst_role, who="analyst")

        if case.status is not CaseStatus.AWAITING_ANALYST:
            raise self._refuse(
                case_id,
                actor,
                "case_not_awaiting_analyst",
                f"case is {case.status.value}; a disposition is "
                "recorded at the analyst gate (awaiting_analyst), "
                "over a completed investigation record",
            )

        if not rationale_codes:
            raise self._refuse(
                case_id,
                actor,
                "rationale_codes_required",
                "a disposition requires at least one coded rationale "
                f"from vocabulary {RATIONALE_VOCABULARY_VERSION}; "
                "free text may supplement the codes, never replace them",
            )
        allowed_codes = RATIONALE_CODES[outcome]
        for code in rationale_codes:
            if code not in allowed_codes:
                raise self._refuse(
                    case_id,
                    actor,
                    "unknown_rationale_code",
                    f"rationale code {code!r} is not in the "
                    f"{outcome.value} set of vocabulary "
                    f"{RATIONALE_VOCABULARY_VERSION}",
                )

        if outcome is DispositionOutcome.CLOSE_MONITOR:
            if review_period_days is None or not (1 <= review_period_days <= 365):
                raise self._refuse(
                    case_id,
                    actor,
                    "missing_review_period",
                    "close_monitor requires a review period of "
                    "1..365 days — monitoring without a review date "
                    "is not monitoring",
                )
        if outcome is DispositionOutcome.REQUEST_MORE_EVIDENCE:
            missing = list(missing_evidence or [])
            if not missing:
                raise self._refuse(
                    case_id,
                    actor,
                    "missing_evidence_required",
                    "request_more_evidence must name the evidence "
                    "types the case still needs",
                )
            for evidence_type in missing:
                if evidence_type not in EVIDENCE_TYPES:
                    raise self._refuse(
                        case_id,
                        actor,
                        "unknown_evidence_type",
                        f"evidence type {evidence_type!r} is not in "
                        "the open-question vocabulary",
                    )

        history = self._records.list_investigation_records(case_id)
        current = history[-1] if history else None
        if current is None:
            raise self._refuse(
                case_id,
                actor,
                "no_investigation_record",
                "the case holds no investigation record; there is "
                "nothing for a disposition to rely on",
            )
        if record_id != current.record_id or record_version != current.version:
            raise self._refuse(
                case_id,
                actor,
                "record_citation_not_current",
                f"disposition cites record {record_id} version "
                f"{record_version}, but the case's current record "
                f"is {current.record_id} version {current.version}; "
                "a disposition relies on the current record or none",
            )

        if outcome in (
            DispositionOutcome.CLOSE_NO_ACTION,
            DispositionOutcome.CLOSE_MONITOR,
        ):
            unresolved = unresolved_sanctions_hits(self._screening, case_id)
            if unresolved:
                raise self._refuse(
                    case_id,
                    actor,
                    "unresolved_sanctions_hit",
                    "unresolved sanctions hit(s) "
                    + ", ".join(h.hit_id for h in unresolved)
                    + f" block {outcome.value}: the lawful outcomes "
                    "are escalate_sar, escalate_l2, or "
                    "request_more_evidence, or an analyst clears "
                    "the hit with a recorded reason first",
                )

        adverse = current.hypothesis.label != "no_adverse_pattern"
        requires_confirmation = (
            outcome is DispositionOutcome.CLOSE_NO_ACTION and adverse
        )
        decided = DispositionRecord(
            case_id=case_id,
            analyst_id=analyst_id,
            analyst_role=analyst_role,
            outcome=outcome,
            rationale_codes=list(rationale_codes),
            rationale_vocabulary_version=RATIONALE_VOCABULARY_VERSION,
            note=note,
            record_id=current.record_id,
            record_version=current.version,
            requires_confirmation=requires_confirmation,
            review_period_days=(
                review_period_days
                if outcome is DispositionOutcome.CLOSE_MONITOR
                else None
            ),
            missing_evidence=(
                list(missing_evidence or [])
                if outcome is DispositionOutcome.REQUEST_MORE_EVIDENCE
                else []
            ),
        )
        if decided.review_period_days is not None:
            decided = decided.model_copy(
                update={
                    "review_due_on": (
                        decided.decided_at.date()
                        + timedelta(days=decided.review_period_days)
                    )
                }
            )

        # Drive the case along the workflow's edges — the table, not
        # this service, decides which moves exist.
        if outcome is DispositionOutcome.CLOSE_NO_ACTION:
            if requires_confirmation:
                self._workflow.transition(
                    case_id, CaseStatus.PENDING_CONFIRMATION, actor=actor
                )
            else:
                self._workflow.transition(
                    case_id,
                    CaseStatus.CLOSED,
                    actor=actor,
                    disposition=Disposition(
                        analyst=analyst_id,
                        decision="close",
                        reason_code=decided.rationale_codes[0],
                        rationale=note,
                    ),
                )
        elif outcome is DispositionOutcome.ESCALATE_L2:
            self._workflow.transition(
                case_id,
                _OUTCOME_TARGETS[outcome],
                actor=actor,
                disposition=Disposition(
                    analyst=analyst_id,
                    decision="escalate",
                    reason_code=decided.rationale_codes[0],
                    rationale=note,
                ),
            )
        else:
            self._workflow.transition(
                case_id, _OUTCOME_TARGETS[outcome], actor=actor
            )

        # The decision joins the chain-of-custody, then the record.
        item = self._evidence.add_item(
            case_id=case_id,
            kind="disposition",
            content=decided.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"disposition:{decided.disposition_id}",
            captured_by=actor,
        )
        final = decided.model_copy(update={"evidence_seq": item.seq})
        self._dispositions.add_disposition(final)
        self._clear_stale_flag(case_id)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="disposition_recorded",
                detail={
                    "disposition_id": final.disposition_id,
                    "outcome": outcome.value,
                    "rationale_codes": list(rationale_codes),
                    "record_id": current.record_id,
                    "record_version": str(current.version),
                    "requires_confirmation": str(requires_confirmation),
                    "case_status": self._store.get_case(case_id).status.value,
                },
            )
        )
        logger.info(
            "disposition recorded for case %s: %s (%s)",
            case_id,
            final.disposition_id,
            outcome.value,
        )
        return final

    # -- confirmations --------------------------------------------------

    def confirm_disposition(
        self,
        case_id: str,
        *,
        confirmer_id: str,
        confirmer_role: str,
        outcome: ConfirmationOutcome,
        note: str = "",
    ) -> DispositionConfirmation:
        """Confirm (or decline) a pending adverse closure. Same
        serialisation as the disposition act (R19): a concurrent
        duplicate confirmation lands exactly once."""
        with self._gate_lock:
            return self._confirm_disposition(
                case_id,
                confirmer_id=confirmer_id,
                confirmer_role=confirmer_role,
                outcome=outcome,
                note=note,
            )

    def _confirm_disposition(
        self,
        case_id: str,
        *,
        confirmer_id: str,
        confirmer_role: str,
        outcome: ConfirmationOutcome,
        note: str = "",
    ) -> DispositionConfirmation:
        case = self._require_case(case_id)
        ensure_case_mutable(self._seals, case_id)
        actor = f"analyst:{confirmer_id}"
        self._validate_identity(
            case_id, confirmer_id, confirmer_role, who="confirmer"
        )
        pending = self.pending_disposition(case_id)
        if case.status is not CaseStatus.PENDING_CONFIRMATION or pending is None:
            raise self._refuse(
                case_id,
                actor,
                "no_pending_confirmation",
                f"case is {case.status.value} and holds no "
                "disposition awaiting confirmation",
            )
        if confirmer_role != L2_ROLE:
            raise self._refuse(
                case_id,
                actor,
                "confirmer_role_not_l2",
                f"confirmation is second-line work: the confirmer's "
                f"role must be {L2_ROLE}, not {confirmer_role}",
            )
        if canonical_person_id(confirmer_id) == canonical_person_id(
            pending.analyst_id
        ):
            raise self._refuse(
                case_id,
                actor,
                "self_confirmation",
                "the analyst who dispositioned a case cannot confirm "
                "their own closure — dual control means a second "
                "person, and identity is the person id in canonical "
                "form, not the exact string it was typed as",
            )

        if outcome is ConfirmationOutcome.CONFIRMED:
            self._workflow.transition(
                case_id,
                CaseStatus.CLOSED,
                actor=actor,
                disposition=Disposition(
                    analyst=pending.analyst_id,
                    decision="close",
                    reason_code=pending.rationale_codes[0],
                    rationale=pending.note,
                ),
            )
        else:
            self._workflow.transition(
                case_id, CaseStatus.INVESTIGATING, actor=actor
            )

        confirmation = DispositionConfirmation(
            disposition_id=pending.disposition_id,
            case_id=case_id,
            confirmer_id=confirmer_id,
            confirmer_role=confirmer_role,
            outcome=outcome,
            note=note,
        )
        item = self._evidence.add_item(
            case_id=case_id,
            kind="disposition_confirmation",
            content=confirmation.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"confirmation:{confirmation.confirmation_id}",
            captured_by=actor,
        )
        final = confirmation.model_copy(update={"evidence_seq": item.seq})
        self._dispositions.add_confirmation(final)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event=f"disposition_{outcome.value}",
                detail={
                    "disposition_id": pending.disposition_id,
                    "confirmation_id": final.confirmation_id,
                    "dispositioning_analyst": pending.analyst_id,
                    "case_status": self._store.get_case(case_id).status.value,
                },
            )
        )
        logger.info(
            "disposition %s for case %s: %s",
            outcome.value,
            case_id,
            pending.disposition_id,
        )
        return final

    # -- views ------------------------------------------------------------

    def status_of(self, record: DispositionRecord) -> str:
        """A disposition's derived standing: superseded (a later
        disposition exists), confirmed / declined (a confirmation
        answers it), pending_confirmation, or effective."""
        siblings = self._dispositions.list_dispositions(record.case_id)
        key = (record.decided_at, record.disposition_id)
        if any(
            (s.decided_at, s.disposition_id) > key
            for s in siblings
            if s.disposition_id != record.disposition_id
        ):
            return "superseded"
        confirmation = self._dispositions.get_confirmation_for(
            record.disposition_id
        )
        if confirmation is not None:
            return confirmation.outcome.value
        if record.requires_confirmation:
            return "pending_confirmation"
        return "effective"

    def view(self, record: DispositionRecord) -> dict:
        """The record as JSON, with its derived standing attached."""
        body = record.model_dump(mode="json")
        body["status"] = self.status_of(record)
        return body

    def history(self, case_id: str) -> list[DispositionRecord]:
        self._require_case(case_id)
        return self._dispositions.list_dispositions(case_id)

    def confirmations(self, case_id: str) -> list[DispositionConfirmation]:
        self._require_case(case_id)
        return self._dispositions.list_confirmations(case_id)

    def pending_disposition(self, case_id: str) -> DispositionRecord | None:
        for record in self._dispositions.list_dispositions(case_id):
            if self.status_of(record) == "pending_confirmation":
                return record
        return None

    def confirmation_queue(self) -> list[dict]:
        """Cases parked at pending_confirmation, with the disposition
        that waits there — the L2 reviewer's worklist."""
        queue = []
        for case in self._store.list_cases(CaseStatus.PENDING_CONFIRMATION.value):
            pending = self.pending_disposition(case.case_id)
            queue.append(
                {
                    "case": case.model_dump(mode="json"),
                    "disposition": (
                        self.view(pending) if pending is not None else None
                    ),
                }
            )
        return queue

    def escalation_queue(self) -> list[dict]:
        """Cases standing escalated or SAR-pending, with their latest
        disposition — the second line's and the SAR queue's worklist."""
        queue = []
        for status in (CaseStatus.ESCALATED, CaseStatus.SAR_PENDING):
            for case in self._store.list_cases(status.value):
                records = self._dispositions.list_dispositions(case.case_id)
                latest = records[-1] if records else None
                queue.append(
                    {
                        "case": case.model_dump(mode="json"),
                        "disposition": (
                            self.view(latest) if latest is not None else None
                        ),
                    }
                )
        return queue

    # -- internals ---------------------------------------------------------

    def _clear_stale_flag(self, case_id: str) -> None:
        case = self._store.get_case(case_id)
        if case is not None and FLAG_DISPOSITION_STALE in case.flags:
            case.flags = [
                f for f in case.flags if f != FLAG_DISPOSITION_STALE
            ]
            self._store.update_case(case)
