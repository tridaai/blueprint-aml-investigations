"""Regulatory clocks and escalation (R8): Law 6, in code.

Law 6 says filing deadlines are computed from the initial-detection
date in the case record, approaching and breached clocks escalate
visibly, and no-file decisions are documented. This service is
where that happens — there is no other clock in the system, and
nobody's calendar is consulted:

- **The filing clock.** Every case carries one, from the day it
  opens: the SAR initial deadline is ``detected_on`` + 30 calendar
  days, and where the record identifies no subject, FinCEN's outer
  limit — ``detected_on`` + 60 days — governs instead. Whether a
  subject is identified is derived from the record (the alert
  payload's subject facts, or a corroborated screening hit), never
  asserted by an analyst: the move to the outer deadline is a
  coded state of the clock, not a favour granted to a case.

- **The no-file ending.** When the analyst gate records a standing
  closing disposition (a confirmed or effective ``close_no_action``,
  or a ``close_monitor``), the filing clock ends
  ``closed_no_file`` and names that disposition: its coded
  rationale *is* the no-file documentation. A case that reaches a
  terminal state with no disposition anywhere on its record is
  reported as a clock **violation** — the state machine makes it
  unreachable through the gates, so its appearance means the
  record itself is wrong, and the clock says so on its face
  instead of papering over it.

- **The continuing-activity clock.** When a new alert opens for a
  customer with a prior ``filed_sar`` case, intake records a
  continuing-activity link on the new case (an evidence item) and
  a second clock starts: review due at the prior filing
  determination date + 90 days, filing due at + 120, per FinCEN's
  continuing-activity guidance. R9's review workflow answers this
  clock, and the derivation learns the answer here: when a review
  store is attached, a cycle is answered ONLY by a recorded
  review disposition naming that cycle — a file-continuing answer
  leaves the cycle live against the filing deadline until the
  case reaches ``filed_sar``, and a no-file answer ends the cycle
  ``closed_no_file`` and starts the next cycle from its own
  decision date (rolling 90/120, chained by review id). A review
  opened but not dispositioned answers nothing.

- **Escalation.** A clock's state is derived — ``on_track``,
  ``due_soon`` (within seven days), ``due``, ``overdue`` — by pure
  date arithmetic against an ``as_of`` the caller names; the
  computation reads no wall clock, so a board rendered for a date
  is reproducible for that date. The first time a refresh finds a
  clock at ``due`` or ``overdue`` for a deadline, the crossing is
  recorded on the case's evidence chain as a ``clock_escalation``
  event — idempotently: the recorded events are read back before
  any new one is written, and re-computation never duplicates
  one. The escalation queue reads the same derivation: overdue
  first, then due, then due_soon, each entry naming its deadline.
  Satisfied and closed clocks never escalate.

Clocks are derived views over stored facts (case record,
disposition history, evidence chain) — no clock table exists, and
a clock's state is never stored as free text someone could edit.
"""

from __future__ import annotations

from datetime import date, timedelta

from .errors import CaseNotFoundError
from .evidence import EvidenceService
from .logging_config import get_logger
from .models import (
    Alert,
    ApprovalOutcome,
    AuditEvent,
    Case,
    CaseClocks,
    CaseStatus,
    ClockEscalationEvent,
    ClockState,
    ConfirmationOutcome,
    ContinuingActivityClock,
    ContinuingActivityLink,
    ContinuingReview,
    ContinuingReviewDisposition,
    DispositionOutcome,
    DispositionRecord,
    EscalationQueueEntry,
    FilingClock,
    HitStatus,
    ReviewOutcome,
    TERMINAL_STATUSES,
)
from .ports import (
    ApprovalStore,
    CaseStore,
    ContinuingReviewStore,
    DispositionStore,
    ScreeningStore,
)

logger = get_logger(__name__)

#: The regulatory day counts, as data. FinCEN: a SAR is due no
#: later than 30 calendar days after initial detection; if no
#: subject is identified, the bank has up to 60 calendar days in
#: total. Continuing activity on a filed subject is reviewed by
#: day 90 and a continuing SAR is due by day 120.
SAR_INITIAL_DAYS = 30
SAR_OUTER_DAYS = 60
CONTINUING_REVIEW_DAYS = 90
CONTINUING_FILING_DAYS = 120

#: A live clock within this many days of its operative deadline
#: stands ``due_soon`` — close enough to escalate visibly before
#: it breaches.
DUE_SOON_DAYS = 7

#: Evidence kinds this service reads and writes.
LINK_KIND = "continuing_activity_link"
ESCALATION_KIND = "clock_escalation"

#: Queue/board urgency ranks: lower sorts first.
_STATE_RANK = {
    ClockState.OVERDUE: 0,
    ClockState.DUE: 1,
    ClockState.DUE_SOON: 2,
    ClockState.ON_TRACK: 3,
    ClockState.SATISFIED: 4,
    ClockState.CLOSED_NO_FILE: 4,
    ClockState.NOT_APPLICABLE: 5,
}

_LIVE_STATES = frozenset(
    {
        ClockState.ON_TRACK,
        ClockState.DUE_SOON,
        ClockState.DUE,
        ClockState.OVERDUE,
    }
)


# ---------------------------------------------------------------------------
# Pure date arithmetic — the whole of the clock math. No wall clock
# is read anywhere below: every function takes its dates as input.
# ---------------------------------------------------------------------------


def filing_deadlines(detected_on: date) -> tuple[date, date]:
    """(initial, outer) SAR deadlines for an initial-detection date."""
    return (
        detected_on + timedelta(days=SAR_INITIAL_DAYS),
        detected_on + timedelta(days=SAR_OUTER_DAYS),
    )


def continuing_deadlines(determination_on: date) -> tuple[date, date]:
    """(review, filing) deadlines for a filing determination date."""
    return (
        determination_on + timedelta(days=CONTINUING_REVIEW_DAYS),
        determination_on + timedelta(days=CONTINUING_FILING_DAYS),
    )


def live_state(as_of: date, operative_deadline: date) -> ClockState:
    """A live clock's state at ``as_of`` against one deadline."""
    remaining = (operative_deadline - as_of).days
    if remaining < 0:
        return ClockState.OVERDUE
    if remaining == 0:
        return ClockState.DUE
    if remaining <= DUE_SOON_DAYS:
        return ClockState.DUE_SOON
    return ClockState.ON_TRACK


def _time_phrase(days_remaining: int) -> str:
    if days_remaining < 0:
        return f"{-days_remaining} day(s) overdue"
    if days_remaining == 0:
        return "due today"
    return f"in {days_remaining} day(s)"


class RegulatoryClockService:
    """Computes, escalates, and reports the regulatory clocks."""

    def __init__(
        self,
        store: CaseStore,
        screening_store: ScreeningStore,
        dispositions: DispositionStore,
        evidence: EvidenceService,
        approvals: ApprovalStore | None = None,
        review_store: ContinuingReviewStore | None = None,
    ) -> None:
        self._store = store
        self._screening = screening_store
        self._dispositions = dispositions
        self._evidence = evidence
        self._approvals = approvals
        # R9: when a review store is attached, the continuing
        # clock learns its cycles' outcomes from the recorded
        # review dispositions. Without one, the derivation is
        # exactly R8's — reviews change what the clock knows,
        # never how it counts.
        self._reviews = review_store

    # -- derivation helpers -------------------------------------------

    def _require_case(self, case_id: str) -> Case:
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        return case

    def _alert_payload(self, case_id: str) -> Alert | None:
        for item in self._store.list_evidence(case_id):
            if item.kind == "alert_payload":
                content = self._evidence.read_item_content(case_id, item.seq)
                return Alert.model_validate_json(content.decode("utf-8"))
        return None

    def subject_identified(self, case: Case) -> tuple[bool, str]:
        """Whether the case's record identifies a subject, and
        where that was read from. A subject is identified when the
        alert payload names them with a disambiguator (a date of
        birth or a recorded identifier), or when a corroborated
        screening hit — strong, or confirmed — identifies them.
        A bare name is not an identification: it is the namesake
        trap, and the clock keeps the outer deadline."""
        alert = self._alert_payload(case.case_id)
        if alert is not None:
            raw = alert.raw or {}
            name = raw.get("customer_name")
            dob = raw.get("customer_dob")
            identifiers = raw.get("customer_identifiers")
            if isinstance(name, str) and name and (
                (isinstance(dob, str) and bool(dob))
                or (
                    isinstance(identifiers, list)
                    and any(str(i) for i in identifiers)
                )
            ):
                return True, "alert_payload"
        for hit in self._screening.list_hits(case.case_id):
            if hit.strength == "strong" or hit.status is HitStatus.CONFIRMED:
                return True, "screening_hit"
        return False, "none"

    def _no_file_disposition(self, case: Case) -> DispositionRecord | None:
        """The standing no-file decision on a case, if one stands:
        the latest disposition record is a closing outcome
        (``close_no_action`` / ``close_monitor``) that took
        effect — confirmed where confirmation was required, never
        declined — and the case still stands on it (closed, or
        under monitoring). A reopened case's clock is live again:
        the earlier no-file decision is history, superseded in
        effect by the reopened work even before a new disposition
        answers it."""
        if case.status not in (CaseStatus.CLOSED, CaseStatus.MONITORING):
            return None
        records = self._dispositions.list_dispositions(case.case_id)
        if not records:
            return None
        latest = records[-1]
        if latest.outcome not in (
            DispositionOutcome.CLOSE_NO_ACTION,
            DispositionOutcome.CLOSE_MONITOR,
        ):
            return None
        if case.status is CaseStatus.CLOSED and (
            latest.outcome is not DispositionOutcome.CLOSE_NO_ACTION
        ):
            return None
        confirmation = self._dispositions.get_confirmation_for(
            latest.disposition_id
        )
        if confirmation is not None:
            if confirmation.outcome is ConfirmationOutcome.DECLINED:
                return None
        elif latest.requires_confirmation:
            # Recorded but not yet confirmed: the closure has not
            # taken effect (the case stands pending_confirmation),
            # so no no-file decision stands yet.
            return None
        return latest

    def _violations(self, case: Case) -> list[str]:
        """A terminal case with no disposition anywhere on its
        record is a clock violation. The gates make it
        unreachable; the clock reports it rather than hiding it."""
        violations: list[str] = []
        if case.status in TERMINAL_STATUSES:
            documented = (
                case.disposition is not None
                or self._no_file_disposition(case) is not None
            )
            if not documented and self._approvals is not None:
                documented = any(
                    a.outcome is ApprovalOutcome.APPROVED
                    for a in self._approvals.list_approvals(case.case_id)
                )
            if not documented:
                violations.append("terminal_without_disposition")
        return violations

    def filing_determination_date(self, prior: Case) -> date:
        """The date a filed case's determination was made: its
        approval date where an approval record exists, else its
        closing disposition's date, else its last update."""
        if self._approvals is not None:
            approved = [
                a
                for a in self._approvals.list_approvals(prior.case_id)
                if a.outcome is ApprovalOutcome.APPROVED
            ]
            if approved:
                return approved[-1].decided_at.date()
        if prior.disposition is not None:
            return prior.disposition.decided_at.date()
        return prior.updated_at.date()

    # -- the clocks themselves -------------------------------------------

    def filing_clock(self, case: Case, *, as_of: date) -> FilingClock:
        identified, basis = self.subject_identified(case)
        initial, outer = filing_deadlines(case.detected_on)
        operative, kind = (initial, "initial") if identified else (outer, "outer")
        no_file = self._no_file_disposition(case)
        if case.status is CaseStatus.FILED_SAR:
            state, remaining = ClockState.SATISFIED, None
        elif no_file is not None:
            state, remaining = ClockState.CLOSED_NO_FILE, None
        else:
            state = live_state(as_of, operative)
            remaining = (operative - as_of).days
        return FilingClock(
            case_id=case.case_id,
            customer_id=case.customer_id,
            detected_on=case.detected_on,
            subject_identified=identified,
            subject_basis=basis,
            initial_deadline=initial,
            outer_deadline=outer,
            operative_deadline=operative,
            operative_deadline_kind=kind,
            state=state,
            days_remaining=remaining,
            as_of=as_of,
            no_file_disposition_id=(
                no_file.disposition_id if no_file is not None else None
            ),
            no_file_rationale_codes=(
                list(no_file.rationale_codes) if no_file is not None else []
            ),
            no_file_decided_on=(
                no_file.decided_at.date() if no_file is not None else None
            ),
            monitor_review_due_on=(
                no_file.review_due_on if no_file is not None else None
            ),
        )

    def continuing_link_for(self, case_id: str) -> ContinuingActivityLink | None:
        """The continuing-activity link recorded on a case, if a
        clock was started for it (the latest link item wins)."""
        link: ContinuingActivityLink | None = None
        for item in self._store.list_evidence(case_id):
            if item.kind == LINK_KIND:
                content = self._evidence.read_item_content(case_id, item.seq)
                link = ContinuingActivityLink.model_validate_json(
                    content.decode("utf-8")
                )
        return link

    def _continuing_link_seq(self, case_id: str) -> int | None:
        seq: int | None = None
        for item in self._store.list_evidence(case_id):
            if item.kind == LINK_KIND:
                seq = item.seq
        return seq

    # -- continuing-activity cycles (R9) ---------------------------
    #
    # The cycle chain is derived, never stored: cycle 1 starts at
    # the link's determination; every no-file review disposition
    # starts the next cycle at its own decision date, chained by
    # its review id. A cycle is answered ONLY by a recorded review
    # disposition — an opened-but-undispositioned review leaves
    # its cycle exactly as unanswered as if it did not exist.

    def _operative_review(
        self, case_id: str, cycle: int
    ) -> ContinuingReview | None:
        """The review that stands for a cycle: the newest one
        opened for it. A stale review superseded by a fresh one
        for the same cycle does not stand — the replacement does."""
        if self._reviews is None:
            return None
        candidates = [
            r for r in self._reviews.list_reviews(case_id) if r.cycle == cycle
        ]
        if not candidates:
            return None
        return candidates[-1]

    def _review_disposition(
        self, review: ContinuingReview | None
    ) -> ContinuingReviewDisposition | None:
        if review is None or self._reviews is None:
            return None
        return self._reviews.get_review_disposition_for(review.review_id)

    def _cycle_starts(
        self, case: Case, link: ContinuingActivityLink
    ) -> list[tuple[int, date, str | None]]:
        """(cycle, determination, prior_review_id) for every
        cycle, oldest first. A file-continuing disposition starts
        nothing: its cycle stays open against the filing deadline
        until the case files."""
        starts = [(1, link.determination_on, None)]
        cycle = 1
        while True:
            review = self._operative_review(case.case_id, cycle)
            disposition = self._review_disposition(review)
            if (
                disposition is None
                or disposition.outcome
                is not ReviewOutcome.NO_FILE_THIS_CYCLE
            ):
                return starts
            starts.append(
                (
                    cycle + 1,
                    disposition.decided_at.date(),
                    review.review_id if review is not None else None,
                )
            )
            cycle += 1

    def current_cycle(
        self, case: Case
    ) -> tuple[int, date, date, date, str | None] | None:
        """The case's live continuing cycle — (cycle,
        determination, review due, filing due, prior review id) —
        or None when no continuing clock was started. The review
        workflow opens its reviews against exactly this
        descriptor."""
        link = self.continuing_link_for(case.case_id)
        if link is None:
            return None
        cycle, determination, prior_review_id = self._cycle_starts(
            case, link
        )[-1]
        review_due, filing_due = continuing_deadlines(determination)
        return cycle, determination, review_due, filing_due, prior_review_id

    def operative_review(self, case: Case) -> ContinuingReview | None:
        """The review standing for the case's current cycle."""
        current = self.current_cycle(case)
        if current is None:
            return None
        return self._operative_review(case.case_id, current[0])

    def _cycle_clock(
        self,
        case: Case,
        link: ContinuingActivityLink,
        *,
        cycle: int,
        determination_on: date,
        prior_review_id: str | None,
        review: ContinuingReview | None,
        disposition: ContinuingReviewDisposition | None,
        as_of: date,
    ) -> ContinuingActivityClock:
        review_due_on, filing_due_on = continuing_deadlines(
            determination_on
        )
        answered_by = (
            review.review_id
            if disposition is not None and review is not None
            else None
        )
        answered_outcome = (
            disposition.outcome.value if disposition is not None else None
        )
        if (
            disposition is not None
            and disposition.outcome
            is ReviewOutcome.NO_FILE_THIS_CYCLE
        ):
            # Answered and closed on the disposition's coded
            # rationale — the cycle's documentation on the clock.
            if as_of <= review_due_on:
                operative, kind = review_due_on, "continuing_review"
            else:
                operative, kind = filing_due_on, "continuing_filing"
            state, remaining = ClockState.CLOSED_NO_FILE, None
            review_late = as_of > review_due_on
        elif (
            disposition is not None
            and disposition.outcome is ReviewOutcome.FILE_CONTINUING
        ):
            # Answered: a continuing filing is due. The cycle
            # stays live against the filing deadline — and only
            # the filing itself satisfies it.
            operative, kind = filing_due_on, "continuing_filing"
            if case.status is CaseStatus.FILED_SAR:
                state, remaining = ClockState.SATISFIED, None
                review_late = False
            else:
                state = live_state(as_of, filing_due_on)
                remaining = (filing_due_on - as_of).days
                review_late = disposition.decided_at.date() > review_due_on
        else:
            # Unanswered — R8's derivation exactly: the case's own
            # endings close the clock, else it stands live, and a
            # review opened but not dispositioned changes nothing.
            no_file = self._no_file_disposition(case)
            if as_of <= review_due_on:
                operative, kind = review_due_on, "continuing_review"
            else:
                operative, kind = filing_due_on, "continuing_filing"
            if case.status is CaseStatus.FILED_SAR:
                state, remaining = ClockState.SATISFIED, None
            elif no_file is not None:
                state, remaining = ClockState.CLOSED_NO_FILE, None
            else:
                state = live_state(as_of, operative)
                remaining = (operative - as_of).days
            review_late = as_of > review_due_on
        return ContinuingActivityClock(
            case_id=case.case_id,
            prior_case_id=link.prior_case_id,
            customer_id=case.customer_id,
            determination_on=determination_on,
            review_due_on=review_due_on,
            filing_due_on=filing_due_on,
            review_overdue=review_late and state in _LIVE_STATES,
            operative_deadline=operative,
            operative_deadline_kind=kind,
            state=state,
            days_remaining=remaining,
            as_of=as_of,
            link_evidence_seq=self._continuing_link_seq(case.case_id),
            cycle=cycle,
            prior_review_id=prior_review_id,
            answered_by_review_id=answered_by,
            answered_outcome=answered_outcome,
        )

    def continuing_cycles(
        self, case: Case, *, as_of: date
    ) -> list[ContinuingActivityClock]:
        """Every cycle's clock, oldest first — the answered
        cycles with the review that answered them, the live
        cycle last. Empty when no continuing clock was started."""
        link = self.continuing_link_for(case.case_id)
        if link is None:
            return []
        clocks: list[ContinuingActivityClock] = []
        for cycle, determination, prior_review_id in self._cycle_starts(
            case, link
        ):
            review = self._operative_review(case.case_id, cycle)
            clocks.append(
                self._cycle_clock(
                    case,
                    link,
                    cycle=cycle,
                    determination_on=determination,
                    prior_review_id=prior_review_id,
                    review=review,
                    disposition=self._review_disposition(review),
                    as_of=as_of,
                )
            )
        return clocks

    def continuing_clock(
        self, case: Case, *, as_of: date
    ) -> ContinuingActivityClock | None:
        """The case's live (latest) continuing-activity cycle
        clock — the derivation the escalation machinery reads."""
        cycles = self.continuing_cycles(case, as_of=as_of)
        return cycles[-1] if cycles else None

    def case_clocks(self, case_id: str, *, as_of: date) -> CaseClocks:
        case = self._require_case(case_id)
        return CaseClocks(
            case_id=case.case_id,
            customer_id=case.customer_id,
            status=case.status,
            as_of=as_of,
            filing=self.filing_clock(case, as_of=as_of),
            continuing_activity=self.continuing_clock(case, as_of=as_of),
            continuing_history=self.continuing_cycles(case, as_of=as_of),
            escalations=self.recorded_escalations(case_id),
            violations=self._violations(case),
        )

    # -- the continuing-activity trigger (intake) -------------------------

    def record_continuing_link(
        self, case: Case, *, actor: str = "intake-service"
    ) -> ContinuingActivityLink | None:
        """Start a continuing-activity clock for a newly opened
        case: when the case's customer has a prior ``filed_sar``
        case, record the link on the new case's evidence chain.
        Idempotent — a case that already carries a link keeps it,
        and intake's own per-alert idempotency means a re-delivered
        alert never reaches here twice for the same case."""
        if self.continuing_link_for(case.case_id) is not None:
            return self.continuing_link_for(case.case_id)
        priors = [
            c
            for c in self._store.list_cases()
            if c.customer_id == case.customer_id
            and c.case_id != case.case_id
            and c.status is CaseStatus.FILED_SAR
        ]
        if not priors:
            return None
        prior = max(
            priors,
            key=lambda c: (self.filing_determination_date(c), c.case_id),
        )
        determination = self.filing_determination_date(prior)
        review_due, filing_due = continuing_deadlines(determination)
        link = ContinuingActivityLink(
            prior_case_id=prior.case_id,
            customer_id=case.customer_id,
            determination_on=determination,
            review_due_on=review_due,
            filing_due_on=filing_due,
            new_case_detected_on=case.detected_on,
        )
        self._evidence.add_item(
            case_id=case.case_id,
            kind=LINK_KIND,
            content=link.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"continuing-activity:{prior.case_id}",
            captured_by=actor,
        )
        self._store.append_audit(
            AuditEvent(
                case_id=case.case_id,
                actor=actor,
                event="continuing_activity_clock_started",
                detail={
                    "prior_case_id": prior.case_id,
                    "determination_on": determination.isoformat(),
                    "review_due_on": review_due.isoformat(),
                    "filing_due_on": filing_due.isoformat(),
                },
            )
        )
        logger.info(
            "continuing-activity clock started for case %s "
            "(prior case %s, determination %s)",
            case.case_id,
            prior.case_id,
            determination.isoformat(),
        )
        return link

    # -- escalation -------------------------------------------------------

    def recorded_escalations(
        self, case_id: str
    ) -> list[ClockEscalationEvent]:
        """The escalation crossings already recorded on a case's
        chain, in chain order."""
        events: list[ClockEscalationEvent] = []
        for item in self._store.list_evidence(case_id):
            if item.kind == ESCALATION_KIND:
                content = self._evidence.read_item_content(case_id, item.seq)
                events.append(
                    ClockEscalationEvent.model_validate_json(
                        content.decode("utf-8")
                    )
                )
        return events

    def refresh_escalations(
        self, case_id: str, *, as_of: date, actor: str = "clock-service"
    ) -> list[ClockEscalationEvent]:
        """Record any clock crossing this ``as_of`` newly reveals.

        A crossing is a clock standing at ``due`` or ``overdue``
        for a deadline no recorded event names. Recording is a
        write to the case's chain, so a sealed case — always
        terminal, its clocks always ended — simply has nothing to
        record: this method writes only when a live clock crossed,
        and a terminal clock never does."""
        case = self._require_case(case_id)
        clocks: list[tuple[str, object]] = [
            ("filing", self.filing_clock(case, as_of=as_of))
        ]
        continuing = self.continuing_clock(case, as_of=as_of)
        if continuing is not None:
            clocks.append(("continuing_activity", continuing))
        recorded = {
            (e.clock_kind, e.deadline_kind, e.deadline, e.state)
            for e in self.recorded_escalations(case_id)
        }
        fresh: list[ClockEscalationEvent] = []
        for clock_kind, clock in clocks:
            if clock.state not in (ClockState.DUE, ClockState.OVERDUE):
                continue
            # A crossing is (clock, deadline, state): reaching
            # `due` and later `overdue` on the same deadline are
            # two crossings, each recorded once.
            key = (
                clock_kind,
                clock.operative_deadline_kind,
                clock.operative_deadline,
                clock.state.value,
            )
            if key in recorded:
                continue
            event = ClockEscalationEvent(
                case_id=case_id,
                clock_kind=clock_kind,
                deadline_kind=clock.operative_deadline_kind,
                deadline=clock.operative_deadline,
                state=clock.state.value,
                as_of=as_of,
                days_overdue=max(0, -(clock.days_remaining or 0)),
            )
            item = self._evidence.add_item(
                case_id=case_id,
                kind=ESCALATION_KIND,
                content=event.model_dump_json(indent=2).encode("utf-8"),
                source_ref=f"clock-escalation:{event.event_id}",
                captured_by=actor,
            )
            event = event.model_copy(update={"evidence_seq": item.seq})
            self._store.append_audit(
                AuditEvent(
                    case_id=case_id,
                    actor=actor,
                    event="clock_escalated",
                    detail={
                        "event_id": event.event_id,
                        "clock_kind": clock_kind,
                        "deadline_kind": event.deadline_kind,
                        "deadline": event.deadline.isoformat(),
                        "state": event.state,
                        "as_of": as_of.isoformat(),
                    },
                )
            )
            recorded.add(
                (clock_kind, event.deadline_kind, event.deadline, event.state)
            )
            fresh.append(event)
            logger.info(
                "case %s clock escalated: %s %s deadline %s is %s",
                case_id,
                clock_kind,
                event.deadline_kind,
                event.deadline.isoformat(),
                event.state,
            )
        return fresh

    def refresh_all_escalations(
        self, *, as_of: date, actor: str = "clock-service"
    ) -> list[ClockEscalationEvent]:
        """The scheduler tick: refresh every case's clocks,
        recording any new crossings. Returns the events recorded."""
        fresh: list[ClockEscalationEvent] = []
        for case in self._store.list_cases():
            fresh.extend(
                self.refresh_escalations(case.case_id, as_of=as_of, actor=actor)
            )
        return fresh

    # -- board + queue ------------------------------------------------------

    @staticmethod
    def _worst(clocks: CaseClocks) -> tuple[int, int]:
        """(urgency rank, days remaining) of a case's most urgent
        live clock — the board's sort key."""
        candidates = [clocks.filing]
        if clocks.continuing_activity is not None:
            candidates.append(clocks.continuing_activity)
        live = [c for c in candidates if c.state in _LIVE_STATES]
        if not live:
            return (_STATE_RANK[ClockState.SATISFIED], 0)
        worst = min(
            live,
            key=lambda c: (
                _STATE_RANK[c.state],
                c.days_remaining if c.days_remaining is not None else 0,
            ),
        )
        return (
            _STATE_RANK[worst.state],
            worst.days_remaining if worst.days_remaining is not None else 0,
        )

    def clock_board(self, *, as_of: date) -> list[CaseClocks]:
        """Every case's clocks at ``as_of``, most urgent first —
        overdue cases lead, ended clocks settle at the bottom."""
        board = [
            self.case_clocks(case.case_id, as_of=as_of)
            for case in self._store.list_cases()
        ]
        board.sort(key=lambda c: (*self._worst(c), c.case_id))
        return board

    def escalation_queue(self, *, as_of: date) -> list[EscalationQueueEntry]:
        """The clocks standing at due_soon / due / overdue at
        ``as_of`` — overdue first, then due, then due_soon, each
        entry naming the deadline it answers to. Satisfied and
        closed clocks never appear: an ended clock has nothing to
        escalate."""
        entries: list[EscalationQueueEntry] = []
        for case in self._store.list_cases():
            filing = self.filing_clock(case, as_of=as_of)
            continuing = self.continuing_clock(case, as_of=as_of)
            for clock_kind, clock in (
                ("filing", filing),
                ("continuing_activity", continuing),
            ):
                if clock is None or clock.state not in (
                    ClockState.OVERDUE,
                    ClockState.DUE,
                    ClockState.DUE_SOON,
                ):
                    continue
                entries.append(
                    EscalationQueueEntry(
                        case_id=case.case_id,
                        customer_id=case.customer_id,
                        clock_kind=clock_kind,
                        deadline_kind=clock.operative_deadline_kind,
                        deadline=clock.operative_deadline,
                        state=clock.state,
                        days_remaining=(
                            clock.days_remaining
                            if clock.days_remaining is not None
                            else 0
                        ),
                        reason=self._reason(clock_kind, clock),
                    )
                )
        entries.sort(
            key=lambda e: (
                _STATE_RANK[e.state],
                e.days_remaining,
                e.case_id,
                e.clock_kind,
            )
        )
        return entries

    @staticmethod
    def _reason(clock_kind: str, clock) -> str:
        phrase = _time_phrase(clock.days_remaining or 0)
        if clock_kind == "filing":
            if clock.operative_deadline_kind == "initial":
                label = (
                    f"SAR filing deadline {clock.operative_deadline} "
                    "(30-day initial deadline)"
                )
            else:
                label = (
                    f"SAR filing deadline {clock.operative_deadline} "
                    "(60-day outer deadline — no subject identified)"
                )
        elif clock.operative_deadline_kind == "continuing_review":
            label = (
                f"continuing-activity review deadline "
                f"{clock.operative_deadline} (90 days from the prior "
                "filing determination)"
            )
        else:
            label = (
                f"continuing-activity filing deadline "
                f"{clock.operative_deadline} (120 days from the prior "
                "filing determination)"
            )
        return f"{label} — {phrase}"
