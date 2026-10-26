"""Management reporting (R17) — Law 8's payoff, derived in code.

Everything in this module is a read-model: the pack and its
sections are computed from stored artefacts at a named ``as_of``
and nothing here writes to any store. The discipline is the
clocks' (R8) and the profile views' (R11): pure derivations over
the record, reproducible for the date they name, with the pack
content-addressed so a reported figure can be pinned and
rebuilt byte-for-byte from the same artefacts.

The four sections:

- **Queue ageing** — open cases by status x age bucket, ageing
  by monitoring rule and severity, the oldest cases, and the two
  queues that wait on named humans (pending confirmations and
  SAR-pending cases) aged separately, with the wait's recorded
  actors named from the artefacts themselves.
- **Clock board** — the R8 clocks portfolio-wide: filing and
  continuing-activity clocks by state, the overdue list, and
  deadline performance over a window. A documented no-file
  decision recorded after its deadline counts as LATE here —
  the documentation stands, and so does the lateness (the R15
  rule, carried into reporting unchanged).
- **Rubber-stamp metrics** — Law 8 measured: how investigation
  records moved between the first composed draft and the record
  version the disposition was decided on (over the stored
  per-version diffs); how SAR narratives moved between first
  draft and approved version (text identity, then a normalised
  edit distance in bands); how second persons answered adverse
  closures at the confirmation gate; and decision-latency
  distributions at the three gates. Measurements only: the
  section states what it measures and what it cannot, and
  scores nobody.
- **Operations** — typology finding volume by check and
  rule-pack version, screening outcomes by list version (with
  namesake clearances counted separately), quarantine counts by
  pattern family, the media band distribution, and model spend
  from the priced ledger (R13).
"""

from __future__ import annotations

import difflib
import hashlib
import json
from collections import Counter, defaultdict
from datetime import date, datetime
from decimal import Decimal

from .clocks import RegulatoryClockService
from .logging_config import get_logger
from .models import (
    TERMINAL_STATUSES,
    AgeingRow,
    ApprovalOutcome,
    Case,
    CaseStatus,
    ClockBoardReport,
    ClockState,
    ConfirmationOutcome,
    ConfirmationRateRow,
    DeadlinePerformance,
    DeadlinePerformanceEntry,
    DecisionTimeRow,
    DispositionOutcome,
    HitStatus,
    MediaBand,
    NarrativeRevisionRow,
    OldestCase,
    OpsReport,
    OverdueClockEntry,
    QuarantineOps,
    QueueAgeingReport,
    RecordRevisionRow,
    ReportPack,
    ReviewOutcome,
    RubberStampReport,
    ScreeningOpsRow,
    SpendRow,
    TypologyOpsRow,
    WaitingEntry,
)
from .ports import (
    ApprovalStore,
    CaseStore,
    ContinuingReviewStore,
    DispositionStore,
    InvestigationStore,
    MediaStore,
    ModelLedgerStore,
    SarNarrativeStore,
    ScreeningStore,
    TypologyStore,
)

logger = get_logger(__name__)

#: The report pack's own version. The derivations are governed
#: like the vocabularies: a changed derivation is a new version,
#: never a silent change to what a figure means.
REPORT_PACK_VERSION = "2026.10.1"

#: Age buckets for the ageing section: (label, max age in days).
AGE_BUCKETS: list[tuple[str, int | None]] = [
    ("0-7", 7),
    ("8-30", 30),
    ("31-60", 60),
    ("61-90", 90),
    ("91+", None),
]

#: Narrative edit-distance bands: (label, max distance). The
#: distance is 1 - difflib's SequenceMatcher ratio over the two
#: rendered texts — a stated, reproducible measure, not a
#: judgement of how much the words mattered.
EDIT_BANDS: list[tuple[str, float]] = [
    ("none", 0.0),
    ("light", 0.10),
    ("moderate", 0.35),
    ("heavy", 1.0),
]

#: The namesake clearance reason (R2): a name match a
#: contradicting date of birth cleared at match time.
NAMESAKE_CLEAR_REASON = "date_of_birth_mismatch"

_MEASURES = [
    "record revisions: findings added / removed / changed and "
    "hypothesis moves between the first composed investigation "
    "record and the record version the case's latest disposition "
    "was decided on, summed over the diffs stored on each record "
    "version (R4) — it measures how much the assembled work moved "
    "before a person decided on it",
    "narrative revisions: whether the approved SAR narrative's "
    "rendered text is identical to the first draft's, and if not, "
    "a normalised edit distance (1 - difflib SequenceMatcher "
    "ratio) in stated bands — it measures how much drafting a "
    "second person let stand",
    "confirmations: of the adverse closures that required a "
    "second person (R5), how many that person confirmed, "
    "declined, or has not yet answered; a confirmation cannot "
    "modify the disposition it answers, so the note's presence "
    "is reported as the only recorded trace of engagement "
    "beyond the act itself",
    "decision times: hours between the artefact a gate decided "
    "on (the cited investigation record, the disposition, the "
    "narrative draft) and the decision recorded against it, "
    "per deciding actor, as median and p90 (nearest-rank)",
]

_CANNOT_MEASURE = [
    "whether an analyst read the underlying evidence — the "
    "records show artefacts changing or not changing, never "
    "attention",
    "whether a decision was right — outcomes are coded acts; "
    "correctness is an examination finding, not a count",
    "case difficulty — a fast decision on a thin case and a "
    "slow one on a hard case have the same shape here, so no "
    "figure in this section ranks or scores a person",
]


def _bucket_for(age_days: int) -> str:
    for label, cap in AGE_BUCKETS:
        if cap is None or age_days <= cap:
            return label
    return AGE_BUCKETS[-1][0]  # pragma: no cover - loop always returns


def _empty_buckets() -> dict[str, int]:
    return {label: 0 for label, _ in AGE_BUCKETS}


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def _p90(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = -(-9 * len(ordered) // 10)  # ceil(0.9 * n), 1-indexed
    return ordered[max(rank, 1) - 1]


def _hours_between(start: datetime, end: datetime) -> float | None:
    hours = (end - start).total_seconds() / 3600.0
    return hours if hours >= 0 else None


def _edit_band(distance: float) -> str:
    for label, cap in EDIT_BANDS:
        if distance <= cap:
            return label
    return EDIT_BANDS[-1][0]  # pragma: no cover - loop always returns


class ReportingService:
    """Builds the management report pack from stored artefacts.

    The service holds store ports and the clock service — the
    same artefacts the gates wrote and the same clock derivation
    the board serves (R8) — and no write path of any kind.
    """

    def __init__(
        self,
        store: CaseStore,
        clocks: RegulatoryClockService,
        *,
        screening_store: ScreeningStore,
        typology_store: TypologyStore,
        investigation_store: InvestigationStore,
        disposition_store: DispositionStore,
        narrative_store: SarNarrativeStore,
        approval_store: ApprovalStore,
        review_store: ContinuingReviewStore,
        media_store: MediaStore,
        ledger_store: ModelLedgerStore,
        quarantine=None,
    ) -> None:
        self._store = store
        self._clocks = clocks
        self._screening = screening_store
        self._typologies = typology_store
        self._investigations = investigation_store
        self._dispositions = disposition_store
        self._narratives = narrative_store
        self._approvals = approval_store
        self._reviews = review_store
        self._media = media_store
        self._ledger = ledger_store
        self._quarantine = quarantine

    # -- the pack -----------------------------------------------------

    def build_pack(
        self,
        *,
        as_of: date,
        window_start: date | None = None,
        window_end: date | None = None,
    ) -> ReportPack:
        """The full pack at ``as_of``. ``window_end`` defaults to
        ``as_of``; ``window_start`` unset means the performance
        window reaches back over all recorded history."""
        window_end = window_end or as_of
        cases = self._store.list_cases()
        inputs: Counter = Counter()
        inputs["cases"] = len(cases)
        ageing = self._queue_ageing(cases, as_of=as_of)
        board = self._clock_board(
            cases,
            as_of=as_of,
            window_start=window_start,
            window_end=window_end,
            inputs=inputs,
        )
        rubber = self._rubber_stamp(cases, as_of=as_of, inputs=inputs)
        ops = self._ops(cases, as_of=as_of, inputs=inputs)
        pack = ReportPack(
            report_version=REPORT_PACK_VERSION,
            as_of=as_of,
            window_start=window_start,
            window_end=window_end,
            inputs=dict(sorted(inputs.items())),
            queue_ageing=ageing,
            clock_board=board,
            rubber_stamp=rubber,
            ops=ops,
        )
        blob = json.dumps(
            pack.model_dump(mode="json", exclude={"pack_id", "content_hash"}),
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256(blob).hexdigest()
        pack.content_hash = digest
        pack.pack_id = f"rep-{digest[:16]}"
        logger.info(
            "report pack built",
            extra={
                "event": "report_pack_built",
                "pack_id": pack.pack_id,
                "as_of": as_of.isoformat(),
                "cases": len(cases),
            },
        )
        return pack

    # -- queue ageing ---------------------------------------------------

    def _queue_ageing(self, cases: list[Case], *, as_of: date) -> QueueAgeingReport:
        open_cases = [c for c in cases if c.status not in TERMINAL_STATUSES]

        def rows_for(key_of) -> list[AgeingRow]:
            groups: dict[str, list[int]] = defaultdict(list)
            for case in open_cases:
                age = max((as_of - case.detected_on).days, 0)
                groups[key_of(case)].append(age)
            rows = []
            for key in sorted(groups):
                ages = groups[key]
                buckets = _empty_buckets()
                for age in ages:
                    buckets[_bucket_for(age)] += 1
                median = _median([float(a) for a in ages])
                rows.append(
                    AgeingRow(
                        key=key,
                        open_cases=len(ages),
                        buckets=buckets,
                        oldest_age_days=max(ages),
                        median_age_days=(
                            round(median, 1) if median is not None else None
                        ),
                    )
                )
            return rows

        oldest = sorted(
            open_cases,
            key=lambda c: (
                -(as_of - c.detected_on).days,
                c.detected_on,
                c.case_id,
            ),
        )[:10]
        return QueueAgeingReport(
            as_of=as_of,
            open_cases=len(open_cases),
            age_buckets=[label for label, _ in AGE_BUCKETS],
            by_status=rows_for(lambda c: c.status.value),
            by_rule=rows_for(lambda c: c.rule_id),
            by_severity=rows_for(lambda c: c.severity.value),
            oldest=[
                OldestCase(
                    case_id=c.case_id,
                    customer_id=c.customer_id,
                    status=c.status,
                    rule_id=c.rule_id,
                    severity=c.severity,
                    detected_on=c.detected_on,
                    age_days=max((as_of - c.detected_on).days, 0),
                    assigned_analyst=c.assigned_analyst,
                )
                for c in oldest
            ],
            waiting_confirmation=[
                self._waiting_confirmation(c, as_of=as_of)
                for c in open_cases
                if c.status is CaseStatus.PENDING_CONFIRMATION
            ],
            waiting_sar=[
                self._waiting_sar(c, as_of=as_of)
                for c in open_cases
                if c.status is CaseStatus.SAR_PENDING
            ],
            sources=[
                "case_store.list_cases (status, detected_on, rule_id, "
                "severity, assigned_analyst as recorded on the case)",
                "disposition_store.list_dispositions + "
                "get_confirmation_for (the pending-confirmation wait)",
                "sar_narrative_store.list_narratives + "
                "list_verifications, approval_store.list_approvals "
                "(the SAR wait's stage)",
            ],
        )

    def _waiting_confirmation(self, case: Case, *, as_of: date) -> WaitingEntry:
        records = self._dispositions.list_dispositions(case.case_id)
        pending = None
        for record in records:
            if record.requires_confirmation and (
                self._dispositions.get_confirmation_for(record.disposition_id)
                is None
            ):
                pending = record  # the latest unconfirmed one stands
        chosen = pending or (records[-1] if records else None)
        since = chosen.decided_at.date() if chosen else case.detected_on
        return WaitingEntry(
            case_id=case.case_id,
            customer_id=case.customer_id,
            stage="awaiting_confirmation",
            waiting_on_role="l2_reviewer",
            disposition_id=chosen.disposition_id if chosen else None,
            disposition_analyst_id=chosen.analyst_id if chosen else None,
            since=since,
            days_waiting=max((as_of - since).days, 0),
        )

    def _waiting_sar(self, case: Case, *, as_of: date) -> WaitingEntry:
        records = self._dispositions.list_dispositions(case.case_id)
        escalations = [
            r for r in records if r.outcome is DispositionOutcome.ESCALATE_SAR
        ]
        routing = escalations[-1] if escalations else None
        since = routing.decided_at.date() if routing else case.detected_on
        narratives = sorted(
            self._narratives.list_narratives(case.case_id),
            key=lambda n: n.version,
        )
        stage, role = "awaiting_draft", "drafting_service"
        version, drafted_by = None, None
        if narratives:
            latest = narratives[-1]
            version, drafted_by = latest.version, latest.drafted_by
            decided = self._approvals.get_approval_for(latest.narrative_id)
            verification = self._narratives.get_verification_for(
                latest.narrative_id
            )
            if decided is not None and decided.outcome is ApprovalOutcome.REJECTED:
                stage, role = "awaiting_draft", "drafting_service"
            elif verification is None or not verification.all_verified:
                stage, role = "awaiting_verification", "citation_verifier"
            elif decided is None:
                stage, role = "awaiting_approval", "sar_approver"
        return WaitingEntry(
            case_id=case.case_id,
            customer_id=case.customer_id,
            stage=stage,
            waiting_on_role=role,
            disposition_id=routing.disposition_id if routing else None,
            disposition_analyst_id=routing.analyst_id if routing else None,
            narrative_version=version,
            drafted_by=drafted_by,
            since=since,
            days_waiting=max((as_of - since).days, 0),
        )

    # -- clock board ------------------------------------------------------

    def _clock_board(
        self,
        cases: list[Case],
        *,
        as_of: date,
        window_start: date | None,
        window_end: date,
        inputs: Counter,
    ) -> ClockBoardReport:
        filing_counts: Counter = Counter()
        continuing_counts: Counter = Counter()
        overdue: list[OverdueClockEntry] = []
        entries: list[DeadlinePerformanceEntry] = []
        with_continuing = 0
        for case in cases:
            clocks = self._clocks.case_clocks(case.case_id, as_of=as_of)
            filing = clocks.filing
            filing_counts[filing.state.value] += 1
            if filing.state is ClockState.OVERDUE and filing.days_remaining is not None:
                overdue.append(
                    OverdueClockEntry(
                        case_id=case.case_id,
                        customer_id=case.customer_id,
                        clock_kind="filing",
                        deadline_kind=filing.operative_deadline_kind,
                        deadline=filing.operative_deadline,
                        days_overdue=-filing.days_remaining,
                    )
                )
            if filing.state is ClockState.SATISFIED:
                entries.append(
                    DeadlinePerformanceEntry(
                        clock_kind="filing",
                        case_id=case.case_id,
                        outcome="satisfied",
                        deadline=filing.operative_deadline,
                        ended_on=self._clocks.filing_determination_date(case),
                        on_time=False,  # set below, uniformly
                        days_late=0,
                    )
                )
            elif filing.state is ClockState.CLOSED_NO_FILE:
                entries.append(
                    DeadlinePerformanceEntry(
                        clock_kind="filing",
                        case_id=case.case_id,
                        outcome="closed_no_file",
                        deadline=filing.operative_deadline,
                        ended_on=filing.no_file_decided_on or case.detected_on,
                        on_time=False,
                        days_late=0,
                    )
                )
            current = clocks.continuing_activity
            if current is not None:
                with_continuing += 1
                continuing_counts[current.state.value] += 1
                if (
                    current.state is ClockState.OVERDUE
                    and current.days_remaining is not None
                ):
                    overdue.append(
                        OverdueClockEntry(
                            case_id=case.case_id,
                            customer_id=case.customer_id,
                            clock_kind="continuing_activity",
                            deadline_kind=current.operative_deadline_kind,
                            deadline=current.operative_deadline,
                            days_overdue=-current.days_remaining,
                        )
                    )
            entries.extend(
                self._continuing_performance(case, clocks.continuing_history)
            )
        for entry in entries:
            entry.days_late = max((entry.ended_on - entry.deadline).days, 0)
            entry.on_time = entry.days_late == 0
        in_window = [
            e
            for e in entries
            if e.ended_on <= window_end
            and (window_start is None or e.ended_on >= window_start)
        ]
        in_window.sort(key=lambda e: (e.ended_on, e.clock_kind, e.case_id))
        overdue.sort(key=lambda e: (-e.days_overdue, e.clock_kind, e.case_id))
        inputs["continuing_review_dispositions"] += sum(
            len(self._reviews.list_review_dispositions(c.case_id)) for c in cases
        )
        return ClockBoardReport(
            as_of=as_of,
            filing_by_state={
                state.value: filing_counts[state.value] for state in ClockState
            },
            continuing_by_state={
                state.value: continuing_counts[state.value]
                for state in ClockState
            },
            cases_with_continuing_clock=with_continuing,
            overdue=overdue,
            performance=DeadlinePerformance(
                window_start=window_start,
                window_end=window_end,
                clocks_ended=len(in_window),
                on_time=sum(1 for e in in_window if e.on_time),
                late=sum(1 for e in in_window if not e.on_time),
                entries=in_window,
            ),
            sources=[
                "clocks.case_clocks (the R8 derivation, read at as_of): "
                "filing state + operative deadline per case, current "
                "continuing cycle per case",
                "clocks.filing_determination_date (approval date, else "
                "closing disposition date) for when a filing clock ended",
                "filing.no_file_decided_on (the standing no-file "
                "disposition's decision date) for no-file endings",
                "continuing_review_store.list_review_dispositions (the "
                "recorded answer's decision date) for answered cycles",
            ],
        )

    def _continuing_performance(
        self, case: Case, history: list
    ) -> list[DeadlinePerformanceEntry]:
        """Terminal continuing-activity cycles for one case. A
        cycle answered by a review disposition is measured
        against its review deadline; a cycle the case's own
        ending closed is measured against its filing deadline."""
        entries: list[DeadlinePerformanceEntry] = []
        dispositions = {
            d.review_id: d
            for d in self._reviews.list_review_dispositions(case.case_id)
        }
        for cycle in history:
            answered = (
                dispositions.get(cycle.answered_by_review_id)
                if cycle.answered_by_review_id
                else None
            )
            if answered is not None:
                if answered.outcome is ReviewOutcome.NO_FILE_THIS_CYCLE:
                    entries.append(
                        DeadlinePerformanceEntry(
                            clock_kind="continuing_activity",
                            case_id=case.case_id,
                            cycle=cycle.cycle,
                            outcome="closed_no_file",
                            deadline=cycle.review_due_on,
                            ended_on=answered.decided_at.date(),
                            on_time=False,
                            days_late=0,
                        )
                    )
                elif (
                    answered.outcome is ReviewOutcome.FILE_CONTINUING
                    and case.status is CaseStatus.FILED_SAR
                ):
                    entries.append(
                        DeadlinePerformanceEntry(
                            clock_kind="continuing_activity",
                            case_id=case.case_id,
                            cycle=cycle.cycle,
                            outcome="satisfied",
                            deadline=cycle.filing_due_on,
                            ended_on=self._clocks.filing_determination_date(case),
                            on_time=False,
                            days_late=0,
                        )
                    )
                # file_continuing without a filing: the cycle is
                # still live against the filing deadline.
                continue
            if cycle.state is ClockState.SATISFIED:
                entries.append(
                    DeadlinePerformanceEntry(
                        clock_kind="continuing_activity",
                        case_id=case.case_id,
                        cycle=cycle.cycle,
                        outcome="satisfied",
                        deadline=cycle.filing_due_on,
                        ended_on=self._clocks.filing_determination_date(case),
                        on_time=False,
                        days_late=0,
                    )
                )
            elif cycle.state is ClockState.CLOSED_NO_FILE:
                ended = self._standing_no_file_date(case)
                if ended is not None:
                    entries.append(
                        DeadlinePerformanceEntry(
                            clock_kind="continuing_activity",
                            case_id=case.case_id,
                            cycle=cycle.cycle,
                            outcome="closed_no_file",
                            deadline=cycle.filing_due_on,
                            ended_on=ended,
                            on_time=False,
                            days_late=0,
                        )
                    )
        return entries

    def _standing_no_file_date(self, case: Case) -> date | None:
        """The decision date of the case's standing no-file
        disposition — the same records the clock derivation
        reads (R8's rule, restated over the stores)."""
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
        confirmation = self._dispositions.get_confirmation_for(
            latest.disposition_id
        )
        if confirmation is not None:
            if confirmation.outcome is ConfirmationOutcome.DECLINED:
                return None
        elif latest.requires_confirmation:
            return None
        return latest.decided_at.date()

    # -- rubber-stamp metrics --------------------------------------------

    def _rubber_stamp(
        self, cases: list[Case], *, as_of: date, inputs: Counter
    ) -> RubberStampReport:
        report = RubberStampReport(
            as_of=as_of,
            measures=list(_MEASURES),
            cannot_measure=list(_CANNOT_MEASURE),
            sources=[
                "investigation_store.list_investigation_records "
                "(versions + the diffs stored on them, R4)",
                "disposition_store.list_dispositions + "
                "list_confirmations (the gate's records, R5)",
                "sar_narrative_store.list_narratives + "
                "list_verifications, approval_store.list_approvals "
                "(drafts and dual-control decisions, R6/R7)",
            ],
        )
        disposition_latency: dict[str, list[float]] = defaultdict(list)
        confirmation_latency: dict[str, list[float]] = defaultdict(list)
        approval_latency: dict[str, list[float]] = defaultdict(list)
        rate_rows: dict[str, ConfirmationRateRow] = {}

        for case in cases:
            records = sorted(
                self._investigations.list_investigation_records(case.case_id),
                key=lambda r: r.version,
            )
            dispositions = self._dispositions.list_dispositions(case.case_id)
            confirmations = self._dispositions.list_confirmations(case.case_id)
            narratives = sorted(
                self._narratives.list_narratives(case.case_id),
                key=lambda n: n.version,
            )
            approvals = self._approvals.list_approvals(case.case_id)
            inputs["investigation_records"] += len(records)
            inputs["dispositions"] += len(dispositions)
            inputs["confirmations"] += len(confirmations)
            inputs["narratives"] += len(narratives)
            inputs["approvals"] += len(approvals)

            # -- records: first draft -> decided version --------------
            if records:
                report.record_cases += 1
                standing = dispositions[-1] if dispositions else None
                decided_version = standing.record_version if standing else None
                added = removed = changed = 0
                hypothesis_changed = False
                transitions = 0
                if decided_version is not None:
                    for record in records:
                        if 2 <= record.version <= decided_version:
                            diff = record.diff or self._recompute_diff(
                                records, record
                            )
                            if diff is None:
                                continue
                            transitions += 1
                            added += len(diff.added)
                            removed += len(diff.removed)
                            changed += len(diff.changed)
                            hypothesis_changed = (
                                hypothesis_changed or diff.hypothesis_changed
                            )
                report.record_rows.append(
                    RecordRevisionRow(
                        case_id=case.case_id,
                        first_version=records[0].version,
                        decided_version=decided_version,
                        latest_version=records[-1].version,
                        findings_added=added,
                        findings_removed=removed,
                        findings_changed=changed,
                        hypothesis_changed=hypothesis_changed,
                    )
                )
                if standing is not None:
                    report.record_cases_decided += 1
                    report.record_transitions += transitions
                    report.findings_added += added
                    report.findings_removed += removed
                    report.findings_changed += changed
                    report.hypothesis_changes += (
                        1 if hypothesis_changed else 0
                    )
                    if decided_version == records[0].version:
                        report.decided_on_first_draft += 1
                    else:
                        report.decided_on_revised_record += 1

            # -- narratives: first draft -> approved version ----------
            if narratives:
                report.narrative_cases += 1
                report.narrative_drafts += len(narratives)
                approved = [
                    a for a in approvals if a.outcome is ApprovalOutcome.APPROVED
                ]
                rejected = [
                    a for a in approvals if a.outcome is ApprovalOutcome.REJECTED
                ]
                report.narrative_rejections += len(rejected)
                row = NarrativeRevisionRow(
                    case_id=case.case_id,
                    drafts=len(narratives),
                    rejections=len(rejected),
                )
                if approved:
                    decision = sorted(
                        approved, key=lambda a: a.decided_at
                    )[0]
                    approved_narrative = self._narratives.get_narrative(
                        decision.narrative_id
                    )
                    report.narratives_approved += 1
                    row.approved_version = decision.narrative_version
                    if approved_narrative is not None:
                        first_text = narratives[0].render_text()
                        approved_text = approved_narrative.render_text()
                        if approved_text == first_text:
                            row.approved_without_edit = True
                            row.edit_distance = 0.0
                            row.edit_band = "none"
                            report.approved_without_edit += 1
                        else:
                            ratio = difflib.SequenceMatcher(
                                None, first_text, approved_text
                            ).ratio()
                            distance = round(1.0 - ratio, 4)
                            row.approved_without_edit = False
                            row.edit_distance = distance
                            row.edit_band = _edit_band(distance)
                            if decision.narrative_version > 1:
                                report.approved_after_redraft += 1
                        report.edit_bands[row.edit_band] = (
                            report.edit_bands.get(row.edit_band, 0) + 1
                        )
                report.narrative_rows.append(row)

            # -- confirmations -----------------------------------------
            confirmations_by_id = {
                c.disposition_id: c for c in confirmations
            }
            for record in dispositions:
                row = rate_rows.setdefault(
                    record.analyst_id,
                    ConfirmationRateRow(analyst_id=record.analyst_id),
                )
                row.dispositions += 1
                if not record.requires_confirmation:
                    continue
                row.requiring_confirmation += 1
                report.confirmations_required += 1
                answer = confirmations_by_id.get(record.disposition_id)
                if answer is None:
                    row.awaiting += 1
                    report.confirmations_awaiting += 1
                    continue
                if answer.outcome is ConfirmationOutcome.CONFIRMED:
                    row.confirmed += 1
                    report.confirmations_confirmed += 1
                    if answer.note.strip():
                        report.confirmed_with_note += 1
                    else:
                        report.confirmed_without_note += 1
                else:
                    row.declined += 1
                    report.confirmations_declined += 1

            # -- decision latencies -------------------------------------
            for record in dispositions:
                cited = self._investigations.get_investigation_record(
                    record.record_id
                )
                if cited is not None:
                    hours = _hours_between(cited.created_at, record.decided_at)
                    if hours is not None:
                        disposition_latency[record.analyst_id].append(hours)
            for answer in confirmations:
                disposition = self._dispositions.get_disposition(
                    answer.disposition_id
                )
                if disposition is not None:
                    hours = _hours_between(
                        disposition.decided_at, answer.decided_at
                    )
                    if hours is not None:
                        confirmation_latency[answer.confirmer_id].append(hours)
            for decision in approvals:
                narrative = self._narratives.get_narrative(decision.narrative_id)
                if narrative is not None:
                    hours = _hours_between(
                        narrative.created_at, decision.decided_at
                    )
                    if hours is not None:
                        approval_latency[decision.approver_id].append(hours)

        for row in rate_rows.values():
            decided = row.confirmed + row.declined
            row.confirmation_rate = (
                round(row.confirmed / decided, 4) if decided else None
            )
        report.confirmation_rates = [
            rate_rows[key] for key in sorted(rate_rows)
        ]
        for gate, table in (
            ("disposition", disposition_latency),
            ("confirmation", confirmation_latency),
            ("sar_approval", approval_latency),
        ):
            for actor_id in sorted(table):
                values = table[actor_id]
                median = _median(values)
                report.decision_times.append(
                    DecisionTimeRow(
                        actor_id=actor_id,
                        gate=gate,
                        decisions=len(values),
                        median_hours=(
                            round(median, 2) if median is not None else None
                        ),
                        p90_hours=(
                            round(_p90(values), 2)
                            if _p90(values) is not None
                            else None
                        ),
                    )
                )
        report.edit_bands = {
            label: report.edit_bands.get(label, 0) for label, _ in EDIT_BANDS
        }
        report.record_rows.sort(key=lambda r: r.case_id)
        report.narrative_rows.sort(key=lambda r: r.case_id)
        return report

    @staticmethod
    def _recompute_diff(records: list, record) -> object | None:
        """Fallback when a version carries no stored diff: the
        key-set difference against its predecessor, with a
        statement comparison standing in for the signature."""
        previous = None
        for candidate in records:
            if candidate.version == record.version - 1:
                previous = candidate
        if previous is None:
            return None
        from .models import RecordDiff

        prev = {f.key: f for f in previous.findings}
        new = {f.key: f for f in record.findings}
        return RecordDiff(
            from_version=previous.version,
            added=sorted(set(new) - set(prev)),
            removed=sorted(set(prev) - set(new)),
            changed=sorted(
                key
                for key in set(new) & set(prev)
                if new[key].statement != prev[key].statement
                or new[key].figures != prev[key].figures
            ),
            hypothesis_changed=previous.hypothesis.label != record.hypothesis.label,
        )

    # -- operations --------------------------------------------------------

    def _ops(self, cases: list[Case], *, as_of: date, inputs: Counter) -> OpsReport:
        report = OpsReport(
            as_of=as_of,
            sources=[
                "typology_store.list_typology_runs + list_findings "
                "(pack id + version recorded on every artefact, R3)",
                "screening_store.list_screening_runs + list_hits "
                "(snapshot version recorded on every hit, R2)",
                "quarantine.records_for per case (the R10 chain "
                "records) + quarantine.queue (review standing)",
                "media_store.list_assessments (bands as scored, R12)",
                "model_ledger_store.list_call_entries (the priced "
                "ledger, R13)",
            ],
        )
        # Typology volume.
        pack_runs: Counter = Counter()
        finding_groups: dict[tuple, dict] = {}
        for case in cases:
            runs = self._typologies.list_typology_runs(case.case_id)
            findings = self._typologies.list_findings(case.case_id)
            inputs["typology_runs"] += len(runs)
            inputs["typology_findings"] += len(findings)
            for run in runs:
                pack_runs[(run.rule_pack_id, run.rule_pack_version)] += 1
            for finding in findings:
                key = (
                    finding.typology_id,
                    finding.rule_pack_id,
                    finding.rule_pack_version,
                )
                group = finding_groups.setdefault(
                    key, {"findings": 0, "cases": set()}
                )
                group["findings"] += 1
                group["cases"].add(case.case_id)
        for (typology_id, pack_id, version) in sorted(finding_groups):
            group = finding_groups[(typology_id, pack_id, version)]
            runs = pack_runs[(pack_id, version)]
            per_run = (
                (Decimal(group["findings"]) / Decimal(runs)).quantize(
                    Decimal("0.0001")
                )
                if runs
                else Decimal("0.0000")
            )
            report.typology.append(
                TypologyOpsRow(
                    typology_id=typology_id,
                    rule_pack_id=pack_id,
                    rule_pack_version=version,
                    pack_runs=runs,
                    findings=group["findings"],
                    cases_with_findings=len(group["cases"]),
                    findings_per_run=str(per_run),
                )
            )
        # Screening volume.
        screened_cases: dict[tuple, set] = defaultdict(set)
        hit_groups: dict[tuple, Counter] = defaultdict(Counter)
        for case in cases:
            runs = self._screening.list_screening_runs(case.case_id)
            hits = self._screening.list_hits(case.case_id)
            inputs["screening_runs"] += len(runs)
            inputs["screening_hits"] += len(hits)
            for run in runs:
                for pin in run.pins:
                    screened_cases[(pin.list_kind.value, pin.version)].add(
                        case.case_id
                    )
            for hit in hits:
                group = hit_groups[(hit.list_kind.value, hit.snapshot_version)]
                group["hits"] += 1
                group[hit.status.value] += 1
                if (
                    hit.status is HitStatus.CLEARED
                    and hit.cleared_reason == NAMESAKE_CLEAR_REASON
                ):
                    group["namesake"] += 1
        for (kind, version) in sorted(hit_groups):
            group = hit_groups[(kind, version)]
            report.screening.append(
                ScreeningOpsRow(
                    list_kind=kind,
                    snapshot_version=version,
                    cases_screened=len(screened_cases[(kind, version)]),
                    hits=group["hits"],
                    open=group[HitStatus.OPEN.value],
                    cleared=group[HitStatus.CLEARED.value],
                    namesake_cleared=group["namesake"],
                    confirmed=group[HitStatus.CONFIRMED.value],
                )
            )
        # Quarantine volume (derived from the chain records).
        if self._quarantine is not None:
            families: Counter = Counter()
            source_kinds: Counter = Counter()
            records_total = 0
            matches_total = 0
            for case in cases:
                for record in self._quarantine.records_for(case.case_id):
                    records_total += 1
                    source_kinds[record.source_kind] += 1
                    for field in record.fields:
                        for match in field.matches:
                            matches_total += 1
                            families[match.family] += 1
            queue = self._quarantine.queue()
            inputs["quarantine_records"] += records_total
            report.quarantine = QuarantineOps(
                available=True,
                records=records_total,
                matches=matches_total,
                by_family=dict(sorted(families.items())),
                by_source_kind=dict(sorted(source_kinds.items())),
                flagged=sum(1 for e in queue if e.status == "flagged"),
                reviewed=sum(1 for e in queue if e.status == "reviewed"),
            )
        # Media band distribution.
        band_counts: Counter = Counter()
        for case in cases:
            assessments = self._media.list_assessments(case.case_id)
            inputs["media_assessments"] += len(assessments)
            for assessment in assessments:
                band_counts[assessment.band.value] += 1
                report.media_assessments += 1
        report.media_by_band = {
            band.value: band_counts[band.value] for band in MediaBand
        }
        # Model spend.
        entries = self._ledger.list_call_entries(None)
        inputs["model_calls"] += len(entries)
        by_profile: dict[str, SpendRow] = {}
        by_purpose: dict[str, SpendRow] = {}
        total_cost = Decimal("0")
        for entry in entries:
            report.model_calls += 1
            report.model_tokens_in += entry.tokens_in
            report.model_tokens_out += entry.tokens_out
            total_cost += entry.cost_usd
            for table, key in (
                (by_profile, entry.profile_id),
                (by_purpose, entry.purpose),
            ):
                row = table.setdefault(key, SpendRow(key=key))
                row.calls += 1
                row.tokens_in += entry.tokens_in
                row.tokens_out += entry.tokens_out
                row.cost_usd = str(Decimal(row.cost_usd) + entry.cost_usd)
        report.model_cost_usd = str(total_cost)
        report.model_by_profile = [by_profile[k] for k in sorted(by_profile)]
        report.model_by_purpose = [by_purpose[k] for k in sorted(by_purpose)]
        return report
