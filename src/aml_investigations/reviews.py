"""Continuing-activity reviews (R9): the workflow answering R8's clock.

R8 started the clock: when a new alert opens for a customer with
a prior ``filed_sar`` case, the new case carries a
continuing-activity clock — review due at the prior determination
+ 90 days, filing due at + 120. This round builds the review that
answers it, under the same discipline as everything upstream:

- **Assembly is citation-bound.** A review gathers the window's
  activity — the cases and alerts opened since the determination,
  the transactions posted in the window, the linked case's record
  (its hypothesis and its typology findings, restated verbatim),
  the screening state, and the prior filing's facts — and every
  gathered item carries citations that resolve under R4's
  :class:`CitationResolver`. There is no second resolver, and a
  review whose citations do not resolve, or whose statements
  carry figures its citations cannot ground, is refused at the
  gate: it is never stored.

- **The continuation assessment is coded, in code.** Whether the
  window activity continues the filed typology is derived from
  the filed record's hypothesis label, the current record's
  findings, and which of those findings rest on transactions
  posted inside the window — ``continues_filed_typology``,
  ``new_pattern_in_window``, ``no_adverse_activity_in_window``,
  or ``activity_unrelated_to_filing`` (the findings rest on
  activity that predates the window). The basis is stated in
  words alongside the code; the code is never a free-text claim.

- **Only a recorded disposition answers the clock.** A named
  analyst decides per cycle: ``file_continuing`` — which mints an
  ``escalate_sar`` disposition through the R5 gate (its coded
  vocabulary, its transition), routing the case to the R6
  narrative path, whose draft then cites this review and the
  prior filing — or ``no_file_this_cycle``, documented by coded
  rationale from the review vocabulary. The clock service reads
  the disposition rows and nothing else: a review opened but not
  dispositioned satisfies nothing, and past the filing deadline
  the unanswered cycle escalates as overdue on R8's machinery.

- **Cycles chain.** A no-file decision ends its cycle and starts
  the next from its own decision date (rolling 90/120); the next
  cycle's review names the review that started it
  (``prior_review_id``). One open review stands per cycle: a
  second open attempt is refused, a dispositioned review is
  immutable, and a review whose cited record has been superseded
  stands stale — a fresh review is opened in its place, naming
  the one it supersedes, never an edit.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone

from .clocks import RegulatoryClockService
from .composer import numeric_tokens, tokens_of
from .dispositions import (
    ANALYST_ROLES,
    RATIONALE_CODES,
    RATIONALE_VOCABULARY_VERSION as DISPOSITION_VOCABULARY_VERSION,
    SYSTEM_ACTORS,
    DispositionService,
)
from .errors import (
    CaseNotFoundError,
    CitationResolutionError,
    ContinuingReviewRefusedError,
    ReviewNotFoundError,
)
from .evidence import EvidenceService, ensure_case_mutable
from .investigation import CitationResolver
from .logging_config import get_logger
from .models import (
    Alert,
    AuditEvent,
    Case,
    CaseStatus,
    Citation,
    ContinuingReview,
    ContinuingReviewDisposition,
    DispositionOutcome,
    InvestigationRecord,
    OpenQuestion,
    ReviewActivityItem,
    ReviewOutcome,
)
from .ports import (
    CaseStore,
    ContinuingReviewStore,
    DispositionStore,
    InvestigationStore,
    SarNarrativeStore,
    ScreeningStore,
    SealStore,
    TypologyStore,
)

logger = get_logger(__name__)

#: Evidence kinds this service writes.
REVIEW_KIND = "continuing_review"
REVIEW_DISPOSITION_KIND = "continuing_review_disposition"

#: The review vocabulary family: coded rationale for a no-file
#: cycle decision. Versioned like the disposition vocabulary —
#: the codes on a stored disposition name the version they were
#: drawn from, so a later vocabulary change never rewrites what a
#: past decision meant.
REVIEW_VOCABULARY_VERSION = "2026.10.1"
REVIEW_NO_FILE_CODES: dict[str, str] = {
    "ACTIVITY_EXPLAINED": (
        "the window activity is explained by the customer's "
        "established profile and legitimate business"
    ),
    "ACTIVITY_CEASED": (
        "the filed typology's activity has ceased in the window"
    ),
    "BELOW_FILING_THRESHOLD": (
        "window activity is isolated or de minimis and does not "
        "meet the filing threshold this cycle"
    ),
    "NO_CONTINUATION_EVIDENCE": (
        "no evidence in the window ties the activity to the "
        "filed typology"
    ),
    "SUBJECT_EXITED": (
        "the subject has exited the relationship; no further "
        "activity is expected"
    ),
}

#: Coded continuation assessments, as data.
ASSESSMENT_CONTINUES = "continues_filed_typology"
ASSESSMENT_NEW_PATTERN = "new_pattern_in_window"
ASSESSMENT_NO_ADVERSE = "no_adverse_activity_in_window"
ASSESSMENT_UNRELATED = "activity_unrelated_to_filing"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ContinuingReviewService:
    """Assembles continuing-activity reviews over a case's clock
    cycles, verifies them at the gate, and records the analyst
    decisions that answer the clock."""

    def __init__(
        self,
        store: CaseStore,
        records: InvestigationStore,
        dispositions: DispositionStore,
        reviews: ContinuingReviewStore,
        typologies: TypologyStore,
        screening: ScreeningStore,
        narratives: SarNarrativeStore,
        evidence: EvidenceService,
        clocks: RegulatoryClockService,
        disposition_gate: DispositionService,
        seal_store: SealStore | None = None,
        quarantine=None,
    ) -> None:
        self._store = store
        self._records = records
        self._dispositions = dispositions
        self._reviews = reviews
        self._typologies = typologies
        self._screening = screening
        self._narratives = narratives
        self._evidence = evidence
        self._clocks = clocks
        self._gate = disposition_gate
        self._seals = seal_store
        # R10 (Law 7): when wired, the review gate's cited tokens
        # mask quarantined spans like every other verifier.
        self._quarantine = quarantine
        self._resolver = CitationResolver(store, evidence)

    # -- refusals / lookups ------------------------------------------

    def _refuse(
        self, case_id: str, actor: str, reason: str, message: str
    ) -> ContinuingReviewRefusedError:
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="continuing_review_refused",
                detail={"reason": reason, "message": message},
            )
        )
        return ContinuingReviewRefusedError(reason, message)

    def _require_case(self, case_id: str) -> Case:
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        return case

    def _current_record(self, case_id: str) -> InvestigationRecord | None:
        records = self._records.list_investigation_records(case_id)
        if not records:
            return None
        return max(records, key=lambda r: r.version)

    def _evidence_seq_for(self, case_id: str, kind: str) -> int | None:
        seq: int | None = None
        for item in self._store.list_evidence(case_id):
            if item.kind == kind:
                seq = item.seq
        return seq

    # -- standing ------------------------------------------------------

    def review_status(self, review: ContinuingReview) -> str:
        """A review's standing, derived: ``decided_<outcome>``
        once its disposition is recorded (immutable from then),
        ``superseded`` when a fresher review stands for its cycle,
        ``stale`` when the record it cites has been superseded,
        else ``open``."""
        disposition = self._reviews.get_review_disposition_for(
            review.review_id
        )
        if disposition is not None:
            return f"decided_{disposition.outcome.value}"
        siblings = [
            r
            for r in self._reviews.list_reviews(review.case_id)
            if r.cycle == review.cycle
        ]
        if siblings and siblings[-1].review_id != review.review_id:
            return "superseded"
        current = self._current_record(review.case_id)
        if (
            current is None
            or current.record_id != review.record_id
            or current.version != review.record_version
        ):
            return "stale"
        return "open"

    def review_view(self, review: ContinuingReview) -> dict:
        """The review as served: the artefact, its standing, and
        its disposition when one is recorded."""
        disposition = self._reviews.get_review_disposition_for(
            review.review_id
        )
        return {
            **review.model_dump(mode="json"),
            "status": self.review_status(review),
            "disposition": (
                disposition.model_dump(mode="json")
                if disposition is not None
                else None
            ),
        }

    def reviews_for_case(self, case_id: str) -> list[dict]:
        self._require_case(case_id)
        return [
            self.review_view(r) for r in self._reviews.list_reviews(case_id)
        ]

    def current_review(self, case_id: str) -> dict | None:
        """The operative review for the case's current cycle, if
        one has been opened."""
        case = self._require_case(case_id)
        operative = self._clocks.operative_review(case)
        return self.review_view(operative) if operative is not None else None

    def get_review_view(self, case_id: str, review_id: str) -> dict:
        """One review on one case, as served — 404-shaped when it
        does not exist there."""
        self._require_case(case_id)
        review = self._reviews.get_review(review_id)
        if review is None or review.case_id != case_id:
            raise ReviewNotFoundError(
                f"no review {review_id} exists on case {case_id}"
            )
        return self.review_view(review)

    def history_for_customer(self, customer_id: str) -> dict:
        """Every review and review disposition across the
        customer's cases — the continuing-activity history a
        reviewer (or an examiner) reads in one place."""
        reviews = self._reviews.list_reviews_for_customer(customer_id)
        dispositions = self._reviews.list_review_dispositions_for_customer(
            customer_id
        )
        return {
            "customer_id": customer_id,
            "reviews": [self.review_view(r) for r in reviews],
            "dispositions": [
                d.model_dump(mode="json") for d in dispositions
            ],
        }

    # -- the verification gate ------------------------------------------

    def verify_review(self, review: ContinuingReview) -> list[str]:
        """The gate every assembled review passes before it is
        stored — and the check an examiner can re-run over a
        stored one. Every activity item must carry at least one
        citation; every citation must resolve under the case's
        CitationResolver; and every figure an item states — in
        its text or its figure map — must appear in the records
        its citations resolve to. Returns the problems found;
        empty is sound."""
        problems: list[str] = []
        if not review.activity:
            problems.append("review carries no activity items")
        for index, item in enumerate(review.activity, start=1):
            label = f"activity item {index} ({item.kind})"
            if not item.citations:
                problems.append(f"{label} carries no citations")
                continue
            cited_tokens: set = set()
            for citation in item.citations:
                try:
                    resolved = self._resolver.resolve(
                        citation, review.case_id
                    )
                except CitationResolutionError as exc:
                    problems.append(
                        f"{label}: citation does not resolve ({exc})"
                    )
                    continue
                if self._quarantine is not None:
                    cited_tokens |= self._quarantine.grounding_tokens(
                        review.case_id, citation, resolved
                    )
                else:
                    cited_tokens |= tokens_of(resolved)
            allowed = cited_tokens | set().union(
                *(numeric_tokens(v) for v in item.figures.values()),
                set(),
            )
            stray = numeric_tokens(item.statement) - allowed
            if stray:
                problems.append(
                    f"{label}: statement carries figures its "
                    f"citations do not ground: "
                    + ", ".join(str(s) for s in sorted(stray))
                )
            for key, value in item.figures.items():
                if numeric_tokens(value) - cited_tokens:
                    problems.append(
                        f"{label}: figure {key}={value} does not "
                        "appear in the records it cites"
                    )
        return problems

    # -- assembly ---------------------------------------------------------

    def _assess(
        self,
        *,
        filed_label: str,
        record: InvestigationRecord,
        window_transaction_ids: set[str],
    ) -> tuple[str, str]:
        """The coded continuation assessment, derived in code:
        from the filed typology's label, the current record's
        typology findings — each record finding's key names its
        typology and the transactions it rests on
        (``typology:<id>:<txn,txn,...>``, the record's own
        deterministic identity) — and whether those transactions
        were posted inside the window."""
        parsed: list[tuple[str, set[str]]] = []
        for finding in record.findings:
            if finding.origin != "typology" or not finding.key.startswith(
                "typology:"
            ):
                continue
            parts = finding.key.split(":", 2)
            label = parts[1] if len(parts) > 1 else ""
            txns = (
                {t for t in parts[2].split(",") if t}
                if len(parts) > 2
                else set()
            )
            parsed.append((label, txns))
        if not parsed:
            return (
                ASSESSMENT_NO_ADVERSE,
                "the current record carries no typology findings: "
                "its counter-search stands and its hypothesis is "
                f"'{record.hypothesis.label}' — no adverse pattern "
                "was found in the window",
            )
        window_labels = {
            label
            for label, txns in parsed
            if txns & window_transaction_ids
        }
        if not window_labels:
            return (
                ASSESSMENT_UNRELATED,
                "the current record's typology findings rest "
                "entirely on transactions posted before the window "
                "opened at the prior determination — the flagged "
                "activity predates this cycle and is not window "
                "activity",
            )
        if filed_label in window_labels:
            return (
                ASSESSMENT_CONTINUES,
                f"a typology finding labelled '{filed_label}' "
                "rests on transactions posted inside the window — "
                "the pattern the prior case filed on is present "
                "again in this cycle",
            )
        return (
            ASSESSMENT_NEW_PATTERN,
            "typology findings resting on window transactions "
            f"are labelled {sorted(window_labels)} — an adverse "
            f"pattern in the window, but not the filed "
            f"'{filed_label}' typology",
        )

    def _assemble(
        self,
        case: Case,
        *,
        cycle: int,
        determination_on: date,
        review_due_on: date,
        filing_due_on: date,
        prior_review_id: str | None,
        supersedes_review_id: str | None,
        actor: str,
    ) -> ContinuingReview:
        link = self._clocks.continuing_link_for(case.case_id)
        assert link is not None  # guarded by open_review
        record = self._current_record(case.case_id)
        assert record is not None and record.evidence_seq is not None
        prior_case = self._require_case(link.prior_case_id)
        prior_record = self._current_record(prior_case.case_id)
        assert prior_record is not None and prior_record.evidence_seq is not None
        filed_label = prior_record.hypothesis.label
        prior_narratives = self._narratives.list_narratives(
            prior_case.case_id
        )
        prior_narrative = (
            max(prior_narratives, key=lambda n: n.version)
            if prior_narratives
            else None
        )

        activity: list[ReviewActivityItem] = []

        # The prior filing's facts, cited across the chain.
        prior_citations = [
            Citation(
                evidence_seq=self._evidence_seq_for(
                    case.case_id, "continuing_activity_link"
                ),
                element="field:determination_on",
            ),
            Citation(
                case_id=prior_case.case_id,
                evidence_seq=prior_record.evidence_seq,
                element="field:hypothesis",
            ),
            Citation(
                case_id=prior_case.case_id,
                evidence_seq=prior_record.evidence_seq,
                element="field:version",
            ),
        ]
        prior_statement = (
            "The prior filing: the earlier case was determined on "
            f"{determination_on.isoformat()}, and its "
            f"investigation record (version {prior_record.version}) "
            f"worked to the hypothesis {filed_label} — "
            f"{prior_record.hypothesis.statement}"
        )
        if prior_narrative is not None and prior_narrative.evidence_seq:
            prior_citations.append(
                Citation(
                    case_id=prior_case.case_id,
                    evidence_seq=prior_narrative.evidence_seq,
                    element="field:narrative_id",
                )
            )
            prior_statement += (
                f" Its SAR narrative {prior_narrative.narrative_id} "
                "was approved, completing the case file."
            )
        activity.append(
            ReviewActivityItem(
                kind="prior_filing",
                statement=prior_statement,
                citations=prior_citations,
                refs={"prior_case_id": prior_case.case_id},
            )
        )

        # Cases and alerts opened in the window.
        window_cases = sorted(
            (
                c
                for c in self._store.list_cases()
                if c.customer_id == case.customer_id
                and c.case_id != prior_case.case_id
                and c.detected_on > determination_on
            ),
            key=lambda c: (c.detected_on, c.case_id),
        )
        for window_case in window_cases:
            alert_seq = self._evidence_seq_for(
                window_case.case_id, "alert_payload"
            )
            alert = self._alert_of(window_case.case_id)
            if alert_seq is None or alert is None:
                continue
            activity.append(
                ReviewActivityItem(
                    kind="window_alert",
                    statement=(
                        f"Alert {alert.alert_id} (rule "
                        f"{alert.rule_id}, {alert.severity} "
                        f"severity) opened a case on "
                        f"{alert.detected_on}: {alert.summary}"
                    ),
                    citations=[
                        Citation(
                            case_id=window_case.case_id,
                            evidence_seq=alert_seq,
                            element="field:alert_id",
                        ),
                        Citation(
                            case_id=window_case.case_id,
                            evidence_seq=alert_seq,
                            element="field:rule_id",
                        ),
                        Citation(
                            case_id=window_case.case_id,
                            evidence_seq=alert_seq,
                            element="field:detected_on",
                        ),
                        Citation(
                            case_id=window_case.case_id,
                            evidence_seq=alert_seq,
                            element="field:summary",
                        ),
                    ],
                    refs={
                        "case_id": window_case.case_id,
                        "alert_id": alert.alert_id,
                    },
                )
            )

        # Transactions posted inside the window.
        window_transactions = [
            t
            for t in self._typologies.list_transactions(case.case_id)
            if t.posted_at.date() > determination_on
        ]
        if window_transactions:
            # Which batch evidence item holds each transaction —
            # read from the batch items themselves, the same
            # contents the citation resolver resolves against.
            batch_seq: dict[str, int] = {}
            for batch in self._typologies.list_transaction_batches(
                case.case_id
            ):
                if batch.evidence_seq is None:
                    continue
                entries = json.loads(
                    self._evidence.read_item_content(
                        case.case_id, batch.evidence_seq
                    )
                )
                for entry in entries:
                    batch_seq[entry["transaction_id"]] = (
                        batch.evidence_seq
                    )
            txn_citations = [
                Citation(
                    evidence_seq=self._evidence_seq_for(
                        case.case_id, "continuing_activity_link"
                    ),
                    element="field:determination_on",
                )
            ]
            for txn in sorted(
                window_transactions, key=lambda t: t.transaction_id
            ):
                seq = batch_seq.get(txn.transaction_id)
                if seq is not None:
                    txn_citations.append(
                        Citation(
                            evidence_seq=seq,
                            element=f"transaction:{txn.transaction_id}",
                        )
                    )
            activity.append(
                ReviewActivityItem(
                    kind="window_transactions",
                    statement=(
                        "Transactions posted after the determination "
                        "date are stored on the case file; the "
                        "typology findings restated below rest on "
                        "them, each citing its own transactions."
                    ),
                    citations=txn_citations,
                    refs={
                        "window_transaction_count": str(
                            len(window_transactions)
                        )
                    },
                )
            )

        # The linked case's record: hypothesis, then its typology
        # findings restated verbatim under their own citations.
        activity.append(
            ReviewActivityItem(
                kind="record_hypothesis",
                statement=(
                    "The linked case's investigation (record "
                    f"version {record.version}) works to the "
                    f"hypothesis {record.hypothesis.label}: "
                    f"{record.hypothesis.statement}"
                ),
                citations=[
                    Citation(
                        evidence_seq=record.evidence_seq,
                        element="field:hypothesis",
                    ),
                    Citation(
                        evidence_seq=record.evidence_seq,
                        element="field:version",
                    ),
                ],
                refs={"record_id": record.record_id},
            )
        )
        for finding in record.findings:
            if finding.origin != "typology":
                continue
            activity.append(
                ReviewActivityItem(
                    kind="typology_finding",
                    statement=finding.statement,
                    citations=list(finding.citations),
                    figures=dict(finding.figures),
                    refs={"finding_id": finding.finding_id},
                )
            )

        # Screening state on the linked case.
        runs = self._screening.list_screening_runs(case.case_id)
        if runs:
            latest = runs[-1]
            if latest.evidence_seq is not None:
                activity.append(
                    ReviewActivityItem(
                        kind="screening_state",
                        statement=(
                            "Screening has run on the linked case: "
                            "the latest run records "
                            f"{latest.open_hits} open hit(s) and "
                            f"{latest.cleared_hits} cleared hit(s) "
                            "against its pinned snapshots."
                        ),
                        citations=[
                            Citation(
                                evidence_seq=latest.evidence_seq,
                                element=f"run:{latest.run_id}",
                            )
                        ],
                        refs={"run_id": latest.run_id},
                    )
                )

        assessment, basis = self._assess(
            filed_label=filed_label,
            record=record,
            window_transaction_ids={
                t.transaction_id for t in window_transactions
            },
        )

        open_questions = list(record.open_questions)
        if not runs:
            open_questions.append(
                OpenQuestion(
                    question=(
                        "Has the linked case been screened in this "
                        "window?"
                    ),
                    evidence_needed="screening_run",
                    rationale=(
                        "the review found no screening run on the "
                        "linked case; the screening state of the "
                        "window is unstated until one runs"
                    ),
                )
            )

        return ContinuingReview(
            case_id=case.case_id,
            customer_id=case.customer_id,
            prior_case_id=prior_case.case_id,
            cycle=cycle,
            prior_review_id=prior_review_id,
            supersedes_review_id=supersedes_review_id,
            determination_on=determination_on,
            review_due_on=review_due_on,
            filing_due_on=filing_due_on,
            record_id=record.record_id,
            record_version=record.version,
            filed_typology_label=filed_label,
            prior_narrative_id=(
                prior_narrative.narrative_id if prior_narrative else None
            ),
            activity=activity,
            continuation_assessment=assessment,
            assessment_basis=basis,
            open_questions=open_questions,
            opened_by=actor,
            opened_at=_utcnow(),
        )

    def _alert_of(self, case_id: str) -> Alert | None:
        for item in self._store.list_evidence(case_id):
            if item.kind == "alert_payload":
                content = self._evidence.read_item_content(case_id, item.seq)
                return Alert.model_validate_json(content.decode("utf-8"))
        return None

    # -- opening a review -------------------------------------------------

    def open_review(
        self, case_id: str, *, actor: str
    ) -> ContinuingReview:
        """Open the current cycle's review: assemble the window's
        activity over the linked case's current investigation
        record, verify it at the gate, and store it on the case's
        evidence chain. One open review stands per cycle; a stale
        one is superseded by the fresh review, never edited."""
        case = self._require_case(case_id)
        ensure_case_mutable(self._seals, case_id)
        if not actor or not actor.strip():
            raise self._refuse(
                case_id,
                actor or "anonymous",
                "actor_required",
                "opening a continuing-activity review requires a "
                "named actor — an analyst, or the scheduler tick",
            )
        current = self._clocks.current_cycle(case)
        if current is None:
            raise self._refuse(
                case_id,
                actor,
                "no_continuing_clock",
                "no continuing-activity clock was started on this "
                "case — there is no cycle to review",
            )
        cycle, determination_on, review_due, filing_due, prior_review_id = (
            current
        )
        record = self._current_record(case_id)
        if record is None:
            raise self._refuse(
                case_id,
                actor,
                "no_investigation_record",
                "the linked case carries no investigation record — "
                "a review assesses a record's window activity, and "
                "there is nothing to assess yet",
            )
        link = self._clocks.continuing_link_for(case_id)
        assert link is not None
        prior_record = self._current_record(link.prior_case_id)
        if prior_record is None:
            raise self._refuse(
                case_id,
                actor,
                "prior_record_missing",
                "the prior filed case carries no investigation "
                "record — the typology this review assesses "
                "continuation against is not on record",
            )
        operative = self._clocks.operative_review(case)
        supersedes: str | None = None
        if operative is not None:
            if (
                self._reviews.get_review_disposition_for(
                    operative.review_id
                )
                is not None
            ):
                raise self._refuse(
                    case_id,
                    actor,
                    "cycle_already_answered",
                    f"cycle {cycle} already stands answered by "
                    f"review {operative.review_id}'s recorded "
                    "disposition — a dispositioned review is "
                    "immutable, and its cycle is closed",
                )
            if (
                operative.record_id == record.record_id
                and operative.record_version == record.version
            ):
                raise self._refuse(
                    case_id,
                    actor,
                    "review_already_open",
                    f"review {operative.review_id} already stands "
                    f"open for cycle {cycle} over the current "
                    "record — one open review per cycle",
                )
            supersedes = operative.review_id

        review = self._assemble(
            case,
            cycle=cycle,
            determination_on=determination_on,
            review_due_on=review_due,
            filing_due_on=filing_due,
            prior_review_id=prior_review_id,
            supersedes_review_id=supersedes,
            actor=actor,
        )
        problems = self.verify_review(review)
        if problems:
            raise self._refuse(
                case_id,
                actor,
                "review_citations_unresolvable",
                "the assembled review failed its citation gate: "
                + "; ".join(problems),
            )
        item = self._evidence.add_item(
            case_id=case_id,
            kind=REVIEW_KIND,
            content=review.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"continuing-review:{review.review_id}",
            captured_by=actor,
        )
        stored = review.model_copy(update={"evidence_seq": item.seq})
        self._reviews.add_review(stored)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="continuing_review_opened",
                detail={
                    "review_id": stored.review_id,
                    "cycle": str(stored.cycle),
                    "prior_case_id": stored.prior_case_id,
                    "prior_review_id": stored.prior_review_id or "",
                    "supersedes_review_id": stored.supersedes_review_id
                    or "",
                    "record_id": stored.record_id,
                    "record_version": str(stored.record_version),
                    "continuation_assessment": stored.continuation_assessment,
                    "review_due_on": stored.review_due_on.isoformat(),
                    "filing_due_on": stored.filing_due_on.isoformat(),
                    "evidence_seq": str(item.seq),
                },
            )
        )
        logger.info(
            "continuing review opened",
            extra={
                "case_id": case_id,
                "review_id": stored.review_id,
                "cycle": stored.cycle,
                "assessment": stored.continuation_assessment,
            },
        )
        return stored

    def open_due_reviews(
        self, *, as_of: date, actor: str = "clock-service"
    ) -> list[ContinuingReview]:
        """The scheduler tick: open a review for every case whose
        current cycle's review deadline has arrived and no review
        stands for the cycle yet. A case without an investigation
        record is skipped — the tick never fabricates an
        assessment — and every review it opens names the tick as
        its actor, like any other opening."""
        opened: list[ContinuingReview] = []
        for case in self._store.list_cases():
            current = self._clocks.current_cycle(case)
            if current is None:
                continue
            _cycle, _det, review_due, _filing_due, _prior = current
            if as_of < review_due:
                continue
            if self._clocks.operative_review(case) is not None:
                continue
            if self._current_record(case.case_id) is None:
                continue
            try:
                opened.append(
                    self.open_review(case.case_id, actor=actor)
                )
            except ContinuingReviewRefusedError:
                continue
        return opened

    # -- the disposition ----------------------------------------------------

    def record_review_disposition(
        self,
        case_id: str,
        review_id: str,
        *,
        analyst_id: str,
        analyst_role: str,
        outcome: ReviewOutcome,
        rationale_codes: list[str],
        note: str = "",
    ) -> ContinuingReviewDisposition:
        """Record the cycle's decision — the only act that
        answers the clock for the cycle. ``file_continuing`` mints
        an escalate_sar disposition through the R5 gate (its
        vocabulary, its record citation, its transition to
        ``sar_pending``); ``no_file_this_cycle`` is documented by
        coded rationale from the review vocabulary. Either way the
        decision lands as its own append-only record on the
        case's evidence chain, naming the cycle's review."""
        case = self._require_case(case_id)
        ensure_case_mutable(self._seals, case_id)
        actor = analyst_id or "anonymous"
        if (
            not analyst_id
            or not analyst_id.strip()
            or analyst_id in SYSTEM_ACTORS
        ):
            raise self._refuse(
                case_id,
                actor,
                "anonymous_or_system_actor",
                "a review disposition is a named analyst's "
                "decision — an unnamed or system identity cannot "
                "record one",
            )
        if analyst_role not in ANALYST_ROLES:
            raise self._refuse(
                case_id,
                actor,
                "unknown_role",
                f"role '{analyst_role}' is not in the analyst role "
                f"vocabulary ({', '.join(sorted(ANALYST_ROLES))})",
            )
        review = self._reviews.get_review(review_id)
        if review is None or review.case_id != case_id:
            raise ReviewNotFoundError(
                f"no review {review_id} exists on case {case_id}"
            )
        if (
            self._reviews.get_review_disposition_for(review_id)
            is not None
        ):
            raise self._refuse(
                case_id,
                actor,
                "already_dispositioned",
                f"review {review_id} already stands dispositioned "
                "— a cycle's decision is recorded exactly once, "
                "and a dispositioned review is immutable",
            )
        status = self.review_status(review)
        if status == "superseded":
            raise self._refuse(
                case_id,
                actor,
                "review_superseded",
                f"review {review_id} was superseded by a fresher "
                "review for its cycle — decide the standing review",
            )
        if status == "stale":
            raise self._refuse(
                case_id,
                actor,
                "review_stale",
                "the investigation record this review was "
                "assembled over has been superseded — open a fresh "
                "review over the current record and decide that",
            )
        codes = list(rationale_codes or [])
        if not codes:
            raise self._refuse(
                case_id,
                actor,
                "rationale_codes_required",
                "a review decision is documented by coded "
                "rationale — free text alone never answers a clock",
            )
        if outcome is ReviewOutcome.NO_FILE_THIS_CYCLE:
            allowed = REVIEW_NO_FILE_CODES
            vocabulary = REVIEW_VOCABULARY_VERSION
        else:
            allowed = RATIONALE_CODES[DispositionOutcome.ESCALATE_SAR]
            vocabulary = DISPOSITION_VOCABULARY_VERSION
        unknown = [c for c in codes if c not in allowed]
        if unknown:
            raise self._refuse(
                case_id,
                actor,
                "unknown_rationale_code",
                "rationale code(s) not in the "
                + (
                    "review no-file vocabulary"
                    if outcome is ReviewOutcome.NO_FILE_THIS_CYCLE
                    else "disposition vocabulary for escalate_sar"
                )
                + f": {', '.join(unknown)} (vocabulary version "
                f"{vocabulary})",
            )

        case_disposition_id: str | None = None
        if outcome is ReviewOutcome.FILE_CONTINUING:
            if case.status is not CaseStatus.AWAITING_ANALYST:
                raise self._refuse(
                    case_id,
                    actor,
                    "case_not_awaiting_analyst",
                    "a file-continuing decision routes the case "
                    "through the analyst gate, which requires the "
                    f"case to stand awaiting_analyst (it stands "
                    f"{case.status.value})",
                )
            current = self._current_record(case_id)
            if (
                current is None
                or current.record_id != review.record_id
                or current.version != review.record_version
            ):
                raise self._refuse(
                    case_id,
                    actor,
                    "record_citation_not_current",
                    "the review's cited record is not the case's "
                    "current record — the gate routes on the "
                    "record the review assessed, and it has moved",
                )
            minted = self._gate.record_disposition(
                case_id,
                analyst_id=analyst_id,
                analyst_role=analyst_role,
                outcome=DispositionOutcome.ESCALATE_SAR,
                rationale_codes=codes,
                record_id=review.record_id,
                record_version=review.record_version,
                note=note
                or (
                    f"Continuing-activity review {review.review_id} "
                    f"(cycle {review.cycle}): the window activity "
                    "is routed to a continuing filing."
                ),
            )
            case_disposition_id = minted.disposition_id

        disposition = ContinuingReviewDisposition(
            review_id=review.review_id,
            case_id=case_id,
            customer_id=case.customer_id,
            analyst_id=analyst_id,
            analyst_role=analyst_role,
            outcome=outcome,
            rationale_codes=codes,
            rationale_vocabulary_version=vocabulary,
            note=note,
            case_disposition_id=case_disposition_id,
            decided_at=_utcnow(),
        )
        item = self._evidence.add_item(
            case_id=case_id,
            kind=REVIEW_DISPOSITION_KIND,
            content=disposition.model_dump_json(indent=2).encode("utf-8"),
            source_ref=(
                f"continuing-review-disposition:"
                f"{disposition.review_disposition_id}"
            ),
            captured_by=analyst_id,
        )
        stored = disposition.model_copy(update={"evidence_seq": item.seq})
        self._reviews.add_review_disposition(stored)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=analyst_id,
                event="continuing_review_dispositioned",
                detail={
                    "review_disposition_id": stored.review_disposition_id,
                    "review_id": stored.review_id,
                    "cycle": str(review.cycle),
                    "outcome": stored.outcome.value,
                    "rationale_codes": ",".join(stored.rationale_codes),
                    "rationale_vocabulary_version": (
                        stored.rationale_vocabulary_version
                    ),
                    "case_disposition_id": stored.case_disposition_id or "",
                    "evidence_seq": str(item.seq),
                },
            )
        )
        logger.info(
            "continuing review dispositioned",
            extra={
                "case_id": case_id,
                "review_id": review.review_id,
                "outcome": stored.outcome.value,
            },
        )
        return stored
