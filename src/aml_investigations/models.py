"""Domain models for the AML alert investigation blueprint.

The case is the unit of work. An alert arrives from the monitoring
system, a case is opened around it, evidence is assembled into the
case file, and the case moves through a small set of states whose
transitions are enforced by the workflow (see ``workflow.py``), never
by convention.

Money is always ``Decimal``; the model layer never computes money —
computed findings arrive from code (typology engine, later rounds)
and are stored as evidence.
"""

from __future__ import annotations

import enum
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Annotated

from pydantic import BaseModel, Field, PlainSerializer


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class CaseStatus(str, enum.Enum):
    """Case states. The lawful edges between them live in workflow.py."""

    OPENED = "opened"
    ASSEMBLING = "assembling"
    INVESTIGATING = "investigating"
    AWAITING_ANALYST = "awaiting_analyst"
    PENDING_CONFIRMATION = "pending_confirmation"
    SAR_PENDING = "sar_pending"
    MONITORING = "monitoring"
    ESCALATED = "escalated"
    CLOSED = "closed"
    FILED_SAR = "filed_sar"


#: States from which no further transition is possible.
TERMINAL_STATUSES = frozenset({CaseStatus.CLOSED, CaseStatus.FILED_SAR})


class AlertSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ListKind(str, enum.Enum):
    """The screening list families a case is screened against (Law 3)."""

    SANCTIONS = "sanctions"
    PEP = "pep"
    ADVERSE_MEDIA = "adverse_media"


class ListEntry(BaseModel):
    """One entry on a screening list snapshot.

    ``dob`` and ``identifiers`` are the disambiguators: a name match
    alone is a *potential* hit; a name match contradicted by a
    different date of birth is the classic namesake false positive.
    """

    entry_id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    dob: date | None = None
    identifiers: list[str] = Field(
        default_factory=list,
        description="Document/registration identifiers, compared normalised.",
    )
    note: str = ""


class ListSnapshot(BaseModel):
    """An immutable, versioned snapshot of one screening list (Law 3).

    A snapshot's content can never change after ingest: a corrected
    list is a NEW snapshot with a new version. ``content_hash`` is
    computed at ingest over the canonical form of the entries, so any
    later tampering with the stored payload is detectable.
    """

    snapshot_id: str = Field(default_factory=lambda: _new_id("snap"))
    list_kind: ListKind
    version: str = Field(description="Publisher's version label, e.g. '2026.10.2'.")
    published_at: datetime
    source_note: str = Field(description="Where this snapshot came from.")
    entries: list[ListEntry] = Field(default_factory=list)
    content_hash: str = Field(
        default="",
        description="SHA-256 over the canonical entries; computed at ingest.",
    )

    @property
    def entry_count(self) -> int:
        return len(self.entries)


class ScreeningSubject(BaseModel):
    """A person or entity screened for a case: the customer, a known
    alias of the customer, or a counterparty found in the evidence."""

    subject_ref: str = Field(description="Case-local reference, e.g. the customer id.")
    name: str
    role: str = Field(description="customer | alias | counterparty")
    aliases: list[str] = Field(default_factory=list)
    dob: date | None = None
    identifiers: list[str] = Field(default_factory=list)


class ScreenedAgainst(BaseModel):
    """One line of a case's screening record: which snapshot version
    of which list the case was last screened against, and by which run."""

    list_kind: ListKind
    snapshot_id: str
    version: str
    run_id: str
    screened_at: datetime


class HitStatus(str, enum.Enum):
    OPEN = "open"
    CLEARED = "cleared"
    CONFIRMED = "confirmed"


class ScreeningHit(BaseModel):
    """One match between a case subject and a list entry.

    A hit is a record, not a verdict. ``status`` moves only by an
    analyst's recorded action (clear with a reason, or confirm),
    except for the deterministic namesake clear at match time: name
    matches but the date of birth contradicts the entry's, which is
    recorded as a cleared hit with the reason on the record — never
    silently dropped.
    """

    hit_id: str = Field(default_factory=lambda: _new_id("hit"))
    case_id: str
    run_id: str
    subject_ref: str
    subject_name: str
    subject_role: str
    list_kind: ListKind
    snapshot_id: str
    snapshot_version: str
    entry_id: str
    entry_name: str
    score: float = Field(description="Deterministic name-match score, 0..1.")
    basis: str = Field(description="Which match rules fired, in words.")
    strength: str = Field(
        default="potential",
        description="potential | strong (identifier or DOB corroboration).",
    )
    status: HitStatus = HitStatus.OPEN
    cleared_reason: str | None = None
    status_actor: str | None = None
    status_reason: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class ScreeningRun(BaseModel):
    """One screening of one case against one pinned snapshot set.

    The pin is the point (Law 3): a run names the exact snapshot
    versions it used, so a case file can always answer "screened
    against what, when" — and a later run on newer versions sits
    alongside it in the case's run history, never replacing it.
    """

    run_id: str = Field(default_factory=lambda: _new_id("run"))
    case_id: str
    actor: str
    run_at: datetime = Field(default_factory=_utcnow)
    pins: list[ScreenedAgainst] = Field(
        default_factory=list,
        description="The pinned snapshot set this run screened against.",
    )
    subject_count: int = 0
    open_hits: int = 0
    cleared_hits: int = 0
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the screening_result evidence item recording this run.",
    )
    is_rescreen: bool = False


class Alert(BaseModel):
    """An alert as delivered by the transaction-monitoring system.

    ``detected_on`` is the initial-detection date: regulatory clocks
    (SAR 30-day filing / 60-day outer limit) are computed from it in
    code, so it is stamped at intake and never edited afterwards.
    """

    alert_id: str
    rule_id: str = Field(description="Monitoring rule/scenario that fired.")
    customer_id: str
    account_id: str
    severity: AlertSeverity = AlertSeverity.MEDIUM
    detected_on: date
    summary: str = ""
    transaction_refs: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict, description="Verbatim alert payload.")


class Disposition(BaseModel):
    """A named analyst's decision on a case, recorded at the gate.

    Law 1: no case reaches ``closed`` or ``filed_sar`` without one of
    these, carrying the analyst's name and a reason code. The agent
    may draft a recommendation (later rounds); it can never record a
    disposition — only the API's analyst action can.
    """

    analyst: str = Field(min_length=1)
    decision: str = Field(description="One of: close, file_sar, escalate.")
    reason_code: str = Field(min_length=1)
    rationale: str = ""
    decided_at: datetime = Field(default_factory=_utcnow)


class Case(BaseModel):
    """The investigation case file's header record."""

    case_id: str = Field(default_factory=lambda: _new_id("case"))
    alert_id: str
    customer_id: str
    account_id: str
    rule_id: str
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: CaseStatus = CaseStatus.OPENED
    detected_on: date = Field(description="Initial-detection date (from the alert).")
    opened_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    assigned_analyst: str | None = None
    disposition: Disposition | None = None
    evidence_head_hash: str | None = Field(
        default=None,
        description="Chain hash of the most recent evidence item (chain-of-custody head).",
    )
    retention_until: date | None = Field(
        default=None,
        description="BSA 5-year retention posture, computed from closure/filing.",
    )
    legal_hold: bool = False
    screened_against: list[ScreenedAgainst] = Field(
        default_factory=list,
        description="Per-list record of the snapshot versions this case was "
        "last screened against (Law 3). Empty until the first screening run.",
    )
    screening_stale: bool = Field(
        default=False,
        description="True when a newer snapshot version exists for a list "
        "this case was screened against and the case has not been re-screened.",
    )
    flags: list[str] = Field(
        default_factory=list,
        description="Visible case flags maintained by services, e.g. "
        "STALE_SCREENING, SANCTIONS_HIT. Shown on the case record itself.",
    )


class EvidenceItem(BaseModel):
    """One immutable item in a case's evidence store.

    Once written, an item is never edited; a correction is a new item.
    ``chain_hash`` binds this item to the case's previous item:
    sha256(prev_chain_hash | content_sha256 | case_id | seq | kind).
    """

    case_id: str
    seq: int = Field(ge=1, description="Per-case sequence, starting at 1.")
    kind: str = Field(description="e.g. alert_payload, transaction_window, kyc_profile.")
    media_type: str = "application/json"
    source_ref: str = Field(description="Where the item came from (system + reference).")
    captured_by: str = Field(description="Actor (service or analyst) that captured it.")
    captured_at: datetime = Field(default_factory=_utcnow)
    object_key: str = Field(description="Key of the content blob in the object store.")
    content_sha256: str
    prev_hash: str | None = None
    chain_hash: str
    legal_hold: bool = False


class AuditEvent(BaseModel):
    """One append-only audit record. The audit log is never updated."""

    event_id: str = Field(default_factory=lambda: _new_id("evt"))
    case_id: str | None = None
    ts: datetime = Field(default_factory=_utcnow)
    actor: str
    event: str = Field(description="e.g. case_opened, transition, evidence_added, transition_refused.")
    detail: dict = Field(default_factory=dict)


class CaseSummary(BaseModel):
    """Queue-shaped view of a case (console/reporting rounds build on it)."""

    case_id: str
    alert_id: str
    customer_id: str
    account_id: str
    status: CaseStatus
    severity: AlertSeverity
    detected_on: date
    assigned_analyst: str | None = None
    evidence_items: int = 0


# Money appears in alert payloads and (later) computed findings. It is
# represented as Decimal end to end and is never computed by a model.
Money = Decimal


def _decimal_as_str(value: Decimal) -> str:
    """Render a Decimal as a plain decimal string (never scientific
    notation, never through a float), so money in JSON payloads is
    exact to the cent on every round trip."""
    return format(value, "f")


#: A Decimal that serialises to JSON as a string. JSON numbers pass
#: through binary floats in most tooling; money in this system never
#: does. Parsers still receive a Decimal on the way back in.
MoneyAmount = Annotated[
    Decimal, PlainSerializer(_decimal_as_str, return_type=str, when_used="json")
]


# ---------------------------------------------------------------------------
# Transactions, typology rules, and findings (R3, Law 4)
# ---------------------------------------------------------------------------


class Transaction(BaseModel):
    """One transaction on a subject account, as delivered by the
    core-banking feed and stored, evidence-backed, on the case.

    ``cash`` marks physical-currency transactions — the only ones the
    CTR threshold and the structuring typology speak about. ``channel``
    (branch, wire, ach, check, card, internal) is carried for the
    record; the typology rules read amount, direction, timing, and
    the cash flag.
    """

    transaction_id: str
    account_id: str
    posted_at: datetime
    direction: str = Field(description="credit | debit")
    amount: MoneyAmount = Field(gt=0)
    currency: str = "USD"
    channel: str = Field(description="branch | wire | ach | check | card | internal")
    cash: bool = False
    counterparty: str | None = None
    memo: str = ""
    balance_after: MoneyAmount | None = None


class AccountProfile(BaseModel):
    """Core-banking facts about an account that the typology engine
    reads alongside its transactions: when the account opened (the
    dormancy clock can start there), its type, and the activity the
    customer profile led the bank to expect."""

    account_id: str
    customer_id: str
    opened_on: date
    account_type: str = Field(description="e.g. personal_checking, business_checking.")
    expected_monthly_amount: MoneyAmount | None = None
    expected_monthly_count: int | None = None


class TransactionBatch(BaseModel):
    """One ingestion of transactions into a case's file.

    The batch's canonical content is captured as a hash-chained
    evidence item (``evidence_seq``) — the typology engine reads only
    the stored records this batch created, so every finding traces
    back to evidence with a hash. Re-delivering the identical batch
    for the same case is an idempotent no-op.
    """

    batch_id: str = Field(default_factory=lambda: _new_id("batch"))
    case_id: str
    account_id: str
    source_ref: str
    content_sha256: str
    transaction_count: int
    evidence_seq: int | None = None
    ingested_by: str
    ingested_at: datetime = Field(default_factory=_utcnow)


class RulePack(BaseModel):
    """A versioned pack of typology thresholds (Law 4's rules, as data).

    A pack is identified by (``pack_id``, ``version``) and is
    immutable once registered: changing a threshold means registering
    a new version, never editing this one — findings keep the version
    that produced them, and findings from different versions coexist
    and are distinguishable. ``content_hash`` is computed at
    registration over the canonical thresholds.
    """

    pack_id: str = Field(description="Rule pack family, e.g. 'harborline-typologies'.")
    version: str = Field(description="Publisher's version label, e.g. '2026.10.1'.")
    source_note: str = ""
    content_hash: str = ""

    # Structuring: cash transactions inside [band_low, ctr_threshold),
    # at least min_count of them, aggregating to at least the CTR
    # threshold inside a window.
    structuring_ctr_threshold: MoneyAmount = Decimal("10000")
    structuring_band_low: MoneyAmount = Decimal("9000")
    structuring_min_count: int = 3
    structuring_window_days: int = 7

    # Velocity: the last observation_days of the stream against the
    # account's own preceding baseline; fires on the count multiple,
    # with the amount multiple reported alongside.
    velocity_observation_days: int = 7
    velocity_min_baseline_days: int = 60
    velocity_count_multiple: Decimal = Decimal("5")
    velocity_min_observation_count: int = 5

    # Dormancy-then-burst: a gap of at least min_gap_days, then at
    # least min_burst_count transactions totalling at least
    # min_burst_amount inside burst_days of activity resuming.
    dormancy_min_gap_days: int = 180
    dormancy_burst_days: int = 3
    dormancy_min_burst_count: int = 2
    dormancy_min_burst_amount: MoneyAmount = Decimal("5000")

    # Round amounts: whole multiples of round_unit at or above
    # round_min_amount; fires on count + share + total together.
    round_unit: MoneyAmount = Decimal("1000")
    round_min_amount: MoneyAmount = Decimal("5000")
    round_min_count: int = 5
    round_min_share: Decimal = Decimal("0.5")
    round_min_total: MoneyAmount = Decimal("25000")

    # Rapid in-out: a credit of at least in_out_min_amount whose
    # funds are disbursed (pass-through fraction or more) within
    # in_out_window_hours.
    in_out_window_hours: int = 72
    in_out_min_amount: MoneyAmount = Decimal("10000")
    in_out_pass_through_fraction: Decimal = Decimal("0.9")


class TypologyRun(BaseModel):
    """One typology-engine run over one case under one rule pack.

    ``input_fingerprint`` hashes the exact stored input (transaction
    ids + batch hashes + profile), which is what makes a re-run with
    the same pack over the same input idempotent: it returns the
    existing run instead of duplicating findings or evidence. A new
    pack version — or new transactions — is a new, distinguishable
    run.
    """

    run_id: str = Field(default_factory=lambda: _new_id("trun"))
    case_id: str
    account_id: str
    actor: str
    run_at: datetime = Field(default_factory=_utcnow)
    rule_pack_id: str
    rule_pack_version: str
    input_fingerprint: str
    transaction_count: int = 0
    finding_count: int = 0
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the typology_findings evidence item recording this run.",
    )


class TypologyFinding(BaseModel):
    """One computed typology hit over a case's stored transactions.

    A finding is arithmetic, not opinion: it names the exact
    transactions involved, carries its figures as exact decimal
    strings (money never passes through a float), and records the
    rule pack id + version whose thresholds produced it. Findings are
    leads for the investigation (R4) — they decide nothing.
    """

    finding_id: str = Field(default_factory=lambda: _new_id("find"))
    case_id: str
    run_id: str
    typology_id: str = Field(
        description="structuring | velocity | dormancy_then_burst | "
        "round_amount | rapid_in_out"
    )
    variant: str | None = Field(
        default=None,
        description="Typology variant where one exists: structuring "
        "reports same_day | multi_day.",
    )
    account_id: str
    rule_pack_id: str
    rule_pack_version: str
    transaction_ids: list[str] = Field(default_factory=list)
    figures: dict[str, str] = Field(
        default_factory=dict,
        description="Computed figures, as exact decimal strings.",
    )
    window_start: date | None = None
    window_end: date | None = None
    detail: str = Field(description="The rule that fired, in words.")
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Investigation records (R4): cited findings, hypothesis discipline
# ---------------------------------------------------------------------------


class Citation(BaseModel):
    """A pointer from a finding to the specific element of a specific
    evidence item that supports it.

    ``element`` addresses one element inside the evidence item's
    content: ``finding:<finding_id>``, ``transaction:<txn_id>``,
    ``hit:<hit_id>``, ``run:<run_id>``, or ``field:<dotted.path>``
    for a field of a JSON payload. A citation that does not resolve —
    the item does not exist, or the element is not inside it — is a
    mechanical refusal at record time, never a warning.

    ``case_id`` is None for the record's own case; a prior case's
    evidence is cited with its case_id named explicitly.
    """

    case_id: str | None = None
    evidence_seq: int = Field(ge=1)
    element: str = Field(min_length=1)


class InvestigationFinding(BaseModel):
    """One finding in an investigation record.

    A finding is a statement plus its proof: every citation must
    resolve, and every figure in the statement must trace to a cited
    record or to the finding's own ``figures`` (which code computed
    from the cited records). ``direction`` is the finding's stance
    toward the record's working hypothesis — facts that cut against
    it are findings too, never edits to the supporting ones.
    """

    finding_id: str = Field(default_factory=lambda: _new_id("invf"))
    key: str = Field(
        description="Deterministic identity across record versions, "
        "e.g. 'typology:<finding_id>' — the version diff is computed over keys."
    )
    kind: str = Field(
        description="typology | screening | alert | profile | prior_case | counter"
    )
    origin: str = Field(
        description="typology | screening | alert | profile | prior_case | "
        "counter_search — where the finding's figures came from."
    )
    statement: str
    citations: list[Citation] = Field(default_factory=list)
    figures: dict[str, str] = Field(
        default_factory=dict,
        description="Figures the statement relies on, as exact decimal "
        "strings, computed by code from the cited records.",
    )
    weight: str = Field(description="high | medium | low")
    direction: str = Field(description="supports | against | context")


class CounterCheck(BaseModel):
    """One named check the counter-evidence search ran.

    The search is a step, not a label: every check that applies to
    the working hypothesis is run and recorded with its outcome,
    including the ones that found nothing and the ones that did not
    apply (with the reason)."""

    name: str
    description: str
    outcome: str = Field(
        description="counter_evidence_found | no_counter_evidence | not_applicable"
    )
    detail: str = Field(description="What the check examined and saw, in words.")
    counter_finding_ids: list[str] = Field(default_factory=list)


class CounterSearch(BaseModel):
    """The record of the counter-evidence search for one hypothesis.

    ``coverage`` states what was actually searched — the transaction
    span, the profile, the screening results — so a record with zero
    counter-findings says what was looked through, not merely that
    nothing was found.
    """

    ran: bool = True
    coverage: str
    checks: list[CounterCheck] = Field(default_factory=list)
    counter_finding_ids: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    """The investigation's working hypothesis, labelled as one.

    It names the findings that support it and the findings that cut
    against it; a hypothesis with no counter-findings still carries
    the counter-search record that looked for them.
    """

    label: str = Field(
        description="structuring | velocity | dormancy_then_burst | "
        "rapid_in_out | round_amount | sanctions_match | no_adverse_pattern"
    )
    statement: str
    supporting_finding_ids: list[str] = Field(default_factory=list)
    counter_finding_ids: list[str] = Field(default_factory=list)


class OpenQuestion(BaseModel):
    """A question the assembled evidence cannot answer, and the
    named evidence type that would answer it. An open question is a
    request for a specific kind of evidence, never a shrug."""

    question: str
    evidence_needed: str = Field(
        description="Named evidence type the case does not yet hold, "
        "e.g. 'source_of_funds_documentation'."
    )
    rationale: str = ""


class PriorCaseRef(BaseModel):
    """A reference to another case for the same customer, assembled
    into the record so the analyst sees the customer's case history.
    Findings may cite the prior case's alert evidence explicitly."""

    case_id: str
    alert_id: str
    rule_id: str
    status: str
    detected_on: date


class RecordDiff(BaseModel):
    """How one investigation record differs from the version it
    supersedes, computed over finding keys (added / removed /
    changed) plus whether the working hypothesis moved."""

    from_version: int
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    changed: list[str] = Field(default_factory=list)
    hypothesis_changed: bool = False


class InvestigationRecord(BaseModel):
    """One version of a case's investigation.

    The record separates facts (findings, each cited), the working
    hypothesis (labelled, with its support and its counter-evidence),
    and open questions (each naming the evidence that would resolve
    it). The record itself is stored as a hash-chained evidence item
    (kind ``investigation_record``); a re-run after new evidence
    arrives produces the next version, which supersedes this one in
    the case view while this one stays on the chain.
    """

    record_id: str = Field(default_factory=lambda: _new_id("inv"))
    case_id: str
    version: int = Field(ge=1)

    actor: str
    model_profile: str = Field(
        default="offline",
        description="Composer profile that produced the narrative text. "
        "'offline' is the deterministic stand-in; a live profile is a "
        "different composer behind the same port, never a silent swap.",
    )
    created_at: datetime = Field(default_factory=_utcnow)
    input_fingerprint: str = Field(
        description="Hash of the exact assembled inputs. A re-run over "
        "identical inputs returns the existing record (idempotent)."
    )
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the investigation_record evidence item holding this record.",
    )
    supersedes_record_id: str | None = None
    findings: list[InvestigationFinding] = Field(default_factory=list)
    hypothesis: Hypothesis
    counter_search: CounterSearch
    open_questions: list[OpenQuestion] = Field(default_factory=list)
    prior_case_refs: list[PriorCaseRef] = Field(default_factory=list)
    diff: RecordDiff | None = None


# ---------------------------------------------------------------------------
# Dispositions (R5): the analyst gate — Law 1, with depth
# ---------------------------------------------------------------------------


class DispositionOutcome(str, enum.Enum):
    """The coded outcomes an analyst disposition can record (R5).

    These are the gate's vocabulary, deliberately smaller and more
    precise than the R1 transition decisions: a disposition routes
    the case — it closes it, watches it, escalates it, or sends it
    back — and each outcome carries its own coded rationale set
    (see ``dispositions.py``).
    """

    CLOSE_NO_ACTION = "close_no_action"
    CLOSE_MONITOR = "close_monitor"
    ESCALATE_SAR = "escalate_sar"
    ESCALATE_L2 = "escalate_l2"
    REQUEST_MORE_EVIDENCE = "request_more_evidence"


class DispositionRecord(BaseModel):
    """One analyst disposition of one case, recorded at the gate (R5).

    The R1 :class:`Disposition` is the state machine's closing
    token; this is the fuller artefact the gate keeps: who decided
    (a named analyst id and a coded role — anonymous and system
    actors are refused by the service, mechanically), what they
    decided (a coded outcome with coded rationale from a versioned
    vocabulary — free text may supplement, never substitute), and
    which investigation-record version the decision relied on.

    Records are append-only: a later disposition supersedes this
    one in the case view, but this record is never edited. The full
    record is also captured as a hash-chained evidence item (kind
    ``disposition``), so the decision sits on the case's
    chain-of-custody like everything else.
    """

    disposition_id: str = Field(default_factory=lambda: _new_id("disp"))
    case_id: str
    analyst_id: str = Field(min_length=1)
    analyst_role: str = Field(
        description="Coded role: analyst | senior_analyst | l2_reviewer."
    )
    outcome: DispositionOutcome
    rationale_codes: list[str] = Field(
        min_length=1,
        description="Coded rationale from the outcome's set in the "
        "versioned vocabulary. Free text alone is refused at the gate.",
    )
    rationale_vocabulary_version: str
    note: str = Field(
        default="",
        description="Free-text supplement. Never a substitute for codes.",
    )
    record_id: str = Field(
        description="The investigation record the analyst relied on."
    )
    record_version: int = Field(
        ge=1,
        description="That record's version. The gate refuses a "
        "citation of anything but the case's current record.",
    )
    requires_confirmation: bool = Field(
        default=False,
        description="True when this closure needs a second pair of "
        "eyes: a close_no_action over an adverse hypothesis. The "
        "closure takes effect only when an L2 reviewer confirms — "
        "see DispositionConfirmation.",
    )
    review_period_days: int | None = Field(
        default=None,
        description="close_monitor only: the enhanced-monitoring "
        "review period, in days.",
    )
    review_due_on: date | None = Field(
        default=None,
        description="close_monitor only: decided date + the review "
        "period — the date the monitoring review falls due.",
    )
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="request_more_evidence only: the named evidence "
        "types the case still needs, in the R4 open-question "
        "vocabulary (e.g. 'source_of_funds_documentation').",
    )
    decided_at: datetime = Field(default_factory=_utcnow)
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the disposition evidence item holding this record.",
    )


class ConfirmationOutcome(str, enum.Enum):
    CONFIRMED = "confirmed"
    DECLINED = "declined"


class DispositionConfirmation(BaseModel):
    """A second person's answer to a pending-confirmation disposition.

    Dual-control at the gate (Law 1's depth, R5): a close_no_action
    over an adverse hypothesis does not close the case until an L2
    reviewer — a different named analyst from the one who
    dispositioned — confirms it. The confirmer's own refusal to
    confirm is recorded the same way, with the case sent back to
    investigation. Like dispositions, confirmations are append-only
    records and hash-chained evidence items (kind
    ``disposition_confirmation``).
    """

    confirmation_id: str = Field(default_factory=lambda: _new_id("conf"))
    disposition_id: str
    case_id: str
    confirmer_id: str = Field(min_length=1)
    confirmer_role: str = Field(
        description="Must be the L2 role ('l2_reviewer'); enforced by the service."
    )
    outcome: ConfirmationOutcome
    note: str = ""
    decided_at: datetime = Field(default_factory=_utcnow)
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the disposition_confirmation evidence item.",
    )


# ---------------------------------------------------------------------------
# SAR narratives (R6): drafting + the citation verifier — Law 2
# ---------------------------------------------------------------------------


class NarrativeStatement(BaseModel):
    """One factual statement in a SAR narrative draft.

    A statement is text plus its proof, in the same discipline as
    an investigation finding: ``citations`` name the evidence
    elements it restates, ``finding_ids`` name the investigation
    findings it is bound to, ``values`` are the exact slot values
    the composer read out of the cited elements, and ``figures``
    are the money/quantity figures it relies on — every one of them
    must appear in the cited records. The citation verifier
    (``sar.py``) re-checks all of this in code over the finished
    narrative; a statement that fails is named, and the narrative
    cannot be marked verified while any statement fails.
    """

    statement_id: str = Field(
        description="Deterministic within the narrative, "
        "e.g. 'amounts_and_instruments-2' — verdicts name it."
    )
    text: str
    citations: list[Citation] = Field(default_factory=list)
    finding_ids: list[str] = Field(
        default_factory=list,
        description="Investigation findings (of the cited record) "
        "this statement restates. Every id must exist in that record.",
    )
    values: dict[str, str] = Field(
        default_factory=dict,
        description="Slot values the statement asserts, each read "
        "from a cited element. The verifier requires every value "
        "to appear in the cited records.",
    )
    figures: dict[str, str] = Field(
        default_factory=dict,
        description="Figures the statement relies on, as exact "
        "decimal strings copied from the cited records — never "
        "computed by the drafting model (Law 4).",
    )


class NarrativeSection(BaseModel):
    """One named section of the narrative, in filing order."""

    key: str = Field(
        description="subject_identification | activity_summary | "
        "chronology | amounts_and_instruments | branch_office_facts | "
        "what_remains_unknown"
    )
    title: str
    statements: list[NarrativeStatement] = Field(default_factory=list)


class SarNarrative(BaseModel):
    """One version of a case's SAR narrative draft (R6).

    The narrative is assembled from the case's current investigation
    record and the escalate_sar disposition that routed the case —
    both pinned here by id and version, so the draft always says
    what it was drafted from. Drafts are append-only versions: a
    re-draft after new evidence is the next version and supersedes
    this one in the case view; this one stays on the record. The
    full draft is captured as a hash-chained evidence item (kind
    ``sar_narrative``).

    ``status`` is deliberately not a stored field: standing is
    derived (see ``SarNarrativeService.status_of``) — superseded by
    a newer draft, stale when the record it cites has been
    superseded, verified when the citation verifier's latest
    verdict passes every statement, draft otherwise. A narrative
    in this round is never approved and never filed: approval is
    R7's dual-control gate, and no SAR is ever filed by this system.
    """

    narrative_id: str = Field(default_factory=lambda: _new_id("sar"))
    case_id: str
    version: int = Field(ge=1)
    record_id: str = Field(
        description="The investigation record the narrative is drafted from."
    )
    record_version: int = Field(ge=1)
    disposition_id: str = Field(
        description="The escalate_sar disposition that routed the case "
        "to SAR drafting. Drafting without one is refused."
    )
    model_profile: str = Field(
        default="offline",
        description="Composer profile that produced the text. "
        "'offline' is the deterministic composer; a live profile is "
        "a different composer behind the same port, never a silent swap.",
    )
    drafted_by: str = Field(
        description="Actor that ran the drafting (a service or an "
        "analyst running it by hand). Drafting is the agent's work; "
        "deciding is not — no disposition rights attach to this field."
    )
    created_at: datetime = Field(default_factory=_utcnow)
    supersedes_narrative_id: str | None = None
    sections: list[NarrativeSection] = Field(default_factory=list)
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the sar_narrative evidence item holding this draft.",
    )

    def render_text(self) -> str:
        """The narrative as plain text, sections in filing order —
        the artefact a human reviewer reads (and R7's gate seals)."""
        lines: list[str] = []
        for section in self.sections:
            lines.append(f"## {section.title}")
            for statement in section.statements:
                lines.append(statement.text)
            lines.append("")
        return "\n".join(lines).strip() + "\n"


class StatementVerdict(BaseModel):
    """The citation verifier's verdict on one narrative statement."""

    statement_id: str
    section_key: str
    verified: bool
    problems: list[str] = Field(
        default_factory=list,
        description="Every reason the statement failed, in words. "
        "Empty iff verified.",
    )


class NarrativeVerification(BaseModel):
    """One run of the citation verifier over one narrative draft.

    Verification is its own stored record — per-statement verdicts,
    plus narrative-level problems (a missing section, an open
    question the draft failed to carry, no statable flagged total).
    ``all_verified`` is true only when every statement verifies and
    there are no narrative-level problems: that, and nothing else,
    is what lets a narrative stand as VERIFIED — ready for R7's
    dual-control approval, never approved or filed by R6 itself.
    Verification runs are append-only; the latest run for a
    narrative is the one its standing derives from. The record is
    also captured as a hash-chained evidence item (kind
    ``sar_narrative_verification``).
    """

    verification_id: str = Field(default_factory=lambda: _new_id("sarv"))
    narrative_id: str
    case_id: str
    verified_at: datetime = Field(default_factory=_utcnow)
    verifier: str = Field(
        default="citation-verifier",
        description="The verifying code's identity. Verification is "
        "a code act, never a model judgement.",
    )
    all_verified: bool = False
    statement_verdicts: list[StatementVerdict] = Field(default_factory=list)
    narrative_problems: list[str] = Field(default_factory=list)
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the sar_narrative_verification evidence item.",
    )
