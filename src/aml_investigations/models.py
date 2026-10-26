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
        description="typology | screening | alert | profile | prior_case | "
        "media | counter"
    )
    origin: str = Field(
        description="typology | screening | alert | profile | prior_case | "
        "media | counter_search — where the finding's figures came from."
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
    superseded, approved or rejected once the dual-control gate
    (R7) has decided this version, verified when the citation
    verifier's latest verdict passes every statement, draft
    otherwise. Approved or not, a narrative is never filed: no SAR
    is ever filed by this system.
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


# ---------------------------------------------------------------------------
# Dual-control approval, sealing, legal hold, export (R7):
# Law 2's second half + Law 5's custody completion
# ---------------------------------------------------------------------------


class ApprovalOutcome(str, enum.Enum):
    """The second person's decision on a verified SAR narrative."""

    APPROVED = "approved"
    REJECTED = "rejected"


class SarApproval(BaseModel):
    """A second person's decision on one SAR narrative version (R7).

    Dual control (Law 2): the approver may be neither the analyst
    who recorded the escalate_sar disposition nor the actor who
    drafted the narrative — both refusals are mechanical, at the
    gate, before anything is recorded. An approval answers exactly
    one narrative version (pinned here with the record and
    disposition it was drafted from); a rejection carries coded
    reasons from a versioned vocabulary and returns the narrative
    to drafting standing. Approvals are append-only records and
    hash-chained evidence items (kind ``sar_approval``).

    An approved narrative is still not a filing: **no SAR is ever
    filed by this system.** Approval completes the case file; the
    file is then sealed (see :class:`CaseSeal`).
    """

    approval_id: str = Field(default_factory=lambda: _new_id("appr"))
    case_id: str
    narrative_id: str = Field(
        description="The narrative version this decision answers. "
        "A narrative version is decided exactly once."
    )
    narrative_version: int = Field(ge=1)
    record_id: str = Field(
        description="The investigation record the narrative was drafted from."
    )
    record_version: int = Field(ge=1)
    disposition_id: str = Field(
        description="The escalate_sar disposition that routed the case. "
        "Its analyst is barred from approving (dual control)."
    )
    approver_id: str = Field(min_length=1)
    approver_role: str = Field(
        description="Coded role: analyst | senior_analyst | l2_reviewer."
    )
    outcome: ApprovalOutcome
    reason_codes: list[str] = Field(
        default_factory=list,
        description="Rejection only: coded reasons from the versioned "
        "vocabulary. An approval carries none — free text never "
        "substitutes for codes, and codes never decorate an approval.",
    )
    reason_vocabulary_version: str = Field(
        default="",
        description="Vocabulary version the rejection codes were "
        "drawn from. Empty for approvals.",
    )
    note: str = Field(
        default="",
        description="Free-text supplement. Never a substitute for codes.",
    )
    decided_at: datetime = Field(default_factory=_utcnow)
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the sar_approval evidence item holding this record.",
    )


class SealManifestItem(BaseModel):
    """One evidence item as a seal certifies it: its position, its
    kind, and the two hashes the chain binds it with."""

    seq: int = Field(ge=1)
    kind: str
    content_sha256: str
    chain_hash: str


class ArtefactPin(BaseModel):
    """One case artefact as a seal manifest references it: the
    artefact kind, its id, its version where it has one, and a
    short detail (an outcome, a verdict) where that is the fact
    the seal certifies."""

    kind: str = Field(
        description="investigation_record | disposition | sar_narrative | "
        "sar_narrative_verification | sar_approval"
    )
    artefact_id: str
    version: int | None = None
    detail: str = ""


class CaseSealManifest(BaseModel):
    """What a seal certifies, in full.

    The manifest lists *every* evidence item on the case at seal
    time (seq, kind, content hash, chain hash), the chain head
    those items produce, and the case's operative artefacts
    (record, dispositions, narrative, verification, approval) by
    id and version. The seal's hash is computed over this
    manifest's canonical JSON — an export package that drops,
    alters, or adds an item cannot reproduce it.
    """

    case_id: str
    chain_head_hash: str = Field(
        description="The case's evidence chain head at seal time — "
        "the hash the manifest's items recompute to. The seal's own "
        "evidence item extends the chain by one beyond this head."
    )
    items: list[SealManifestItem] = Field(default_factory=list)
    artefacts: list[ArtefactPin] = Field(default_factory=list)


class CaseSeal(BaseModel):
    """One sealing of one case file (R7).

    Sealing is a named officer's act over a case in a terminal
    state (``closed``, or ``filed_sar`` once its narrative stands
    approved). The seal certifies the manifest with a hash; from
    that moment the case file is read-only — every mutating
    service path refuses on it — until a named officer unseals it
    with a coded reason. Seals are append-only: a reseal after an
    unseal is the next seal version, and earlier seals stay in the
    history exactly as recorded. The seal is also a hash-chained
    evidence item (kind ``case_seal``).

    Retention is stated on the seal: the BSA five-year basis, the
    retention date it produces, and the legal-hold state at seal
    time. Retention never authorises destruction in this system —
    no purge path exists anywhere in the blueprint, and a legal
    hold would bar one if it ever did.
    """

    seal_id: str = Field(default_factory=lambda: _new_id("seal"))
    case_id: str
    version: int = Field(ge=1, description="Seal version for the case: 1, 2, ...")
    sealed_by: str = Field(min_length=1)
    sealed_role: str = Field(
        description="Coded officer role: senior_analyst | l2_reviewer."
    )
    sealed_at: datetime = Field(default_factory=_utcnow)
    purpose: str = Field(
        default="custody",
        description="custody | archive. An archive seal is refused "
        "while a legal hold stands on the case.",
    )
    manifest: CaseSealManifest
    seal_hash: str = Field(
        description="SHA-256 over the manifest's canonical JSON — "
        "the seal's certificate over everything the manifest lists."
    )
    retention_basis: str = Field(
        description="The retention rule the seal records, in words "
        "(BSA five-year retention posture)."
    )
    retention_until: date = Field(
        description="Sealed date + five years: the date through "
        "which the sealed file is retained under the stated basis."
    )
    legal_hold: bool = Field(
        default=False,
        description="The case's legal-hold state at seal time. A "
        "hold suspends any archive or purge consequence of retention.",
    )
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the case_seal evidence item holding this record.",
    )


class CaseUnseal(BaseModel):
    """A named officer lifting one seal, with a coded reason (R7).

    Unsealing never edits or removes the seal it lifts: it is its
    own append-only record (and a hash-chained evidence item, kind
    ``case_unseal``), and the seal history keeps both. While
    unsealed, the case is mutable again — and a later reseal
    certifies the file as it then stands, as the next seal version.
    """

    unseal_id: str = Field(default_factory=lambda: _new_id("unseal"))
    case_id: str
    seal_id: str = Field(description="The seal this unseal lifts.")
    unsealed_by: str = Field(min_length=1)
    unsealed_role: str = Field(
        description="Coded officer role: senior_analyst | l2_reviewer."
    )
    reason_code: str = Field(
        description="Coded reason from the unseal vocabulary."
    )
    note: str = ""
    unsealed_at: datetime = Field(default_factory=_utcnow)
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the case_unseal evidence item holding this record.",
    )


class LegalHoldEvent(BaseModel):
    """One placing or releasing of a legal hold on a case (R7).

    A legal hold is placed and released by a named officer, with a
    coded reason each way; the events are append-only and
    hash-chained (kind ``legal_hold``), and the case's hold state
    is derived from the latest event. A hold in force bars an
    archive seal, suspends any retention consequence, and would
    bar any purge path — none exists in this system, and the hold
    is recorded so that remains a governed fact, not a hope.
    """

    hold_event_id: str = Field(default_factory=lambda: _new_id("hold"))
    case_id: str
    action: str = Field(description="placed | released")
    officer_id: str = Field(min_length=1)
    officer_role: str = Field(
        description="Coded officer role: senior_analyst | l2_reviewer."
    )
    reason_code: str = Field(
        description="Coded reason from the hold (or hold-release) vocabulary."
    )
    note: str = ""
    recorded_at: datetime = Field(default_factory=_utcnow)
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the legal_hold evidence item holding this event.",
    )


# ---------------------------------------------------------------------------
# Regulatory clocks (R8): Law 6 — deadlines computed in code
# ---------------------------------------------------------------------------


class ClockState(str, enum.Enum):
    """A regulatory clock's state, derived — never stored as text.

    A live clock moves ``on_track`` -> ``due_soon`` -> ``due`` ->
    ``overdue`` by pure date arithmetic against its operative
    deadline. A clock ends ``satisfied`` (the case reached
    ``filed_sar``) or ``closed_no_file`` (a documented no-file
    decision at the analyst gate). ``not_applicable`` is the
    vocabulary's remainder — a clock kind that does not apply to
    the case at hand.
    """

    ON_TRACK = "on_track"
    DUE_SOON = "due_soon"
    DUE = "due"
    OVERDUE = "overdue"
    SATISFIED = "satisfied"
    CLOSED_NO_FILE = "closed_no_file"
    NOT_APPLICABLE = "not_applicable"


class FilingClock(BaseModel):
    """One case's SAR filing clock, computed in code (Law 6).

    The deadlines are pure date arithmetic over the case's
    initial-detection date: the SAR initial deadline is detection
    + 30 calendar days; where the record identifies no subject,
    FinCEN's outer limit — detection + 60 days — is the operative
    deadline instead. ``subject_identified`` is itself derived
    from the record (the alert payload's subject facts, or a
    corroborated screening hit), never an analyst's say-so: the
    extension to the outer deadline is a coded state, not a
    favour someone grants a case.

    ``state`` and ``days_remaining`` are computed against the
    ``as_of`` the caller names — the clock computation reads no
    wall clock, so a board rendered for a date is reproducible
    for that date. When the clock has ended (``satisfied`` /
    ``closed_no_file``) ``days_remaining`` is None and, for a
    no-file ending, the closing disposition is named with its
    coded rationale: that rationale *is* the no-file
    documentation (Law 6).
    """

    case_id: str
    customer_id: str
    detected_on: date
    subject_identified: bool
    subject_basis: str = Field(
        description="alert_payload | screening_hit | none — where "
        "the identification (or its absence) was read from."
    )
    initial_deadline: date
    outer_deadline: date
    operative_deadline: date
    operative_deadline_kind: str = Field(
        description="initial | outer — which deadline governs."
    )
    state: ClockState
    days_remaining: int | None = Field(
        default=None,
        description="operative_deadline - as_of, signed. Negative "
        "is days overdue. None once the clock has ended.",
    )
    as_of: date
    no_file_disposition_id: str | None = Field(
        default=None,
        description="closed_no_file only: the disposition record "
        "whose coded rationale documents the no-file decision.",
    )
    no_file_rationale_codes: list[str] = Field(default_factory=list)
    no_file_decided_on: date | None = None
    monitor_review_due_on: date | None = Field(
        default=None,
        description="When the no-file decision was close_monitor: "
        "the date its enhanced-monitoring review falls due.",
    )


class ContinuingActivityLink(BaseModel):
    """The trigger record of a continuing-activity clock (R8).

    Written onto the *new* case's evidence chain (kind
    ``continuing_activity_link``) at intake, when a new alert
    opens for a customer with a prior ``filed_sar`` case: the
    link names the prior case and the filing determination date
    every continuing deadline is computed from. The full review
    workflow over this clock is R9; R8 starts the clock and
    escalates it.
    """

    prior_case_id: str
    customer_id: str
    determination_on: date = Field(
        description="The date the prior case's filing "
        "determination was made (its approval / closing "
        "disposition date)."
    )
    review_due_on: date = Field(
        description="determination_on + 90 days (FinCEN "
        "continuing-activity review)."
    )
    filing_due_on: date = Field(
        description="determination_on + 120 days (the continuing "
        "filing deadline)."
    )
    new_case_detected_on: date


class ContinuingActivityClock(BaseModel):
    """One case's continuing-activity clock, computed in code.

    Started by a :class:`ContinuingActivityLink` on the case.
    Until the review deadline the operative deadline is the
    90-day review; once that date passes unmet, the operative
    deadline becomes the 120-day filing deadline and
    ``review_overdue`` says the review date went by. The clock
    ends with the case: ``satisfied`` at ``filed_sar``,
    ``closed_no_file`` at a documented no-file decision.
    """

    case_id: str
    prior_case_id: str
    customer_id: str
    determination_on: date
    review_due_on: date
    filing_due_on: date
    review_overdue: bool = False
    operative_deadline: date
    operative_deadline_kind: str = Field(
        description="continuing_review | continuing_filing"
    )
    state: ClockState
    days_remaining: int | None = None
    as_of: date
    link_evidence_seq: int | None = Field(
        default=None,
        description="Seq of the continuing_activity_link evidence "
        "item that started this clock.",
    )
    cycle: int = Field(
        default=1,
        description="R9: which continuing-activity cycle this "
        "clock is for. Cycle 1 derives from the link; a no-file "
        "review disposition starts the next cycle from its own "
        "determination date (rolling 90/120).",
    )
    prior_review_id: str | None = Field(
        default=None,
        description="R9: the review whose no-file decision "
        "started this cycle — the explicit cycle chain. None on "
        "cycle 1.",
    )
    answered_by_review_id: str | None = Field(
        default=None,
        description="R9: the review whose recorded disposition "
        "answered this cycle's clock, when one did. A review "
        "opened but not dispositioned never appears here — it "
        "does not satisfy the clock.",
    )
    answered_outcome: str | None = Field(
        default=None,
        description="R9: the answering review disposition's "
        "outcome (a ReviewOutcome value), when one answered.",
    )


class ClockEscalationEvent(BaseModel):
    """One recorded crossing of a clock into due / overdue (R8).

    Escalation is a case event, not a sort order: the first time
    a refresh finds a clock at ``due`` or ``overdue`` for a given
    deadline, the crossing is written onto the case's evidence
    chain (kind ``clock_escalation``) with the deadline it names.
    Idempotent by construction — the recorded events are read
    back before any new one is written, so re-computation never
    duplicates a crossing.
    """

    event_id: str = Field(default_factory=lambda: _new_id("cesc"))
    case_id: str
    clock_kind: str = Field(description="filing | continuing_activity")
    deadline_kind: str = Field(
        description="initial | outer | continuing_review | "
        "continuing_filing — the deadline that was crossed."
    )
    deadline: date
    state: str = Field(description="due | overdue — the state at the crossing.")
    as_of: date
    days_overdue: int = Field(
        default=0, description="Days past the deadline at the crossing."
    )
    recorded_at: datetime = Field(default_factory=_utcnow)
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the clock_escalation evidence item.",
    )


class CaseClocks(BaseModel):
    """A case's full clock picture at an ``as_of``: its filing
    clock, its continuing-activity clock when one was started,
    the escalation events recorded on it, and any clock
    violations the derivation found (a terminal case with no
    disposition on record is a violation here, never a silence).
    """

    case_id: str
    customer_id: str
    status: CaseStatus
    as_of: date
    filing: FilingClock
    continuing_activity: ContinuingActivityClock | None = None
    continuing_history: list[ContinuingActivityClock] = Field(
        default_factory=list,
        description="R9: every continuing-activity cycle's clock, "
        "oldest first — the answered cycles with the review that "
        "answered them, and the live cycle last. Empty when no "
        "continuing clock was started.",
    )
    escalations: list[ClockEscalationEvent] = Field(default_factory=list)
    violations: list[str] = Field(default_factory=list)


class EscalationQueueEntry(BaseModel):
    """One entry of the clock escalation queue: a clock standing
    at due_soon, due, or overdue, with the deadline it answers to
    named in words. Satisfied and closed clocks never appear."""

    case_id: str
    customer_id: str
    clock_kind: str = Field(description="filing | continuing_activity")
    deadline_kind: str
    deadline: date
    state: ClockState
    days_remaining: int = Field(
        description="Signed: negative is days overdue."
    )
    reason: str = Field(
        description="The named deadline and the time to it, in "
        "words — the reason this entry stands in the queue."
    )


# ------------------------------------------------------------------
# Continuing-activity reviews (R9) — the workflow answering R8's
# continuing-activity clock. When a subject returns after a prior
# SAR filing, the BSA posture asks one question per cycle: has the
# activity continued, and is a continuing SAR being filed? R8
# started the clock (review due at determination + 90, filing due
# at + 120); R9 records the review that answers it. One
# ContinuingReview is assembled per cycle — window activity, each
# item cited under the R4 citation discipline, a coded assessment
# of whether the window activity continues the filed typology,
# open questions — and one ContinuingReviewDisposition, a named
# analyst's recorded decision, is the ONLY thing that answers the
# clock for that cycle. A no-file decision ends the cycle and
# starts the next cycle's clock from its own determination date
# (rolling 90/120), chained explicitly by review id.


class ReviewOutcome(str, enum.Enum):
    """The cycle's decision: a continuing filing is due (the
    linked case is routed to the R6 narrative path), or no filing
    this cycle (documented on the clock by coded rationale)."""

    FILE_CONTINUING = "file_continuing"
    NO_FILE_THIS_CYCLE = "no_file_this_cycle"


class ReviewActivityItem(BaseModel):
    """One gathered piece of window activity, cited.

    ``statement`` is assembled from cited evidence text only;
    ``citations`` resolve under the case's own CitationResolver —
    no new resolver exists for this round. ``refs`` carries the
    machine references (case and alert ids the statement speaks
    of) as data, so the statement itself never has to name an
    identifier its citations cannot ground.
    """

    kind: str = Field(
        description="prior_filing | window_alert | "
        "window_transactions | record_hypothesis | "
        "typology_finding | screening_state"
    )
    statement: str
    citations: list[Citation] = Field(min_length=1)
    figures: dict[str, str] = Field(default_factory=dict)
    refs: dict[str, str] = Field(default_factory=dict)


class ContinuingReview(BaseModel):
    """One cycle's review artefact. Immutable once assembled: it
    cites the linked case's investigation record by id and version,
    and if that record is superseded the review stands stale — a
    fresh review is opened in its place (``supersedes_review_id``),
    never an edit. ``prior_review_id`` chains the cycles: cycle
    N's review names cycle N−1's dispositioned review, whose
    no-file determination started this cycle's clock."""

    review_id: str = Field(default_factory=lambda: _new_id("crev"))
    case_id: str
    customer_id: str
    prior_case_id: str
    cycle: int = Field(ge=1)
    prior_review_id: str | None = None
    supersedes_review_id: str | None = None
    determination_on: date = Field(
        description="The determination that started this cycle: "
        "for cycle 1, the prior case's SAR determination; for "
        "later cycles, the prior cycle's no-file decision date."
    )
    review_due_on: date = Field(description="determination + 90 days")
    filing_due_on: date = Field(description="determination + 120 days")
    record_id: str = Field(
        description="The linked case's investigation record the "
        "review is assembled over, cited exactly."
    )
    record_version: int
    filed_typology_label: str = Field(
        description="The hypothesis label the prior case filed "
        "on — the typology continuation is assessed against."
    )
    prior_narrative_id: str | None = Field(
        default=None,
        description="The prior case's completed narrative, "
        "cited by the review's prior-filing item.",
    )
    activity: list[ReviewActivityItem] = Field(default_factory=list)
    continuation_assessment: str = Field(
        description="Coded, derived in code from the filed "
        "typology and the current record's hypothesis and "
        "findings: continues_filed_typology | "
        "new_pattern_in_window | no_adverse_activity_in_window | "
        "activity_unrelated_to_filing"
    )
    assessment_basis: str = Field(
        description="How the coded assessment was derived, in "
        "words — never a free-text substitute for the code."
    )
    open_questions: list[OpenQuestion] = Field(default_factory=list)
    opened_by: str = Field(
        description="The named analyst who opened the review, "
        "or the scheduler tick's actor — recorded either way."
    )
    opened_at: datetime
    evidence_seq: int | None = None


class ContinuingReviewDisposition(BaseModel):
    """A named analyst's recorded decision for one cycle.

    Append-only, like every decision artefact in this system: the
    decision is never edited, and a dispositioned review is
    immutable. For a file-continuing decision,
    ``case_disposition_id`` names the escalate_sar case
    disposition the decision minted through the R5 gate — the
    routing into the R6 narrative path — and
    ``rationale_codes`` are drawn from that gate's escalate_sar
    vocabulary. For a no-file decision the codes are drawn from
    the review vocabulary family, and they are the cycle's
    documentation on the clock.
    """

    review_disposition_id: str = Field(
        default_factory=lambda: _new_id("crevd")
    )
    review_id: str
    case_id: str
    customer_id: str
    analyst_id: str
    analyst_role: str
    outcome: ReviewOutcome
    rationale_codes: list[str] = Field(min_length=1)
    rationale_vocabulary_version: str
    note: str = ""
    case_disposition_id: str | None = Field(
        default=None,
        description="file_continuing only: the escalate_sar case "
        "disposition minted through the disposition gate.",
    )
    decided_at: datetime
    evidence_seq: int | None = None


# ---------------------------------------------------------------------------
# Quarantine (R10, Law 7): instructions inside evidence are case events
# ---------------------------------------------------------------------------


class QuarantineMatch(BaseModel):
    """One instruction-pattern match inside one text field.

    The span addresses the field's own string (``start``/``end``
    character offsets), and ``excerpt`` is the matched text itself —
    kept on the record so an analyst can see exactly what the
    scanner saw without re-reading the evidence item.
    """

    pattern_id: str = Field(description="e.g. override.instructions.")
    family: str = Field(
        description="override | roleplay | system_marker | "
        "case_directive | output_directive | encoded_payload"
    )
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    excerpt: str


class QuarantineField(BaseModel):
    """Every match inside one named text field of one evidence item.

    Field labels name where the text lives: ``summary`` and
    ``raw.<path>`` on the alert payload, ``transaction:<id>.memo``
    and ``transaction:<id>.counterparty`` on a transaction batch,
    ``hit:<id>.subject_name`` / ``hit:<id>.entry_name`` on a
    screening result, ``content`` on a document item. The label is
    the join key between the quarantine record, the fencing the
    composers apply, and the spans the verifiers exclude from the
    groundable token set.
    """

    field: str
    matches: list[QuarantineMatch] = Field(min_length=1)


class QuarantineRecord(BaseModel):
    """One quarantine event: an item's untrusted text matched the
    instruction pattern pack at ingestion.

    Stored as a hash-chained evidence item (kind
    ``quarantine_event``) and nothing else — quarantine state is
    derived from the chain like seals and clocks. The evidence item
    itself is NOT rejected and NOT edited (Law 5): the record points
    at it, and the point is what fences it everywhere it is
    consumed. ``quarantine_seq`` is the seq of the quarantine_event
    item itself, assigned by the reader from the chain position —
    the stored content carries everything else.
    """

    case_id: str
    quarantine_seq: int = Field(
        default=0,
        description="Seq of the quarantine_event evidence item "
        "(assigned from the chain when read; 0 in stored content).",
    )
    source_kind: str = Field(
        description="alert_payload | transaction_batch | "
        "screening_result | evidence_document"
    )
    evidence_seq: int = Field(
        description="Seq of the evidence item whose text matched."
    )
    pack_version: str
    fields: list[QuarantineField] = Field(min_length=1)
    recorded_by: str
    recorded_at: datetime = Field(default_factory=_utcnow)


class QuarantineReview(BaseModel):
    """A named analyst's review of one quarantine record (R10).

    An audit act, recorded as a hash-chained evidence item (kind
    ``quarantine_review``). Review never un-fences the content:
    the fences derive from the quarantine record, which is
    append-only, so a reviewed item is consumed exactly as
    fenced as an unreviewed one.
    """

    case_id: str
    quarantine_seq: int = Field(
        description="Seq of the quarantine_event item reviewed."
    )
    reviewer: str
    note: str = ""
    reviewed_at: datetime = Field(default_factory=_utcnow)
    evidence_seq: int | None = None


class QuarantineQueueEntry(BaseModel):
    """One row of the cross-case quarantine queue (R10)."""

    case_id: str
    customer_id: str
    case_status: CaseStatus
    quarantine_seq: int
    source_kind: str
    evidence_seq: int
    fields: list[str] = Field(default_factory=list)
    pattern_ids: list[str] = Field(default_factory=list)
    families: list[str] = Field(default_factory=list)
    status: str = Field(description="flagged | reviewed")
    reviewed_by: str | None = None


class ExportVerification(BaseModel):
    """The offline verdict on one exported case-file package (R7).

    Produced by re-checking the package end to end, with no store
    and no network: every manifest item's content present and
    hashing to its certified value, the chain recomputing link by
    link to the manifest's head, and the seal hash reproducing
    over the manifest. ``problems`` names every failure — an
    altered item is named by its seq — and ``ok`` is true only
    when there are none.
    """

    case_id: str = ""
    seal_id: str = ""
    ok: bool = False
    items_checked: int = 0
    problems: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# KYC profile assembly + counterparty views (R11)
# ---------------------------------------------------------------------------


class IdentityFact(BaseModel):
    """One identity fact about a customer, with its provenance.

    A fact is never hand-entered into a profile view: it is read
    out of a stored artefact, and it carries that artefact with it
    — the source kind, the case it came from, and (where the source
    is an evidence item) the item's chain position. Two sources
    disagreeing about the same field produce two facts and an
    :class:`IdentityConflict`; the assembly never merges, picks,
    or averages them away.
    """

    field: str = Field(description="name | dob | identifier")
    value: str = Field(
        description="The value exactly as recorded at the source."
    )
    source_kind: str = Field(
        description="alert_payload | screening — the stored artefact "
        "this fact was read from."
    )
    source_case_id: str
    source_ref: str = Field(
        description="Human-readable pointer at the source, e.g. "
        "'alert ALRT-2026-1001 raw payload' or 'screening hit hit-…'."
    )
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the evidence item holding the source, "
        "when the source is one (alert payload, screening result).",
    )


class IdentityConflict(BaseModel):
    """A field on which the stored sources disagree.

    The conflict is the finding: every distinct value stands with
    its facts, flagged ``identity_conflict``, and no value is
    promoted over another. An analyst resolves a conflict by
    evidence arriving on a case — never by an edit here, because
    this view is derived and has no edit path.
    """

    field: str
    flag: str = "identity_conflict"
    values: list[str] = Field(
        description="Every distinct value on record for the field."
    )
    facts: list[IdentityFact] = Field(
        description="The facts carrying those values, with sources."
    )


class ProfileAccount(BaseModel):
    """One account in a customer profile view: the core-banking
    facts (from the stored account profile) and the cases that
    touched the account. An account a case names but no stored
    profile covers stands with ``profile_present`` false — the
    gap is named, not papered over."""

    account_id: str
    profile_present: bool
    opened_on: date | None = None
    account_type: str | None = None
    expected_monthly_amount: MoneyAmount | None = None
    expected_monthly_count: int | None = None
    case_ids: list[str] = Field(default_factory=list)


class ProfileCaseEntry(BaseModel):
    """One case in a customer's history, as the profile states it:
    where the case stands, what the analyst gate last decided on
    it (the latest disposition record's outcome and its derived
    standing), and its SAR outcome — filed, or a narrative
    approved under dual control."""

    case_id: str
    alert_id: str
    rule_id: str
    severity: AlertSeverity
    status: CaseStatus
    detected_on: date
    disposition_outcome: str | None = Field(
        default=None,
        description="The latest disposition record's coded outcome, "
        "or None when the gate has not decided this case.",
    )
    disposition_standing: str | None = Field(
        default=None,
        description="The latest disposition's derived standing "
        "(effective | pending_confirmation | confirmed | declined | "
        "superseded), from the disposition service's derivation.",
    )
    filed_sar: bool = False
    narrative_approved: bool = False


class ProfileScreeningHit(BaseModel):
    """One screening hit as the profile's screening history states
    it — including cleared hits, whose ``cleared_reason`` is the
    point: a namesake clearance is a fact about the customer that
    later investigators must be able to see, with its reason."""

    hit_id: str
    subject_name: str
    subject_role: str
    entry_name: str
    status: HitStatus
    strength: str
    basis: str
    cleared_reason: str | None = None
    status_reason: str | None = None


class ProfileScreeningEntry(BaseModel):
    """One (case, list, snapshot version) line of screening
    history: the run that pinned it and every hit it produced."""

    case_id: str
    list_kind: ListKind
    snapshot_version: str
    run_id: str
    screened_at: datetime
    hits: list[ProfileScreeningHit] = Field(default_factory=list)


class FreshnessEntry(BaseModel):
    """One fact class's KYC freshness, against the versioned
    freshness policy: when the class was last corroborated by a
    stored artefact, and whether that is now stale. A class with
    no corroboration at all stands with ``last_corroborated_on``
    None and ``stale`` true — never corroborated is the stalest
    state there is, and it is named like any other."""

    fact_class: str = Field(
        description="identity | account | screening | activity"
    )
    last_corroborated_on: date | None = None
    stale: bool
    limit_days: int
    policy_version: str


class ProfileView(BaseModel):
    """A customer's assembled KYC profile (R11): a DERIVED
    artefact, assembled in code from stored artefacts only.

    Content-addressed: ``content_hash`` covers the derived facts
    (identity facts and conflicts, accounts, case history,
    screening history, freshness as computed at ``as_of``), and
    ``profile_id`` derives from it — rebuilding over unchanged
    inputs returns the stored view; changed inputs append the
    next version, and no version is ever edited. Content is
    monotonic in practice because every input is append-only:
    cases, hits, transactions and dispositions are never deleted,
    so a fact set, once superseded, does not recur.
    """

    profile_id: str = Field(description="Content-derived: prof-<hash>.")
    customer_id: str
    version: int = Field(ge=1)
    content_hash: str
    assembled_at: datetime = Field(default_factory=_utcnow)
    as_of: date = Field(
        description="The date freshness was computed at — an "
        "assembly input, passed in, never a wall-clock read inside "
        "the derivation."
    )
    freshness_policy_version: str
    identity_facts: list[IdentityFact] = Field(default_factory=list)
    identity_conflicts: list[IdentityConflict] = Field(default_factory=list)
    accounts: list[ProfileAccount] = Field(default_factory=list)
    case_history: list[ProfileCaseEntry] = Field(default_factory=list)
    screening_history: list[ProfileScreeningEntry] = Field(default_factory=list)
    freshness: list[FreshnessEntry] = Field(default_factory=list)
    source_case_ids: list[str] = Field(
        default_factory=list,
        description="Every case the view was assembled from — the "
        "input set the content hash covers.",
    )


class CounterpartyScreening(BaseModel):
    """One screening hit naming a counterparty, wherever it sits:
    the hit's case, list, snapshot version, and standing."""

    case_id: str
    hit_id: str
    list_kind: ListKind
    snapshot_version: str
    status: HitStatus
    entry_name: str


class CounterpartyView(BaseModel):
    """One counterparty, aggregated in code from stored
    transactions across cases (Decimal end to end — Law 4).

    ``name`` is the display form for composed artefacts: where
    R10's quarantine fenced the name on any batch it rode in on,
    the display carries the fence marker. ``name_raw`` is the
    stored value, verbatim — storage is never touched by fencing.
    A counterparty standing on more than one customer's cases is
    the shared-counterparty network signal; ``customer_ids``
    names them all.
    """

    name: str = Field(description="Display form (fenced where quarantined).")
    name_raw: str = Field(description="The stored name, verbatim.")
    total_in: MoneyAmount = Field(
        description="Sum of credits from this counterparty (Decimal)."
    )
    total_out: MoneyAmount = Field(
        description="Sum of debits to this counterparty (Decimal)."
    )
    transaction_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    currencies: list[str] = Field(default_factory=list)
    customer_ids: list[str] = Field(default_factory=list)
    case_ids: list[str] = Field(default_factory=list)
    account_ids: list[str] = Field(default_factory=list)
    screening: list[CounterpartyScreening] = Field(default_factory=list)


class SharedCounterparty(BaseModel):
    """A counterparty appearing on more than one customer's cases
    — the network signal, computed exactly: the counterparty, the
    customers it links, and its aggregate footprint."""

    name: str = Field(description="Display form (fenced where quarantined).")
    name_raw: str
    customer_ids: list[str] = Field(min_length=2)
    case_ids: list[str] = Field(default_factory=list)
    transaction_count: int = 0
    total_in: MoneyAmount = Decimal("0")
    total_out: MoneyAmount = Decimal("0")


# ---------------------------------------------------------------------------
# Adverse media (R12): the media port, similarity scoring in code
# ---------------------------------------------------------------------------


class MediaArticle(BaseModel):
    """One article record as an adverse-media source returns it.

    The blueprint's reference feed is a labelled stand-in corpus;
    a production deployment wires a licensed news database behind
    the same port (see ``ports.AdverseMediaSource``) — the record
    shape is the feed's extraction, structured fields and all,
    because the scorer (``media.py``) reads structure, not prose:
    who the article names, the date of birth or age it attributes
    to them, where it places them, what it says they do, and the
    entities it associates with them. The body text is carried
    verbatim — it is untrusted text (Law 7) and is quarantined
    and fenced like every other untrusted text on the case.
    """

    article_id: str = Field(description="The feed's article identifier.")
    headline: str
    outlet: str = Field(description="The publishing outlet, as the feed names it.")
    published_on: date
    body_text: str = ""
    subjects_named: list[str] = Field(
        default_factory=list,
        description="The people/entities the feed's extraction says "
        "the article is about — the surfaces name matching runs over.",
    )
    jurisdiction: str = ""
    locations: list[str] = Field(
        default_factory=list,
        description="Places the article associates with the subject.",
    )
    occupations: list[str] = Field(
        default_factory=list,
        description="Occupations/industries the article attributes "
        "to the subject.",
    )
    subject_dob: date | None = Field(
        default=None,
        description="A date of birth the article states for the "
        "named subject, when it states one.",
    )
    subject_age: int | None = Field(
        default=None,
        description="An age the article states for the named "
        "subject (at publication), when it states one.",
    )
    identifiers: list[str] = Field(
        default_factory=list,
        description="Document/registration identifiers the article "
        "states for the subject (entity reporting carries these).",
    )
    associated_entities: list[str] = Field(
        default_factory=list,
        description="Other entities the article associates with "
        "the subject.",
    )
    source_note: str = Field(
        default="",
        description="Feed-side provenance note for the record.",
    )


class MediaBand(str, enum.Enum):
    """An assessment's relevance band — is this article about the
    case's subject, and how sure is the code of it?

    ``namesake_cleared`` is R2's discipline carried into media: a
    name match contradicted by the subject's date of birth (or
    stated age) is a different person, recorded as cleared with
    the contradiction named — never silently dropped, never
    allowed to stand as a hit.
    """

    STRONG = "strong"
    POSSIBLE = "possible"
    NAMESAKE_CLEARED = "namesake_cleared"
    IRRELEVANT = "irrelevant"


class MediaNameMatch(BaseModel):
    """The name-match leg of an assessment: the deterministic
    matcher's verdict over the subject's name surfaces against
    the article's named subjects (the screening matcher's rules,
    reused — see ``screening.match_name``)."""

    matched: bool
    strength: str = Field(
        description="exact | token_set | fuzzy | none — the "
        "match rule family that fired."
    )
    score: float = Field(description="The matcher's score, 0..1.")
    rule: str = Field(
        default="",
        description="The match rule that fired (exact_name, "
        "name_token_set, name_token_subset, name_token_overlap), "
        "or empty when nothing matched.",
    )
    subject_surface: str = Field(
        default="",
        description="The subject name/alias surface that matched.",
    )
    article_surface: str = Field(
        default="",
        description="The article's named-subject surface that matched.",
    )


class MediaSignal(BaseModel):
    """One disambiguation signal's contribution to an assessment.

    Every signal the scorer examines is recorded — supports,
    contradicts, or absent — with its numeric contribution and
    the facts it was read from, so the band is auditable signal
    by signal rather than a score an analyst must take on trust.
    """

    signal: str = Field(
        description="identifier | dob | age | geography | "
        "occupation | associated_entities"
    )
    outcome: str = Field(description="supports | contradicts | absent")
    contribution: float = Field(
        description="The signal's signed contribution to the "
        "similarity score (0 when absent)."
    )
    detail: str = Field(description="What was compared, in words.")


class MediaCategoryMatch(BaseModel):
    """One adverse category the taxonomy found in the article,
    with the exact terms that matched — classification is a
    keyword taxonomy in code (versioned data), never a model
    judgement, and the matched terms are the proof."""

    category: str = Field(
        description="fraud | corruption | sanctions_evasion | "
        "organised_crime | regulatory_action | other"
    )
    matched_terms: list[str] = Field(min_length=1)


class MediaAssessment(BaseModel):
    """One article assessed against one case's subject (R12).

    The assessment is a finding artefact, nothing more: it is
    stored append-only, captured on the case's hash chain (kind
    ``media_assessment``), and cited by the investigation record
    like any other finding input. It dispositions nothing, blocks
    nothing, and changes no case state — a named analyst decides
    what a strong match means for the case, exactly as with a
    screening hit.

    Everything the score rests on is pinned: the scorer and
    taxonomy versions, the profile view the subject facts were
    read from (``profile_id``/``profile_version`` — None when the
    facts came from the case's alert payload because no view had
    been assembled, with ``facts_basis`` saying which), and the
    article's evidence position, so an assessment can always be
    re-derived and checked against the exact inputs it used.
    """

    assessment_id: str = Field(default_factory=lambda: _new_id("med"))
    case_id: str
    customer_id: str
    article_id: str
    article_evidence_seq: int | None = Field(
        default=None,
        description="Seq of the adverse_media evidence item "
        "holding the article on this case's chain.",
    )
    subject_name: str = Field(
        description="The subject surface the article was "
        "assessed against (the customer's primary recorded name)."
    )
    name_match: MediaNameMatch
    signals: list[MediaSignal] = Field(default_factory=list)
    categories: list[MediaCategoryMatch] = Field(default_factory=list)
    score: float = Field(
        description="Similarity score, 0..1: the name match "
        "weighted with the signals' signed contributions, "
        "computed in code."
    )
    band: MediaBand
    band_basis: str = Field(
        description="Why the band is what it is, in words — "
        "including the contradiction, when one cleared a namesake."
    )
    published_on: date
    article_age_days: int = Field(
        description="as_of - published_on, in days — the "
        "article's age at assessment, computed and shown."
    )
    as_of: date = Field(
        description="The date the assessment was computed at — "
        "passed in, never a wall-clock read inside the scoring."
    )
    scorer_version: str
    taxonomy_version: str
    profile_id: str | None = Field(
        default=None,
        description="The profile view the subject facts were "
        "read from, when one was used.",
    )
    profile_version: int | None = None
    facts_basis: str = Field(
        description="profile_view | alert_payload — where the "
        "subject facts came from."
    )
    assessed_by: str
    assessed_at: datetime = Field(default_factory=_utcnow)
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the media_assessment evidence item "
        "holding this record.",
    )


# ---------------------------------------------------------------------------
# Model gateway: profiles, prices, and the cost ledger (R13)
# ---------------------------------------------------------------------------


class ProviderKind(str, enum.Enum):
    """How a model profile's endpoint speaks.

    ``offline`` is the deterministic template composer — no model
    call at all. ``anthropic`` is the hosted-frontier shape
    (Messages API). ``openai_compatible`` is the shape an
    in-boundary open-weight server (vLLM, NIM, a private gateway)
    exposes. The kind decides the adapter; the profile decides
    everything else, as data.
    """

    OFFLINE = "offline"
    ANTHROPIC = "anthropic"
    OPENAI_COMPATIBLE = "openai-compatible"


class ModelProfileDefinition(BaseModel):
    """One model profile, as governed configuration data.

    Profiles are data, not code branches: a deployment adds a
    profile by adding a definition (and a price entry), never by
    patching the gateway. Endpoint and key are named as
    *environment variables*, never as values — the definition is
    safe to commit; the secret never is. ``endpoint_default`` is
    the public default base URL for a hosted provider (a URL is
    not a secret); an in-boundary endpoint has no default, so a
    deployment that has not set one is unconfigured by
    construction.
    """

    profile_id: str = Field(min_length=1)
    provider_kind: ProviderKind
    model: str = Field(min_length=1)
    endpoint_env: str | None = Field(
        default=None,
        description="Environment variable naming the endpoint "
        "base URL. Required for live profiles.",
    )
    endpoint_default: str | None = Field(
        default=None,
        description="Fallback base URL when the env var is unset "
        "(hosted providers' public endpoints only).",
    )
    api_key_env: str | None = Field(
        default=None,
        description="Environment variable naming the API key. "
        "The value is read at wiring time and never stored on "
        "the definition, a ledger entry, or a log line.",
    )
    key_required: bool = Field(
        default=True,
        description="True when the endpoint refuses keyless "
        "calls (hosted providers). An in-boundary server inside "
        "the bank's own network may set this False — the "
        "endpoint itself stays required.",
    )
    timeout_seconds: float = Field(default=60.0, gt=0)


class ModelPrice(BaseModel):
    """One model's prices in the governed price table.

    Prices are reference data with a basis, maintained by the
    deployment — the table is versioned as a whole, and every
    ledger entry pins the table version it was priced under, so
    a later price change never rewrites what a past call cost.
    """

    model: str = Field(min_length=1)
    input_per_mtok_usd: MoneyAmount = Field(
        description="USD per 1M input tokens, as an exact Decimal."
    )
    output_per_mtok_usd: MoneyAmount = Field(
        description="USD per 1M output tokens, as an exact Decimal."
    )
    basis: str = Field(
        default="",
        description="Where the price comes from (provider list "
        "price, internal serving-cost allocation, zero for the "
        "offline composer) — stated, never implied.",
    )


class PriceTable(BaseModel):
    """The versioned price table: every model a profile may name,
    priced. A profile whose model has no entry here cannot be
    loaded — an unpriceable call is a configuration error, refused
    at load time, not discovered on an invoice."""

    version: str = Field(min_length=1)
    as_of: date
    entries: list[ModelPrice] = Field(min_length=1)


class ModelCallEntry(BaseModel):
    """One model call, priced, in the cost ledger (R13).

    EVERY call through the gateway appends one of these —
    including offline calls at zero — so the ledger is the complete
    record of what the drafting cost, case by case. The entry
    carries the unit prices it was priced with (not just the table
    version), so the cost is re-checkable from the entry alone:
    ``cost = (tokens_in * input_price + tokens_out *
    output_price) / 1_000_000``, exact Decimal arithmetic.

    ``token_basis`` states where the token counts came from:
    ``reported`` (the provider's usage block) or the adapter's
    stated estimate basis when a provider reported none.
    ``called_at`` comes from the gateway's injected clock, so
    tests and evals price a call at a known instant.
    """

    entry_id: str = Field(default_factory=lambda: _new_id("led"))
    case_id: str | None = Field(
        default=None,
        description="The case the call drafted for; None is the "
        "system scope (a call not made for any one case).",
    )
    purpose: str = Field(
        description="record_draft | sar_draft | review_draft | "
        "… — what the composed text was for.",
    )
    profile_id: str
    model: str
    tokens_in: int = Field(ge=0)
    tokens_out: int = Field(ge=0)
    token_basis: str = Field(
        description="reported | estimated:chars/4 — the stated "
        "basis of the token counts.",
    )
    price_table_version: str
    input_per_mtok_usd: MoneyAmount
    output_per_mtok_usd: MoneyAmount
    cost_usd: MoneyAmount = Field(
        description="The call's priced cost, exact Decimal USD."
    )
    latency_ms: int = Field(ge=0)
    called_at: datetime = Field(default_factory=_utcnow)


class ModelBudgetEvent(BaseModel):
    """A budget refusal, recorded (R13).

    When a case's priced spend reaches the deployment's per-case
    cap, further live-profile calls for that case are refused
    before any transport is touched. The refusal is a record, not
    a log line: this artefact in the ledger store, an audit event
    on the case, and — where the evidence service is wired — an
    item on the case's hash chain (kind ``model_budget_refusal``).
    """

    event_id: str = Field(default_factory=lambda: _new_id("bud"))
    case_id: str
    profile_id: str
    model: str
    purpose: str
    cap_usd: MoneyAmount = Field(
        description="The per-case cap in force, exact Decimal USD."
    )
    spent_usd: MoneyAmount = Field(
        description="The case's priced spend at refusal time."
    )
    recorded_at: datetime = Field(default_factory=_utcnow)
    evidence_seq: int | None = Field(
        default=None,
        description="Seq of the model_budget_refusal evidence "
        "item holding this event on the case's chain, when the "
        "evidence service was wired to record it there.",
    )


# ---------------------------------------------------------------------------
# Management reporting (R17): derived read-models — Law 8's payoff
# ---------------------------------------------------------------------------
#
# Every model below is a DERIVED view, computed in code from stored
# artefacts at a named ``as_of`` — the same discipline as the clocks
# (R8) and the profile views (R11), except that a report is never
# stored: rebuilding it over the same artefacts at the same
# ``as_of`` returns the same content, and its ``pack_id`` is a hash
# of that content, so a pack can be pinned and re-checked without
# a table. Each section names the sources its figures were read
# from; a figure with no stated source does not appear.


class AgeingRow(BaseModel):
    """Open-case ageing for one grouping key (a case status, a
    monitoring rule, a severity): how many cases stand open, their
    ages spread over the pack's buckets, and the oldest age."""

    key: str
    open_cases: int = 0
    buckets: dict[str, int] = Field(
        default_factory=dict,
        description="Age bucket -> open case count. Every bucket "
        "of the pack's set is present, zero-filled.",
    )
    oldest_age_days: int | None = None
    median_age_days: float | None = None


class OldestCase(BaseModel):
    """One row of the oldest-open-cases list."""

    case_id: str
    customer_id: str
    status: CaseStatus
    rule_id: str = Field(description="The monitoring rule (alert type).")
    severity: AlertSeverity
    detected_on: date
    age_days: int
    assigned_analyst: str | None = None


class WaitingEntry(BaseModel):
    """A case standing in a human's queue: a pending_confirmation
    case waits on a second person (an L2 reviewer who is not the
    dispositioning analyst); a sar_pending case waits on drafting,
    verification, or the dual-control approval. Person-level
    detail is limited to the actor ids the artefacts themselves
    record — the report aggregates nothing about a person that
    the record does not already carry."""

    case_id: str
    customer_id: str
    stage: str = Field(
        description="awaiting_confirmation | awaiting_draft | "
        "awaiting_verification | awaiting_approval"
    )
    waiting_on_role: str = Field(
        description="The coded role the wait stands with: "
        "l2_reviewer for a confirmation; for SAR stages, the "
        "drafting service or a second-person approver."
    )
    disposition_id: str | None = None
    disposition_analyst_id: str | None = Field(
        default=None,
        description="The analyst whose recorded disposition "
        "put the case in this queue.",
    )
    narrative_version: int | None = None
    drafted_by: str | None = None
    since: date = Field(
        description="The date the wait began (the disposition's "
        "decision date)."
    )
    days_waiting: int


class QueueAgeingReport(BaseModel):
    """The queue-ageing section: open cases by status x age
    bucket, ageing by alert type and severity, the oldest cases,
    and the two human-wait queues aged separately."""

    as_of: date
    open_cases: int = 0
    age_buckets: list[str] = Field(
        description="The bucket labels, in order — the axis every "
        "row's ``buckets`` dict is keyed by."
    )
    by_status: list[AgeingRow] = Field(default_factory=list)
    by_rule: list[AgeingRow] = Field(default_factory=list)
    by_severity: list[AgeingRow] = Field(default_factory=list)
    oldest: list[OldestCase] = Field(default_factory=list)
    waiting_confirmation: list[WaitingEntry] = Field(default_factory=list)
    waiting_sar: list[WaitingEntry] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class OverdueClockEntry(BaseModel):
    """One clock standing overdue on the board."""

    case_id: str
    customer_id: str
    clock_kind: str = Field(description="filing | continuing_activity")
    deadline_kind: str
    deadline: date
    days_overdue: int = Field(ge=0)


class DeadlinePerformanceEntry(BaseModel):
    """One clock that reached a terminal state, and whether it
    got there on time. A documented decision recorded after its
    deadline is a LATE ending — the documentation stands, and so
    does the lateness (the R15 rule, carried into reporting)."""

    clock_kind: str = Field(description="filing | continuing_activity")
    case_id: str
    cycle: int | None = Field(
        default=None,
        description="Continuing-activity cycle number; None for "
        "a filing clock.",
    )
    outcome: str = Field(description="satisfied | closed_no_file")
    deadline: date
    ended_on: date
    on_time: bool
    days_late: int = Field(ge=0)


class DeadlinePerformance(BaseModel):
    """Deadline performance over a window: of the clocks that
    ended inside it, how many ended on time and how many late."""

    window_start: date | None = None
    window_end: date | None = None
    clocks_ended: int = 0
    on_time: int = 0
    late: int = 0
    entries: list[DeadlinePerformanceEntry] = Field(default_factory=list)


class ClockBoardReport(BaseModel):
    """The clock-board section: every case's clocks by state at
    ``as_of`` (the continuing counts read each case's current
    cycle), the overdue list, and deadline performance."""

    as_of: date
    filing_by_state: dict[str, int] = Field(
        default_factory=dict,
        description="ClockState value -> case count, zero-filled "
        "for every state in the vocabulary.",
    )
    continuing_by_state: dict[str, int] = Field(default_factory=dict)
    cases_with_continuing_clock: int = 0
    overdue: list[OverdueClockEntry] = Field(default_factory=list)
    performance: DeadlinePerformance = Field(
        default_factory=DeadlinePerformance
    )
    sources: list[str] = Field(default_factory=list)


class RecordRevisionRow(BaseModel):
    """One case's investigation-record revision history, from the
    first composed draft to the version the standing disposition
    was decided on (summed over the stored per-version diffs)."""

    case_id: str
    first_version: int
    decided_version: int | None = Field(
        default=None,
        description="The record version the case's latest "
        "disposition cites; None when no disposition stands.",
    )
    latest_version: int
    findings_added: int = 0
    findings_removed: int = 0
    findings_changed: int = 0
    hypothesis_changed: bool = False


class NarrativeRevisionRow(BaseModel):
    """One case's SAR narrative drafting history: how many drafts
    it took, which version was approved, and how far the approved
    text stands from the first draft."""

    case_id: str
    drafts: int = 0
    approved_version: int | None = None
    approved_without_edit: bool | None = Field(
        default=None,
        description="True when the approved text is identical "
        "to the first draft's text; None when nothing stands "
        "approved.",
    )
    edit_distance: float | None = Field(
        default=None,
        description="1 - difflib SequenceMatcher ratio between "
        "the first draft's rendered text and the approved "
        "version's, 0..1. None when nothing stands approved.",
    )
    edit_band: str | None = Field(
        default=None,
        description="none | light | moderate | heavy — the "
        "pack's distance bands, as data.",
    )
    rejections: int = 0


class DecisionTimeRow(BaseModel):
    """A decision-latency distribution for one actor at one gate:
    counts plus median and p90 (nearest-rank), in hours. A
    measurement of recorded timestamps, presented without any
    performance label."""

    actor_id: str
    gate: str = Field(
        description="disposition | confirmation | sar_approval"
    )
    decisions: int = 0
    median_hours: float | None = None
    p90_hours: float | None = None


class ConfirmationRateRow(BaseModel):
    """One dispositioning analyst's confirmation outcomes: how
    many of their adverse closures required a second person, and
    what that second person answered."""

    analyst_id: str
    dispositions: int = 0
    requiring_confirmation: int = 0
    confirmed: int = 0
    declined: int = 0
    awaiting: int = 0
    confirmation_rate: float | None = Field(
        default=None,
        description="confirmed / (confirmed + declined); None "
        "when no confirmation has been decided either way.",
    )


class RubberStampReport(BaseModel):
    """The rubber-stamp section (Law 8): draft-vs-final
    measurement across the three artefact families, plus the
    confirmation patterns and decision-latency distributions.
    Measurements only — the section states what it measures and
    what it cannot; it scores nobody."""

    as_of: date
    # Investigation records: first draft -> decided version.
    record_cases: int = 0
    record_cases_decided: int = 0
    decided_on_first_draft: int = 0
    decided_on_revised_record: int = 0
    record_transitions: int = 0
    findings_added: int = 0
    findings_removed: int = 0
    findings_changed: int = 0
    hypothesis_changes: int = 0
    record_rows: list[RecordRevisionRow] = Field(default_factory=list)
    # SAR narratives: first draft -> approved version.
    narrative_cases: int = 0
    narrative_drafts: int = 0
    narratives_approved: int = 0
    approved_without_edit: int = 0
    approved_after_redraft: int = 0
    narrative_rejections: int = 0
    edit_bands: dict[str, int] = Field(
        default_factory=dict,
        description="Edit band -> approved narratives, zero-filled.",
    )
    narrative_rows: list[NarrativeRevisionRow] = Field(default_factory=list)
    # Disposition confirmations (dual control at the gate).
    confirmations_required: int = 0
    confirmations_confirmed: int = 0
    confirmations_declined: int = 0
    confirmations_awaiting: int = 0
    confirmed_with_note: int = 0
    confirmed_without_note: int = 0
    confirmation_rates: list[ConfirmationRateRow] = Field(
        default_factory=list
    )
    # Decision latencies at the three gates.
    decision_times: list[DecisionTimeRow] = Field(default_factory=list)
    measures: list[str] = Field(
        default_factory=list,
        description="What each metric measures, in words.",
    )
    cannot_measure: list[str] = Field(
        default_factory=list,
        description="What these records cannot show, in words.",
    )
    sources: list[str] = Field(default_factory=list)


class TypologyOpsRow(BaseModel):
    """Finding volume for one typology check under one rule-pack
    version: runs of the pack, findings, and the cases they fell
    on. A rate is findings per run of the pack, exact Decimal."""

    typology_id: str
    rule_pack_id: str
    rule_pack_version: str
    pack_runs: int = 0
    findings: int = 0
    cases_with_findings: int = 0
    findings_per_run: str = Field(
        description="Exact Decimal string, 4dp."
    )


class ScreeningOpsRow(BaseModel):
    """Screening outcomes against one list version: hits by
    standing, with the namesake clearances (a name match a
    contradicting date of birth cleared) counted separately —
    they are the false-positive shape this system exists to
    record honestly."""

    list_kind: str
    snapshot_version: str
    cases_screened: int = 0
    hits: int = 0
    open: int = 0
    cleared: int = 0
    namesake_cleared: int = 0
    confirmed: int = 0


class QuarantineOps(BaseModel):
    """Quarantine volume (Law 7): records and pattern matches by
    family and source kind, and how many records a named analyst
    has reviewed (an audit act — reviewed content stays fenced)."""

    available: bool = Field(
        description="False when no quarantine service is wired "
        "into the reporting stack; the section then carries no "
        "figures rather than invented ones.",
    )
    records: int = 0
    matches: int = 0
    by_family: dict[str, int] = Field(default_factory=dict)
    by_source_kind: dict[str, int] = Field(default_factory=dict)
    flagged: int = 0
    reviewed: int = 0


class SpendRow(BaseModel):
    """Model spend for one ledger key (a profile or a purpose)."""

    key: str
    calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: str = Field(
        default="0", description="Exact Decimal string."
    )


class OpsReport(BaseModel):
    """The operations section: typology and screening volume,
    quarantine counts, the media band distribution, and model
    spend from the priced ledger (R13)."""

    as_of: date
    typology: list[TypologyOpsRow] = Field(default_factory=list)
    screening: list[ScreeningOpsRow] = Field(default_factory=list)
    quarantine: QuarantineOps = Field(
        default_factory=lambda: QuarantineOps(available=False)
    )
    media_by_band: dict[str, int] = Field(
        default_factory=dict,
        description="MediaBand value -> assessments, zero-filled.",
    )
    media_assessments: int = 0
    model_calls: int = 0
    model_tokens_in: int = 0
    model_tokens_out: int = 0
    model_cost_usd: str = "0"
    model_by_profile: list[SpendRow] = Field(default_factory=list)
    model_by_purpose: list[SpendRow] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)


class ReportPack(BaseModel):
    """The full management report at an ``as_of``: the four
    sections, the window the deadline-performance figures cover,
    and the counts of the artefacts the pack was derived from —
    every figure in it reproducible from those artefacts by the
    derivations the sections name. ``pack_id`` is a content hash
    (the derived-artefact discipline of R11, unstored like the
    clocks): the same artefacts at the same ``as_of`` rebuild the
    same pack, byte for byte."""

    pack_id: str = Field(default_factory=lambda: _new_id("rep"))
    report_version: str
    as_of: date
    window_start: date | None = None
    window_end: date | None = None
    inputs: dict[str, int] = Field(
        default_factory=dict,
        description="Artefact family -> records read, e.g. "
        "cases, dispositions, narratives. The pack's stated "
        "sources, counted.",
    )
    queue_ageing: QueueAgeingReport
    clock_board: ClockBoardReport
    rubber_stamp: RubberStampReport
    ops: OpsReport
    content_hash: str = ""
