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

from pydantic import BaseModel, Field


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
