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
