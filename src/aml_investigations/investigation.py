"""The investigation graph: cited findings, hypothesis discipline.

R4 assembles what R1–R3 put on the case — the alert payload, the
screening runs and hits, the typology findings, the account
profile, the customer's prior cases — and works it into an
:class:`InvestigationRecord` through a LangGraph graph:

    assemble -> draft -> counter_search -> compose -> verify -> persist

The record separates three things that agent demos habitually blur:

- **Facts** — findings, each carrying citations that must resolve
  to a specific element of a specific evidence item, and statements
  whose figures must trace to the cited records. A finding whose
  citations do not resolve is refused at record time, mechanically
  (the verify node), and the composer refuses a statement carrying
  an ungrounded figure before that.
- **The working hypothesis** — labelled as a hypothesis, naming the
  findings that support it and the findings that cut against it.
- **Open questions** — each naming the evidence type that would
  resolve it.

The counter-evidence search is a graph step, not a label: for the
working hypothesis it runs named checks over the stored transaction
record and the profile (regular cadence, documented expectation,
recurring history, established counterparty, namesake clearance),
and records every check's outcome — including the searches that
found nothing, with their coverage stated.

Narrative text comes through the model port (``composer.py``): the
deterministic offline profile by default; a live profile is a
different composer behind the same port. The model never computes
money (Law 4) and never decides anything (Law 1): this graph stops
at a recorded investigation — disposition is R5's analyst gate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, timedelta
from decimal import Decimal
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from .composer import (
    NarrativeComposer,
    StatementDraft,
    get_composer,
    numeric_tokens,
    tokens_of,
    ungrounded_figures,
    DEFAULT_PROFILE,
)
from .dispositions import flag_dispositions_stale
from .errors import (
    CaseNotFoundError,
    CitationResolutionError,
    InvestigationRefusedError,
    InvestigationStateError,
)
from .evidence import EvidenceService
from .logging_config import get_logger
from .models import (
    AccountProfile,
    Alert,
    AuditEvent,
    Case,
    CaseStatus,
    Citation,
    CounterCheck,
    CounterSearch,
    HitStatus,
    Hypothesis,
    InvestigationFinding,
    InvestigationRecord,
    ListKind,
    OpenQuestion,
    PriorCaseRef,
    RecordDiff,
    ScreeningHit,
    ScreeningRun,
    Transaction,
    TypologyFinding,
    TypologyRun,
)
from .ports import (
    CaseStore,
    DispositionStore,
    InvestigationStore,
    ScreeningStore,
    TypologyStore,
)
from .typologies import input_fingerprint as _txn_fingerprint

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Citation resolution
# ---------------------------------------------------------------------------

#: Element schemes that address an object inside an evidence item by
#: one of its id fields: ``finding:<id>`` finds the object whose
#: ``finding_id`` is <id>, wherever it sits in the item's JSON.
_ID_ELEMENTS = {
    "transaction": "transaction_id",
    "finding": "finding_id",
    "hit": "hit_id",
    "run": "run_id",
    "batch": "batch_id",
}


def _find_by_id(node: object, key: str, value: str) -> dict | None:
    if isinstance(node, dict):
        if node.get(key) == value:
            return node
        for child in node.values():
            found = _find_by_id(child, key, value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for child in node:
            found = _find_by_id(child, key, value)
            if found is not None:
                return found
    return None


def _walk_path(payload: object, path: str, citation: Citation) -> object:
    node = payload
    for segment in path.split("."):
        if isinstance(node, dict) and segment in node:
            node = node[segment]
        elif isinstance(node, list) and segment.isdigit() and int(segment) < len(node):
            node = node[int(segment)]
        else:
            raise CitationResolutionError(
                f"citation element {citation.element!r}: path segment "
                f"{segment!r} is not present in evidence item "
                f"seq {citation.evidence_seq}"
            )
    return node


class CitationResolver:
    """Resolves citations against the evidence store, mechanically.

    A citation resolves iff the evidence item exists on the named
    case AND the named element is inside its content. Anything else
    raises :class:`CitationResolutionError` — the refusal the record
    gate is built on.
    """

    def __init__(self, store: CaseStore, evidence: EvidenceService) -> None:
        self._store = store
        self._evidence = evidence

    def resolve(self, citation: Citation, default_case_id: str) -> object:
        case_id = citation.case_id or default_case_id
        item = self._store.get_evidence_item(case_id, citation.evidence_seq)
        if item is None:
            raise CitationResolutionError(
                f"citation names evidence seq {citation.evidence_seq} on "
                f"case {case_id}, which does not exist"
            )
        try:
            content = self._evidence.read_item_content(case_id, citation.evidence_seq)
        except Exception as exc:
            raise CitationResolutionError(
                f"citation names evidence seq {citation.evidence_seq} on "
                f"case {case_id}, whose content cannot be read: {exc}"
            ) from exc
        try:
            payload = json.loads(content.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise CitationResolutionError(
                f"citation element {citation.element!r}: evidence seq "
                f"{citation.evidence_seq} on case {case_id} is not JSON"
            ) from exc
        scheme, _, target = citation.element.partition(":")
        if scheme == "field" and target:
            return _walk_path(payload, target, citation)
        if scheme in _ID_ELEMENTS and target:
            found = _find_by_id(payload, _ID_ELEMENTS[scheme], target)
            if found is None:
                raise CitationResolutionError(
                    f"citation element {citation.element!r}: no "
                    f"{_ID_ELEMENTS[scheme]} {target!r} inside evidence "
                    f"seq {citation.evidence_seq} on case {case_id}"
                )
            return found
        raise CitationResolutionError(
            f"citation element {citation.element!r}: unknown element "
            "scheme (expected field:<path> or one of "
            + ", ".join(f"{k}:<id>" for k in sorted(_ID_ELEMENTS))
            + ")"
        )


def _citation_key(citation: Citation) -> tuple:
    return (citation.case_id or "", citation.evidence_seq, citation.element)


# ---------------------------------------------------------------------------
# Working drafts (graph-internal; the record holds the composed findings)
# ---------------------------------------------------------------------------


@dataclass
class _Draft:
    key: str
    kind: str
    origin: str
    weight: str
    direction: str
    template: str
    values: dict[str, str]
    figures: dict[str, str]
    citations: list[Citation]
    allowed: set[Decimal]


def _allowed_for(
    resolver: CitationResolver,
    case_id: str,
    citations: list[Citation],
    figures: dict[str, str],
) -> set[Decimal]:
    """The figure tokens a statement over these citations may use:
    every numeric token of every resolved element, plus the tokens
    of the finding's own code-computed figures."""
    allowed: set[Decimal] = set()
    for citation in citations:
        allowed |= tokens_of(resolver.resolve(citation, case_id))
    for value in figures.values():
        allowed |= numeric_tokens(value)
    return allowed


# ---------------------------------------------------------------------------
# Hypothesis selection
# ---------------------------------------------------------------------------

#: Typology priority for the working hypothesis: the most specific,
#: most consequential pattern leads. Sanctions (a screening result,
#: not a typology) outranks them all.
_TYPOLOGY_PRIORITY = (
    "structuring",
    "rapid_in_out",
    "dormancy_then_burst",
    "velocity",
    "round_amount",
)

_HYPOTHESIS_STATEMENTS = {
    "structuring": (
        "The cash deposits were structured to stay under the "
        "currency-transaction reporting threshold."
    ),
    "velocity": (
        "The account's activity changed pace in a way its own history "
        "and profile do not explain, consistent with the account "
        "being directed by a third party."
    ),
    "dormancy_then_burst": (
        "A long-dormant account was reactivated to move funds, "
        "consistent with a dormant account being taken over or lent "
        "for a single movement."
    ),
    "rapid_in_out": (
        "Funds passed through the account with minimal retention, "
        "consistent with the account being used as a conduit."
    ),
    "round_amount": (
        "The stream's round amounts are consistent with sums chosen "
        "for transfer convenience rather than set by underlying "
        "obligations."
    ),
    "sanctions_match": (
        "A case subject is a listed person or entity, and the "
        "relationship is prohibited or restricted."
    ),
    "no_adverse_pattern": (
        "The assembled evidence shows no typology pattern and no "
        "open screening hit; nothing in it is shown to be "
        "inconsistent with the customer's profile."
    ),
}

_ADVERSE_LABELS = frozenset(_HYPOTHESIS_STATEMENTS) - {"no_adverse_pattern"}

_TYPOLOGY_WEIGHTS = {
    "structuring": "high",
    "velocity": "medium",
    "dormancy_then_burst": "high",
    "round_amount": "medium",
    "rapid_in_out": "high",
}


def _choose_hypothesis(
    hits: list[ScreeningHit], findings: list[TypologyFinding]
) -> str:
    open_hits = [h for h in hits if h.status is not HitStatus.CLEARED]
    if any(h.list_kind is ListKind.SANCTIONS for h in open_hits):
        return "sanctions_match"
    present = {f.typology_id for f in findings}
    for label in _TYPOLOGY_PRIORITY:
        if label in present:
            return label
    return "no_adverse_pattern"


# ---------------------------------------------------------------------------
# Counter-evidence checks (pure computations over stored records)
# ---------------------------------------------------------------------------


def _cadence(txns: list[Transaction]) -> dict | None:
    """Regular-cadence statistics for a transaction subset, or None
    when there are too few points to speak of cadence at all.

    Regular means: at least four points spanning at least sixty
    days, with every gap at least two days and no gap more than
    twice the smallest — the shape of a recurring receipt pattern,
    not of a one-off cluster."""
    if len(txns) < 4:
        return None
    ordered = sorted(txns, key=lambda t: (t.posted_at, t.transaction_id))
    span = (ordered[-1].posted_at.date() - ordered[0].posted_at.date()).days
    gaps = [
        (b.posted_at.date() - a.posted_at.date()).days
        for a, b in zip(ordered, ordered[1:])
    ]
    regular = (
        span >= 60 and min(gaps) >= 2 and max(gaps) <= 2 * min(gaps)
    )
    return {
        "count": len(ordered),
        "span_days": span,
        "min_gap_days": min(gaps),
        "max_gap_days": max(gaps),
        "regular": regular,
        "transactions": ordered,
    }


def _monthly_stability(txns: list[Transaction]) -> dict | None:
    """Monthly-total stability for a subset: at least three months,
    every month's total within a quarter of the median month. That
    is the shape of a documented recurring obligation."""
    if not txns:
        return None
    totals: dict[tuple[int, int], Decimal] = {}
    for txn in txns:
        key = (txn.posted_at.year, txn.posted_at.month)
        totals[key] = totals.get(key, Decimal("0")) + txn.amount
    if len(totals) < 3:
        return {"months": len(totals), "stable": False, "median": None}
    ordered = sorted(totals.values())
    median = ordered[len(ordered) // 2]
    stable = all(abs(t - median) <= median * Decimal("0.25") for t in totals.values())
    return {"months": len(totals), "stable": stable, "median": median}


def _in_band_cash(
    txns: list[Transaction], finding: TypologyFinding
) -> list[Transaction]:
    """The stored cash transactions inside a structuring finding's
    band, in the finding's direction — the population the counter
    checks reason about."""
    low = Decimal(finding.figures["band_low"])
    high = Decimal(finding.figures["ctr_threshold"])
    direction = finding.figures["direction"]
    return [
        t
        for t in txns
        if t.cash and t.direction == direction and low <= t.amount < high
    ]


# ---------------------------------------------------------------------------
# The graph state
# ---------------------------------------------------------------------------


class _State(TypedDict, total=False):
    case_id: str
    actor: str
    composer: NarrativeComposer
    case: Case
    alert: Alert
    alert_seq: int
    profile: AccountProfile | None
    profile_seq: int | None
    screening_run: ScreeningRun | None
    screening_hits: list[ScreeningHit]
    typology_run: TypologyRun | None
    typology_findings: list[TypologyFinding]
    transactions: list[Transaction]
    txn_seq: dict[str, int]
    prior_cases: list[Case]
    prior_refs: list[PriorCaseRef]
    prior_alert_seqs: dict[str, int]
    label: str
    drafts: list[_Draft]
    counter: CounterSearch
    findings: list[InvestigationFinding]
    hypothesis: Hypothesis
    open_questions: list[OpenQuestion]
    record: InvestigationRecord


def _typology_template(finding: TypologyFinding) -> tuple[str, dict[str, str]]:
    f = finding.figures
    if finding.typology_id == "structuring":
        direction_word = "credits" if f["direction"] == "credit" else "debits"
        if finding.variant == "same_day":
            return (
                "The typology engine found {transaction_count} cash "
                "{direction_word} totalling {total_amount} on "
                "{window_start}, each inside the band {band_low} to "
                "{ctr_threshold}.",
                {"direction_word": direction_word},
            )
        return (
            "The typology engine found {transaction_count} cash "
            "{direction_word} totalling {total_amount} between "
            "{window_start} and {window_end}, each inside the band "
            "{band_low} to {ctr_threshold}.",
            {"direction_word": direction_word},
        )
    if finding.typology_id == "velocity":
        return (
            "Activity in the observation window reached "
            "{observation_count} transactions totalling "
            "{observation_amount}, against a baseline of "
            "{baseline_count} transactions totalling {baseline_amount} "
            "over {baseline_days} days — a count multiple of "
            "{count_multiple} and an amount multiple of "
            "{amount_multiple}.",
            {},
        )
    if finding.typology_id == "dormancy_then_burst":
        return (
            "After {gap_days} days without activity, from {gap_start} "
            "to {gap_end}, {burst_count} transactions totalling "
            "{burst_amount} followed when activity resumed.",
            {},
        )
    if finding.typology_id == "round_amount":
        return (
            "{round_count} of {total_count} transactions are whole "
            "multiples of {round_unit}, totalling {round_total} — a "
            "round share of {round_share} of the stream by count.",
            {},
        )
    if finding.typology_id == "rapid_in_out":
        return (
            "A credit of {credit_amount} was disbursed "
            "{disbursed_amount} within {window_hours} hours, leaving "
            "{retained_amount} retained — a pass-through fraction of "
            "{pass_through}.",
            {},
        )
    return (f"Typology finding under rule {finding.typology_id}.", {})


def _typology_values(finding: TypologyFinding) -> dict[str, str]:
    """Template values for a typology finding: its figures verbatim
    (amounts exact decimal strings), plus the window dates, which
    the engine records as finding fields rather than figures. The
    record's own figures stay an exact copy of the engine's."""
    values = dict(finding.figures)
    if finding.window_start is not None:
        values["window_start"] = finding.window_start.isoformat()
    if finding.window_end is not None:
        values["window_end"] = finding.window_end.isoformat()
    return values


# ---------------------------------------------------------------------------
# Input fingerprint + record diff (module helpers)
# ---------------------------------------------------------------------------

_SOF_KINDS = {"source_of_funds_documentation", "customer_documentation"}


def _input_fingerprint(
    store: CaseStore,
    screening_store: ScreeningStore,
    typology_store: TypologyStore,
    case: Case,
) -> str:
    """A fingerprint of everything an investigation reads. Same
    inputs ⇒ same record: re-running an investigation over unchanged
    inputs returns the existing record instead of stacking a
    duplicate version. New evidence, a new screening or typology
    run, a hit changing state, or a prior case moving all change
    the fingerprint and produce the next version."""
    items = store.list_evidence(case.case_id)
    alert_hash = next(
        (i.content_sha256 for i in items if i.kind == "alert_payload"), ""
    )
    kinds = {i.kind for i in items}
    runs = screening_store.list_screening_runs(case.case_id)
    hits = screening_store.list_hits(case.case_id)
    truns = typology_store.list_typology_runs(case.case_id)
    tfindings = typology_store.list_findings(case.case_id)
    txns = typology_store.list_transactions(case.case_id)
    batches = typology_store.list_transaction_batches(case.case_id)
    profile = typology_store.get_account_profile(case.account_id)
    priors = sorted(
        (
            c.case_id,
            c.status.value,
            c.disposition.decision if c.disposition else "",
        )
        for c in store.list_cases()
        if c.customer_id == case.customer_id and c.case_id != case.case_id
    )
    payload = {
        "alert": alert_hash,
        "has_source_of_funds": bool(kinds & _SOF_KINDS),
        "screening_runs": sorted(r.run_id for r in runs),
        "screening_hits": sorted((h.hit_id, h.status.value) for h in hits),
        "typology_runs": sorted(r.run_id for r in truns),
        "typology_findings": sorted(f.finding_id for f in tfindings),
        "transactions": (
            _txn_fingerprint(txns, batches, profile)
            if (txns or batches)
            else "none"
        ),
        "priors": priors,
    }
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _finding_signature(f: InvestigationFinding) -> tuple:
    return (
        f.statement,
        tuple(sorted(_citation_key(c) for c in f.citations)),
        tuple(sorted(f.figures.items())),
        f.weight,
        f.direction,
    )


def _record_diff(
    previous: InvestigationRecord | None,
    findings: list[InvestigationFinding],
    label: str,
) -> RecordDiff:
    if previous is None:
        return RecordDiff(
            from_version=0,
            added=sorted(f.key for f in findings),
            removed=[],
            changed=[],
            hypothesis_changed=False,
        )
    prev_by_key = {f.key: f for f in previous.findings}
    new_by_key = {f.key: f for f in findings}
    return RecordDiff(
        from_version=previous.version,
        added=sorted(set(new_by_key) - set(prev_by_key)),
        removed=sorted(set(prev_by_key) - set(new_by_key)),
        changed=sorted(
            key
            for key in set(new_by_key) & set(prev_by_key)
            if _finding_signature(prev_by_key[key])
            != _finding_signature(new_by_key[key])
        ),
        hypothesis_changed=previous.hypothesis.label != label,
    )


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------


class InvestigationService:
    """Runs the investigation graph and owns the record gate.

    One graph invocation investigates one case. The record it
    produces is verified by :meth:`verify_record` before it is
    stored — the same gate an eval or an auditor can call on any
    record — and persisted as a hash-chained evidence item plus an
    append-only record version.
    """

    def __init__(
        self,
        store: CaseStore,
        screening_store: ScreeningStore,
        typology_store: TypologyStore,
        investigation_store: InvestigationStore,
        evidence: EvidenceService,
        disposition_store: DispositionStore | None = None,
    ) -> None:
        self._store = store
        self._screening = screening_store
        self._typologies = typology_store
        self._records = investigation_store
        self._evidence = evidence
        # R5: when a disposition store is wired, persisting a new
        # record version flags any disposition that relied on an
        # older version as stale (the gate's DISPOSITION_STALE flag).
        self._dispositions = disposition_store
        self._resolver = CitationResolver(store, evidence)
        builder = StateGraph(_State)
        builder.add_node("assemble", self._assemble)
        builder.add_node("draft", self._draft)
        builder.add_node("counter_search", self._counter_search)
        builder.add_node("compose", self._compose)
        builder.add_node("verify", self._verify)
        builder.add_node("persist", self._persist)
        builder.add_edge(START, "assemble")
        builder.add_edge("assemble", "draft")
        builder.add_edge("draft", "counter_search")
        builder.add_edge("counter_search", "compose")
        builder.add_edge("compose", "verify")
        builder.add_edge("verify", "persist")
        builder.add_edge("persist", END)
        self._graph = builder.compile()

    # -- public surface ------------------------------------------------

    def run_investigation(
        self, case_id: str, *, actor: str, profile: str = DEFAULT_PROFILE
    ) -> InvestigationRecord:
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(f"case {case_id} not found")
        if case.status is not CaseStatus.INVESTIGATING:
            raise InvestigationStateError(
                f"case {case_id} is {case.status.value}; the "
                "investigation graph works a case in 'investigating'"
            )
        composer = get_composer(profile)
        fingerprint = _input_fingerprint(
            self._store, self._screening, self._typologies, case
        )
        existing = self._records.list_investigation_records(case_id)
        if (
            existing
            and existing[-1].input_fingerprint == fingerprint
            and existing[-1].model_profile == composer.profile_name
        ):
            logger.info(
                "investigation inputs unchanged for case %s; returning "
                "record %s",
                case_id,
                existing[-1].record_id,
            )
            return existing[-1]
        result = self._graph.invoke(
            {"case_id": case_id, "actor": actor, "composer": composer}
        )
        return result["record"]

    def current_record(self, case_id: str) -> InvestigationRecord | None:
        records = self._records.list_investigation_records(case_id)
        return records[-1] if records else None

    def record_history(self, case_id: str) -> list[InvestigationRecord]:
        return self._records.list_investigation_records(case_id)

    # -- the record gate ------------------------------------------------

    def verify_record(self, record: InvestigationRecord) -> None:
        """The mechanical record-time gate. Raises
        :class:`InvestigationRefusedError` listing every problem:
        an uncited finding, a citation that does not resolve, a
        figure that does not trace to the cited records, a statement
        carrying an ungrounded figure, or broken hypothesis
        discipline. A record that fails here is never stored."""
        problems: list[str] = []
        findings = {f.finding_id: f for f in record.findings}
        if len(findings) != len(record.findings):
            problems.append("duplicate finding ids in record")
        for finding in record.findings:
            if not finding.citations:
                problems.append(f"finding {finding.finding_id} has no citations")
                continue
            cited_tokens: set[Decimal] = set()
            for citation in finding.citations:
                try:
                    resolved = self._resolver.resolve(citation, record.case_id)
                except CitationResolutionError as exc:
                    problems.append(
                        f"finding {finding.finding_id}: {exc}"
                    )
                    continue
                cited_tokens |= tokens_of(resolved)
            if finding.origin in (
                "typology",
                "screening",
                "alert",
                "profile",
                "prior_case",
            ):
                for name, value in finding.figures.items():
                    if not numeric_tokens(value) <= cited_tokens:
                        problems.append(
                            f"finding {finding.finding_id}: figure {name}="
                            f"{value!r} does not appear in its cited records"
                        )
            allowed = cited_tokens | set().union(
                *(numeric_tokens(v) for v in finding.figures.values()),
                set(),
            )
            stray = ungrounded_figures(finding.statement, allowed)
            if stray:
                problems.append(
                    f"finding {finding.finding_id}: statement carries "
                    f"figure(s) not grounded in its citations or "
                    f"figures: {', '.join(stray)}"
                )
        hypothesis = record.hypothesis
        for fid in hypothesis.supporting_finding_ids:
            target = findings.get(fid)
            if target is None:
                problems.append(f"hypothesis supports unknown finding {fid}")
            elif target.direction != "supports":
                problems.append(
                    f"hypothesis names {fid} as supporting but its "
                    f"direction is {target.direction}"
                )
        for fid in hypothesis.counter_finding_ids:
            target = findings.get(fid)
            if target is None:
                problems.append(f"hypothesis counter-names unknown finding {fid}")
            elif target.direction != "against":
                problems.append(
                    f"hypothesis names {fid} as counter-evidence but "
                    f"its direction is {target.direction}"
                )
        counter = record.counter_search
        if counter is None or not counter.ran or not counter.checks:
            problems.append(
                "record carries no counter-evidence search, or the "
                "search recorded no checks"
            )
        else:
            for check in counter.checks:
                if check.outcome == "counter_evidence_found" and (
                    not set(check.counter_finding_ids)
                    <= set(hypothesis.counter_finding_ids)
                ):
                    problems.append(
                        f"counter check {check.name} claims evidence in "
                        "findings the hypothesis does not name"
                    )
        if problems:
            raise InvestigationRefusedError(
                "investigation record refused: " + "; ".join(problems)
            )

    # -- graph nodes -----------------------------------------------------

    def _assemble(self, state: _State) -> dict:
        case_id = state["case_id"]
        actor = state["actor"]
        case = self._store.get_case(case_id)
        items = self._store.list_evidence(case_id)
        alert_item = next(i for i in items if i.kind == "alert_payload")
        alert = Alert.model_validate_json(
            self._evidence.read_item_content(case_id, alert_item.seq).decode("utf-8")
        )
        # The account profile joins the case's evidence the first
        # time an investigation assembles it, so profile facts are
        # citable like everything else. Re-assembly reuses the
        # capture while the profile is unchanged.
        profile = self._typologies.get_account_profile(case.account_id)
        profile_seq: int | None = None
        if profile is not None:
            profile_json = profile.model_dump(mode="json")
            for item in items:
                if item.kind != "account_profile":
                    continue
                captured = json.loads(
                    self._evidence.read_item_content(case_id, item.seq)
                )
                if captured == profile_json:
                    profile_seq = item.seq
                    break
            if profile_seq is None:
                captured_item = self._evidence.add_item(
                    case_id=case_id,
                    kind="account_profile",
                    content=json.dumps(profile_json, indent=2).encode("utf-8"),
                    source_ref=f"core-banking:{case.account_id}",
                    captured_by=actor,
                )
                profile_seq = captured_item.seq
        runs = self._screening.list_screening_runs(case_id)
        screening_run = (
            max(runs, key=lambda r: (r.run_at, r.run_id)) if runs else None
        )
        screening_hits = (
            [
                h
                for h in self._screening.list_hits(case_id)
                if h.run_id == screening_run.run_id
            ]
            if screening_run
            else []
        )
        truns = self._typologies.list_typology_runs(case_id)
        typology_run = (
            max(truns, key=lambda r: (r.run_at, r.run_id)) if truns else None
        )
        typology_findings = (
            [
                f
                for f in self._typologies.list_findings(case_id)
                if f.run_id == typology_run.run_id
            ]
            if typology_run
            else []
        )
        transactions = self._typologies.list_transactions(case_id)
        txn_seq: dict[str, int] = {}
        for batch in self._typologies.list_transaction_batches(case_id):
            content = self._evidence.read_item_content(
                case_id, batch.evidence_seq
            )
            for entry in json.loads(content):
                txn_seq[entry["transaction_id"]] = batch.evidence_seq
        prior_cases = sorted(
            (
                c
                for c in self._store.list_cases()
                if c.customer_id == case.customer_id and c.case_id != case_id
            ),
            key=lambda c: (c.detected_on, c.case_id),
        )
        prior_refs: list[PriorCaseRef] = []
        prior_alert_seqs: dict[str, int] = {}
        for prior in prior_cases:
            prior_items = self._store.list_evidence(prior.case_id)
            prior_alert_item = next(
                i for i in prior_items if i.kind == "alert_payload"
            )
            prior_alert = Alert.model_validate_json(
                self._evidence.read_item_content(
                    prior.case_id, prior_alert_item.seq
                ).decode("utf-8")
            )
            prior_alert_seqs[prior.case_id] = prior_alert_item.seq
            prior_refs.append(
                PriorCaseRef(
                    case_id=prior.case_id,
                    alert_id=prior_alert.alert_id,
                    rule_id=prior_alert.rule_id,
                    status=prior.status.value,
                    detected_on=prior_alert.detected_on,
                )
            )
        return {
            "case": case,
            "alert": alert,
            "alert_seq": alert_item.seq,
            "profile": profile,
            "profile_seq": profile_seq,
            "screening_run": screening_run,
            "screening_hits": screening_hits,
            "typology_run": typology_run,
            "typology_findings": typology_findings,
            "transactions": transactions,
            "txn_seq": txn_seq,
            "prior_cases": prior_cases,
            "prior_refs": prior_refs,
            "prior_alert_seqs": prior_alert_seqs,
        }

    def _draft(self, state: _State) -> dict:
        case = state["case"]
        case_id = case.case_id
        label = _choose_hypothesis(
            state["screening_hits"], state["typology_findings"]
        )
        drafts: list[_Draft] = []

        def make(**kwargs) -> _Draft:
            draft = _Draft(**kwargs, allowed=set())
            draft.allowed = _allowed_for(
                self._resolver, case_id, draft.citations, draft.figures
            )
            return draft

        typology_run = state["typology_run"]
        for finding in state["typology_findings"]:
            citations = [
                Citation(
                    evidence_seq=typology_run.evidence_seq,
                    element=f"finding:{finding.finding_id}",
                )
            ]
            for txn_id in finding.transaction_ids:
                seq = state["txn_seq"].get(txn_id)
                if seq is not None:
                    citations.append(
                        Citation(
                            evidence_seq=seq, element=f"transaction:{txn_id}"
                        )
                    )
            template, extra = _typology_template(finding)
            values = _typology_values(finding)
            values.update(extra)
            drafts.append(
                make(
                    # The key names the pattern (typology + the exact
                    # transactions), not the run's random finding id,
                    # so the same computed pattern keeps one identity
                    # across record versions and diffs stay readable.
                    key=(
                        f"typology:{finding.typology_id}:"
                        + ",".join(sorted(finding.transaction_ids))
                    ),
                    kind="typology",
                    origin="typology",
                    weight=_TYPOLOGY_WEIGHTS.get(finding.typology_id, "medium"),
                    direction=(
                        "supports"
                        if finding.typology_id == label
                        else "context"
                    ),
                    template=template,
                    values=values,
                    figures=dict(finding.figures),
                    citations=citations,
                )
            )

        screening_run = state["screening_run"]
        for hit in state["screening_hits"]:
            list_phrase = hit.list_kind.value.replace("_", " ")
            if hit.status is HitStatus.CLEARED:
                template = (
                    "Screening matched subject {subject_name} to the "
                    "{list_phrase} list entry {entry_name} at score "
                    "{score} ({strength}); the match was cleared at "
                    "screening time on the recorded basis."
                )
                weight, direction = "low", "context"
            else:
                template = (
                    "Screening matched subject {subject_name} to the "
                    "{list_phrase} list entry {entry_name} at score "
                    "{score} ({strength}); the hit stands {status}."
                )
                weight = (
                    "high" if hit.list_kind is ListKind.SANCTIONS else "medium"
                )
                direction = (
                    "supports"
                    if label == "sanctions_match"
                    and hit.list_kind is ListKind.SANCTIONS
                    else "context"
                )
            drafts.append(
                make(
                    # Stable across re-screenings: same subject, same
                    # list entry (hit ids are minted per run).
                    key=f"screening:{hit.subject_ref}:{hit.entry_id}",
                    kind="screening",
                    origin="screening",
                    weight=weight,
                    direction=direction,
                    template=template,
                    values={
                        "subject_name": hit.subject_name,
                        "list_phrase": list_phrase,
                        "entry_name": hit.entry_name,
                        "score": str(hit.score),
                        "strength": hit.strength,
                        "status": hit.status.value,
                    },
                    figures={"score": str(hit.score)},
                    citations=[
                        Citation(
                            evidence_seq=screening_run.evidence_seq,
                            element=f"hit:{hit.hit_id}",
                        )
                    ],
                )
            )
        if screening_run is not None and not state["screening_hits"]:
            drafts.append(
                make(
                    key="screening:no_hits",
                    kind="screening",
                    origin="screening",
                    weight="low",
                    direction="context",
                    template=(
                        "Screening against the pinned list versions "
                        "produced no hits."
                    ),
                    values={},
                    figures={},
                    citations=[
                        Citation(
                            evidence_seq=screening_run.evidence_seq,
                            element=f"run:{screening_run.run_id}",
                        )
                    ],
                )
            )

        alert = state["alert"]
        drafts.append(
            make(
                key="alert:payload",
                kind="alert",
                origin="alert",
                weight="medium",
                direction="context",
                template=(
                    "The monitoring rule {rule_id} raised this alert "
                    "on {detected_on} at {severity} severity: {summary}"
                ),
                values={
                    "rule_id": alert.rule_id,
                    "detected_on": alert.detected_on.isoformat(),
                    "severity": alert.severity.value,
                    "summary": alert.summary,
                },
                figures={},
                citations=[
                    Citation(
                        evidence_seq=state["alert_seq"],
                        element="field:rule_id",
                    ),
                    Citation(
                        evidence_seq=state["alert_seq"],
                        element="field:detected_on",
                    ),
                    Citation(
                        evidence_seq=state["alert_seq"],
                        element="field:summary",
                    ),
                ],
            )
        )

        profile = state["profile"]
        if profile is not None:
            template = (
                "The account was opened on {opened_on} as a "
                "{account_type} account."
            )
            values = {
                "opened_on": profile.opened_on.isoformat(),
                "account_type": profile.account_type,
            }
            figures: dict[str, str] = {}
            citations = [
                Citation(
                    evidence_seq=state["profile_seq"],
                    element="field:opened_on",
                )
            ]
            if (
                profile.expected_monthly_amount is not None
                and profile.expected_monthly_count is not None
            ):
                template += (
                    " The customer profile expects about "
                    "{expected_monthly_count} transactions totalling "
                    "{expected_monthly_amount} a month."
                )
                values["expected_monthly_count"] = str(
                    profile.expected_monthly_count
                )
                values["expected_monthly_amount"] = str(
                    profile.expected_monthly_amount
                )
                figures = {
                    "expected_monthly_amount": str(
                        profile.expected_monthly_amount
                    ),
                    "expected_monthly_count": str(
                        profile.expected_monthly_count
                    ),
                }
                citations += [
                    Citation(
                        evidence_seq=state["profile_seq"],
                        element="field:expected_monthly_count",
                    ),
                    Citation(
                        evidence_seq=state["profile_seq"],
                        element="field:expected_monthly_amount",
                    ),
                ]
            drafts.append(
                make(
                    key="profile:account",
                    kind="profile",
                    origin="profile",
                    weight="low",
                    direction="context",
                    template=template,
                    values=values,
                    figures=figures,
                    citations=citations,
                )
            )

        for ref in state["prior_refs"]:
            drafts.append(
                make(
                    key=f"prior:{ref.case_id}",
                    kind="prior_case",
                    origin="prior_case",
                    weight=(
                        "medium"
                        if ref.rule_id == alert.rule_id
                        else "low"
                    ),
                    direction=(
                        "supports"
                        if label in _ADVERSE_LABELS
                        and ref.rule_id == alert.rule_id
                        else "context"
                    ),
                    template=(
                        "The customer has a prior case under rule "
                        "{rule_id}, raised on {detected_on}; that case "
                        "stands {status}."
                    ),
                    values={
                        "rule_id": ref.rule_id,
                        "detected_on": ref.detected_on.isoformat(),
                        "status": ref.status,
                    },
                    figures={},
                    citations=[
                        Citation(
                            case_id=ref.case_id,
                            evidence_seq=state["prior_alert_seqs"][ref.case_id],
                            element="field:rule_id",
                        ),
                        Citation(
                            case_id=ref.case_id,
                            evidence_seq=state["prior_alert_seqs"][ref.case_id],
                            element="field:detected_on",
                        ),
                    ],
                )
            )
        return {"label": label, "drafts": drafts}

    # -- counter-evidence search -----------------------------------------

    def _txn_citations(
        self, state: _State, txns: list[Transaction]
    ) -> list[Citation]:
        citations = []
        for txn in txns:
            seq = state["txn_seq"].get(txn.transaction_id)
            if seq is not None:
                citations.append(
                    Citation(
                        evidence_seq=seq,
                        element=f"transaction:{txn.transaction_id}",
                    )
                )
        return citations

    def _counter_draft(self, state: _State, **kwargs) -> _Draft:
        draft = _Draft(**kwargs, allowed=set())
        draft.allowed = _allowed_for(
            self._resolver, state["case_id"], draft.citations, draft.figures
        )
        return draft

    def _cadence_check(
        self, state: _State, subset: list[Transaction], noun: str, key: str
    ) -> tuple[CounterCheck, _Draft | None]:
        stats = _cadence(subset)
        if stats is None:
            return (
                CounterCheck(
                    name="regular_cadence",
                    outcome="no_counter_evidence",
                    description=(
                        f"All {len(subset)} {noun} in the stored stream "
                        "for this account."
                    ),
                    detail=(
                        f"Only {len(subset)} {noun} are stored; too few "
                        "to establish any recurring cadence."
                    ),
                ),
                None,
            )
        coverage = (
            f"All {len(subset)} {noun} in the stored stream for this "
            "account, examined for a regular long-window cadence."
        )
        if not stats["regular"]:
            return (
                CounterCheck(
                    name="regular_cadence",
                    outcome="no_counter_evidence",
                    description=coverage,
                    detail=(
                        f"The {noun} span {stats['span_days']} days "
                        f"across {stats['count']} transactions with "
                        f"gaps of {stats['min_gap_days']} to "
                        f"{stats['max_gap_days']} days; no regular "
                        "long-window cadence is present."
                    ),
                ),
                None,
            )
        figures = {
            "count": str(stats["count"]),
            "span_days": str(stats["span_days"]),
            "min_gap_days": str(stats["min_gap_days"]),
            "max_gap_days": str(stats["max_gap_days"]),
        }
        draft = self._counter_draft(
            state,
            key=key,
            kind="counter",
            origin="counter_search",
            weight="medium",
            direction="against",
            template=(
                "Across the stored stream, {count} {noun} recur on a "
                "regular cadence over {span_days} days, with gaps of "
                "{min_gap_days} to {max_gap_days} days — consistent "
                "with a recurring pattern rather than a one-off "
                "cluster."
            ),
            values={**figures, "noun": noun},
            figures=figures,
            citations=self._txn_citations(state, stats["transactions"]),
        )
        return (
            CounterCheck(
                name="regular_cadence",
                outcome="counter_evidence_found",
                description=coverage,
                detail=(
                    f"{stats['count']} {noun} span {stats['span_days']} "
                    f"days with regular gaps of "
                    f"{stats['min_gap_days']} to {stats['max_gap_days']} "
                    "days."
                ),
                counter_finding_ids=[key],
            ),
            draft,
        )

    def _expectation_check(
        self,
        state: _State,
        subset: list[Transaction],
        noun: str,
        key: str,
    ) -> tuple[CounterCheck, _Draft | None]:
        profile = state["profile"]
        if not subset:
            return (
                CounterCheck(
                    name="documented_expectation",
                    outcome="no_counter_evidence",
                    description=(
                        "The account profile's documented expectation, "
                        f"tested against the monthly pattern of the {noun}."
                    ),
                    detail=(
                        f"No {noun} exist in the stored stream to "
                        "match against a documented recurring "
                        "obligation."
                    ),
                ),
                None,
            )
        if profile is None or profile.expected_monthly_amount is None:
            return (
                CounterCheck(
                    name="documented_expectation",
                    outcome="not_applicable",
                    description=(
                        "The account profile's documented expectation, "
                        "tested against the monthly pattern of the "
                        f"{noun}."
                    ),
                    detail=(
                        "The account profile records no expected "
                        "monthly activity to test against."
                    ),
                ),
                None,
            )
        stability = _monthly_stability(subset)
        coverage = (
            f"Monthly totals of the {noun} across the stored stream, "
            "tested for stability against the profile's documented "
            "expected monthly amount."
        )
        if not stability or not stability["stable"]:
            months = stability["months"] if stability else 0
            return (
                CounterCheck(
                    name="documented_expectation",
                    outcome="no_counter_evidence",
                    description=coverage,
                    detail=(
                        f"The {noun} span {months} month(s) without a "
                        "stable monthly pattern that matches a "
                        "documented recurring obligation."
                    ),
                ),
                None,
            )
        figures = {
            "months": str(stability["months"]),
            "median_monthly_total": str(stability["median"]),
            "expected_monthly_amount": str(profile.expected_monthly_amount),
        }
        draft = self._counter_draft(
            state,
            key=key,
            kind="counter",
            origin="counter_search",
            weight="medium",
            direction="against",
            template=(
                "The {noun} recur across {months} months at a stable "
                "monthly total (median {median_monthly_total}), and "
                "the account profile documents expected monthly "
                "activity of {expected_monthly_amount} — consistent "
                "with a documented recurring obligation."
            ),
            values={**figures, "noun": noun},
            figures=figures,
            citations=self._txn_citations(state, subset)
            + [
                Citation(
                    evidence_seq=state["profile_seq"],
                    element="field:expected_monthly_amount",
                )
            ],
        )
        return (
            CounterCheck(
                name="documented_expectation",
                outcome="counter_evidence_found",
                description=coverage,
                detail=(
                    f"Monthly totals are stable across "
                    f"{stability['months']} months (median "
                    f"{stability['median']}) against a documented "
                    f"expectation of {profile.expected_monthly_amount}."
                ),
                counter_finding_ids=[key],
            ),
            draft,
        )

    def _counter_search(self, state: _State) -> dict:
        label = state["label"]
        txns = state["transactions"]
        findings = state["typology_findings"]
        checks: list[CounterCheck] = []
        extra: list[_Draft] = []

        def add(result: tuple[CounterCheck, _Draft | None]) -> None:
            check, draft = result
            checks.append(check)
            if draft is not None:
                extra.append(draft)

        if label == "structuring":
            finding = next(
                f for f in findings if f.typology_id == "structuring"
            )
            # The counter-search reasons over the in-band population
            # BEYOND the flagged cluster: the innocent explanation
            # for a cluster is that the same deposits recur on a
            # documented cadence outside it.
            flagged = set(finding.transaction_ids)
            in_band = [
                t
                for t in _in_band_cash(txns, finding)
                if t.transaction_id not in flagged
            ]
            noun = (
                "further cash credits inside the band beyond the "
                "flagged cluster"
                if finding.figures["direction"] == "credit"
                else "further cash debits inside the band beyond the "
                "flagged cluster"
            )
            add(self._cadence_check(state, in_band, noun, "counter:cadence"))
            add(
                self._expectation_check(
                    state, in_band, noun, "counter:expectation"
                )
            )
            coverage = (
                "Searched the stored transaction stream beyond the "
                "flagged cluster for innocent explanations of the "
                "in-band cash pattern: a regular long-window cadence, "
                "and agreement with the account's documented "
                "expectation."
            )
        elif label == "round_amount":
            finding = next(
                f for f in findings if f.typology_id == "round_amount"
            )
            unit = Decimal(finding.figures["round_unit"])
            subset = [
                t for t in txns if t.amount > 0 and t.amount % unit == 0
            ]
            add(
                self._cadence_check(
                    state, subset, "round-amount transactions",
                    "counter:cadence",
                )
            )
            add(
                self._expectation_check(
                    state, subset, "round-amount transactions",
                    "counter:expectation",
                )
            )
            coverage = (
                "Searched the stored stream for innocent explanations "
                "of the round amounts: a regular long-window cadence, "
                "and agreement with the account's documented "
                "expectation."
            )
        elif label == "velocity":
            finding = next(f for f in findings if f.typology_id == "velocity")
            add(self._velocity_history_check(state, finding))
            add(self._velocity_expectation_check(state, finding))
            coverage = (
                "Searched the account's own baseline history for a "
                "comparable surge, and the observation month against "
                "the account's documented expectation."
            )
        elif label == "dormancy_then_burst":
            finding = next(
                f for f in findings if f.typology_id == "dormancy_then_burst"
            )
            add(self._dormancy_expectation_check(state, finding))
            coverage = (
                "Tested the burst's size against the account's "
                "documented expectation — the innocent explanation "
                "available in the record for a resumed account."
            )
        elif label == "rapid_in_out":
            finding = next(
                f for f in findings if f.typology_id == "rapid_in_out"
            )
            add(self._established_counterparty_check(state, finding))
            coverage = (
                "Searched the stored stream for an established "
                "relationship with the pass-through counterparty — "
                "the innocent explanation available in the record "
                "for a conduit pattern."
            )
        elif label == "sanctions_match":
            add(self._namesake_check(state))
            add(self._corroboration_check(state))
            coverage = (
                "Searched this case's full screening history for a "
                "cleared namesake match on the same subject, and "
                "recorded the open hit's corroboration strength."
            )
        else:  # no_adverse_pattern
            checks.append(
                CounterCheck(
                    name="adverse_search_coverage",
                    outcome=(
                        "no_counter_evidence"
                        if state["typology_run"] and state["screening_run"]
                        else "not_applicable"
                    ),
                    description=(
                        "The typology run and the screening run over "
                        "this case — the searches that would have "
                        "produced adverse findings."
                    ),
                    detail=(
                        f"Typology run "
                        f"{state['typology_run'].run_id if state['typology_run'] else 'none'} "
                        f"produced {len(findings)} finding(s); screening "
                        f"run {state['screening_run'].run_id if state['screening_run'] else 'none'} "
                        f"produced {len(state['screening_hits'])} hit(s), "
                        "none standing open."
                    ),
                )
            )
            coverage = (
                "For a no-adverse-pattern hypothesis the counter-search "
                "is the adverse search itself: the typology and "
                "screening runs were examined for anything they "
                "produced."
            )
        counter = CounterSearch(ran=True, coverage=coverage, checks=checks)
        return {"drafts": state["drafts"] + extra, "counter": counter}

    def _velocity_history_check(
        self, state: _State, finding: TypologyFinding
    ) -> tuple[CounterCheck, _Draft | None]:
        txns = state["transactions"]
        window_days = (finding.window_end - finding.window_start).days + 1
        baseline = [
            t for t in txns if t.posted_at.date() < finding.window_start
        ]
        peak: list[Transaction] = []
        for anchor in baseline:
            start = anchor.posted_at.date()
            window = [
                t
                for t in baseline
                if start <= t.posted_at.date() < start + timedelta(days=window_days)
            ]
            if len(window) > len(peak):
                peak = window
        observation_count = int(finding.figures["observation_count"])
        coverage = (
            f"Every {window_days}-day window in the account's stored "
            "baseline history, compared with the observation window's "
            "count."
        )
        if len(peak) * 2 >= observation_count and peak:
            figures = {
                "baseline_peak_count": str(len(peak)),
                "observation_count": str(observation_count),
                "window_days": str(window_days),
            }
            draft = self._counter_draft(
                state,
                key="counter:history",
                kind="counter",
                origin="counter_search",
                weight="medium",
                direction="against",
                template=(
                    "The account's own baseline holds "
                    "{baseline_peak_count} transactions inside "
                    "{window_days} days — at least half the "
                    "observation count of {observation_count} — so "
                    "surges of this size have occurred in the "
                    "account's ordinary history."
                ),
                values=figures,
                figures=figures,
                citations=self._txn_citations(state, peak)
                + [
                    Citation(
                        evidence_seq=state["typology_run"].evidence_seq,
                        element=f"finding:{finding.finding_id}",
                    )
                ],
            )
            return (
                CounterCheck(
                    name="recurring_pattern_in_history",
                    outcome="counter_evidence_found",
                    description=coverage,
                    detail=(
                        f"The baseline's busiest {window_days}-day "
                        f"window holds {len(peak)} transactions "
                        f"against an observation count of "
                        f"{observation_count}."
                    ),
                    counter_finding_ids=["counter:history"],
                ),
                draft,
            )
        return (
            CounterCheck(
                name="recurring_pattern_in_history",
                outcome="no_counter_evidence",
                description=coverage,
                detail=(
                    f"The baseline's busiest {window_days}-day window "
                    f"holds {len(peak)} transactions, under half the "
                    f"observation count of {observation_count}."
                ),
            ),
            None,
        )

    def _velocity_expectation_check(
        self, state: _State, finding: TypologyFinding
    ) -> tuple[CounterCheck, _Draft | None]:
        profile = state["profile"]
        if profile is None or profile.expected_monthly_amount is None:
            return (
                CounterCheck(
                    name="documented_expectation",
                    outcome="not_applicable",
                    description=(
                        "The observation month's stored total against "
                        "the profile's documented expectation."
                    ),
                    detail=(
                        "The account profile records no expected "
                        "monthly activity to test against."
                    ),
                ),
                None,
            )
        month = (finding.window_end.year, finding.window_end.month)
        month_txns = [
            t
            for t in state["transactions"]
            if (t.posted_at.year, t.posted_at.month) == month
        ]
        total = sum((t.amount for t in month_txns), Decimal("0"))
        expected = profile.expected_monthly_amount
        coverage = (
            "The stored transactions in the observation month, "
            "totalled and compared with the profile's documented "
            "expected monthly amount (a quarter's tolerance allowed)."
        )
        if total <= expected * Decimal("1.25"):
            figures = {
                "month_total": str(total),
                "expected_monthly_amount": str(expected),
            }
            draft = self._counter_draft(
                state,
                key="counter:expectation",
                kind="counter",
                origin="counter_search",
                weight="medium",
                direction="against",
                template=(
                    "The stored transactions in the observation month "
                    "total {month_total}, within the profile's "
                    "documented expected monthly amount of "
                    "{expected_monthly_amount}."
                ),
                values=figures,
                figures=figures,
                citations=self._txn_citations(state, month_txns)
                + [
                    Citation(
                        evidence_seq=state["profile_seq"],
                        element="field:expected_monthly_amount",
                    )
                ],
            )
            return (
                CounterCheck(
                    name="documented_expectation",
                    outcome="counter_evidence_found",
                    description=coverage,
                    detail=(
                        f"The observation month totals {total} "
                        f"against a documented expectation of "
                        f"{expected}."
                    ),
                    counter_finding_ids=["counter:expectation"],
                ),
                draft,
            )
        return (
            CounterCheck(
                name="documented_expectation",
                outcome="no_counter_evidence",
                description=coverage,
                detail=(
                    f"The observation month totals {total}, beyond "
                    f"the documented expectation of {expected}."
                ),
            ),
            None,
        )

    def _dormancy_expectation_check(
        self, state: _State, finding: TypologyFinding
    ) -> tuple[CounterCheck, _Draft | None]:
        profile = state["profile"]
        burst = Decimal(finding.figures["burst_amount"])
        if profile is None or profile.expected_monthly_amount is None:
            return (
                CounterCheck(
                    name="documented_expectation",
                    outcome="not_applicable",
                    description=(
                        "The burst total against the profile's "
                        "documented expectation."
                    ),
                    detail=(
                        "The account profile records no expected "
                        "monthly activity to test against."
                    ),
                ),
                None,
            )
        expected = profile.expected_monthly_amount
        coverage = (
            "The burst total from the typology finding, compared "
            "with the profile's documented expected monthly amount."
        )
        if burst <= expected:
            figures = {
                "burst_amount": finding.figures["burst_amount"],
                "expected_monthly_amount": str(expected),
            }
            draft = self._counter_draft(
                state,
                key="counter:expectation",
                kind="counter",
                origin="counter_search",
                weight="medium",
                direction="against",
                template=(
                    "The burst totals {burst_amount}, no more than "
                    "the profile's documented expected monthly amount "
                    "of {expected_monthly_amount}; its size alone is "
                    "not inconsistent with the documented profile."
                ),
                values=figures,
                figures=figures,
                citations=[
                    Citation(
                        evidence_seq=state["typology_run"].evidence_seq,
                        element=f"finding:{finding.finding_id}",
                    ),
                    Citation(
                        evidence_seq=state["profile_seq"],
                        element="field:expected_monthly_amount",
                    ),
                ],
            )
            return (
                CounterCheck(
                    name="documented_expectation",
                    outcome="counter_evidence_found",
                    description=coverage,
                    detail=(
                        f"The burst of {burst} sits within the "
                        f"documented expectation of {expected}."
                    ),
                    counter_finding_ids=["counter:expectation"],
                ),
                draft,
            )
        return (
            CounterCheck(
                name="documented_expectation",
                outcome="no_counter_evidence",
                description=coverage,
                detail=(
                    f"The burst of {burst} exceeds the documented "
                    f"expectation of {expected}."
                ),
            ),
            None,
        )

    def _established_counterparty_check(
        self, state: _State, finding: TypologyFinding
    ) -> tuple[CounterCheck, _Draft | None]:
        by_id = {t.transaction_id: t for t in state["transactions"]}
        credit = by_id.get(finding.transaction_ids[0])
        coverage = (
            "The stored stream before the pass-through window, "
            "searched for earlier transactions with the same "
            "counterparty."
        )
        if credit is None or not credit.counterparty:
            return (
                CounterCheck(
                    name="established_counterparty",
                    outcome="not_applicable",
                    description=coverage,
                    detail=(
                        "The pass-through credit names no counterparty "
                        "to search for."
                    ),
                ),
                None,
            )
        prior = [
            t
            for t in state["transactions"]
            if t.counterparty == credit.counterparty
            and t.posted_at.date() < finding.window_start
            and t.transaction_id not in finding.transaction_ids
        ]
        if len(prior) >= 2:
            figures = {"prior_count": str(len(prior))}
            draft = self._counter_draft(
                state,
                key="counter:counterparty",
                kind="counter",
                origin="counter_search",
                weight="medium",
                direction="against",
                template=(
                    "The counterparty {counterparty} appears in "
                    "{prior_count} earlier transactions on this "
                    "account — an established relationship, not a "
                    "first-seen conduit counterparty."
                ),
                values={
                    **figures,
                    "counterparty": credit.counterparty,
                },
                figures=figures,
                citations=self._txn_citations(state, prior)
                + self._txn_citations(state, [credit]),
            )
            return (
                CounterCheck(
                    name="established_counterparty",
                    outcome="counter_evidence_found",
                    description=coverage,
                    detail=(
                        f"{credit.counterparty} appears in "
                        f"{len(prior)} earlier transactions."
                    ),
                    counter_finding_ids=["counter:counterparty"],
                ),
                draft,
            )
        return (
            CounterCheck(
                name="established_counterparty",
                outcome="no_counter_evidence",
                description=coverage,
                detail=(
                    f"{credit.counterparty} appears in {len(prior)} "
                    "earlier transaction(s); no established "
                    "relationship is shown."
                ),
            ),
            None,
        )

    def _namesake_check(
        self, state: _State
    ) -> tuple[CounterCheck, _Draft | None]:
        case_id = state["case_id"]
        open_names = {
            h.subject_name
            for h in state["screening_hits"]
            if h.status is not HitStatus.CLEARED
        }
        all_hits = self._screening.list_hits(case_id)
        runs = {
            r.run_id: r for r in self._screening.list_screening_runs(case_id)
        }
        cleared = next(
            (
                h
                for h in all_hits
                if h.status is HitStatus.CLEARED
                and h.subject_name in open_names
            ),
            None,
        )
        coverage = (
            "Every screening run on this case, searched for a "
            "cleared hit on a subject the open hits name."
        )
        if cleared is None:
            return (
                CounterCheck(
                    name="namesake_cleared_same_name",
                    outcome="no_counter_evidence",
                    description=coverage,
                    detail=(
                        "No cleared namesake match exists in this "
                        "case's screening history."
                    ),
                ),
                None,
            )
        run = runs[cleared.run_id]
        draft = self._counter_draft(
            state,
            key="counter:namesake",
            kind="counter",
            origin="counter_search",
            weight="medium",
            direction="against",
            template=(
                "Screening also matched {subject_name} to a list "
                "entry that was cleared as a namesake on a "
                "date-of-birth mismatch — the name alone has already "
                "produced a false match in this case's screening."
            ),
            values={"subject_name": cleared.subject_name},
            figures={},
            citations=[
                Citation(
                    evidence_seq=run.evidence_seq,
                    element=f"hit:{cleared.hit_id}",
                )
            ],
        )
        return (
            CounterCheck(
                name="namesake_cleared_same_name",
                outcome="counter_evidence_found",
                description=coverage,
                detail=(
                    f"A match on {cleared.subject_name} was cleared "
                    "as a namesake in this case's screening history."
                ),
                counter_finding_ids=["counter:namesake"],
            ),
            draft,
        )

    def _corroboration_check(
        self, state: _State
    ) -> tuple[CounterCheck, _Draft | None]:
        open_hit = next(
            (
                h
                for h in state["screening_hits"]
                if h.status is not HitStatus.CLEARED
                and h.list_kind is ListKind.SANCTIONS
            ),
            None,
        )
        if open_hit is None:
            return (
                CounterCheck(
                    name="identifier_corroboration",
                    outcome="not_applicable",
                    description="The open sanctions hit's match strength.",
                    detail="No open sanctions hit stands on this case.",
                ),
                None,
            )
        if open_hit.strength == "exact":
            detail = (
                "The open sanctions hit is an exact match on name "
                "and identifiers; nothing in the screening record "
                "cuts against it."
            )
        else:
            detail = (
                f"The open sanctions hit is a {open_hit.strength} "
                "match — name-based; identity corroboration remains "
                "an open question on this case."
            )
        return (
            CounterCheck(
                name="identifier_corroboration",
                outcome="no_counter_evidence",
                description="The open sanctions hit's match strength.",
                detail=detail,
            ),
            None,
        )

    def _open_questions(self, state: _State) -> list[OpenQuestion]:
        case_id = state["case_id"]
        kinds = {i.kind for i in self._store.list_evidence(case_id)}
        questions: list[OpenQuestion] = []
        if state["label"] in _ADVERSE_LABELS and not (kinds & _SOF_KINDS):
            questions.append(
                OpenQuestion(
                    question=(
                        "What is the documented source of the funds "
                        "behind the activity this case examines?"
                    ),
                    evidence_needed="source_of_funds_documentation",
                    rationale=(
                        "The file holds transaction records and "
                        "computed findings but no source-of-funds "
                        "documentation from the customer; the "
                        "hypothesis can be neither confirmed nor "
                        "cleared without it."
                    ),
                )
            )
        if state["screening_run"] is None:
            questions.append(
                OpenQuestion(
                    question=(
                        "Has the case been screened against the "
                        "current list snapshots?"
                    ),
                    evidence_needed="screening_run",
                    rationale=(
                        "No screening run stands on this case; the "
                        "record cannot speak to list exposure."
                    ),
                )
            )
        if state["typology_run"] is None:
            if state["transactions"]:
                questions.append(
                    OpenQuestion(
                        question=(
                            "What do the stored transactions show "
                            "under the typology rules?"
                        ),
                        evidence_needed="typology_run",
                        rationale=(
                            "Transactions are stored but the typology "
                            "engine has not run over them."
                        ),
                    )
                )
            else:
                questions.append(
                    OpenQuestion(
                        question="What transactions stand behind this alert?",
                        evidence_needed="transaction_records",
                        rationale=(
                            "No transaction batch has been ingested "
                            "for this case."
                        ),
                    )
                )
        if any(
            h.status is not HitStatus.CLEARED for h in state["screening_hits"]
        ):
            questions.append(
                OpenQuestion(
                    question=(
                        "Is the screened subject the listed person "
                        "the open hit names?"
                    ),
                    evidence_needed="customer_identification_documentation",
                    rationale=(
                        "A screening hit stands open; identification "
                        "documentation is what confirms or clears "
                        "the identity match."
                    ),
                )
            )
        if state["profile"] is None:
            questions.append(
                OpenQuestion(
                    question=(
                        "What activity did the customer document as "
                        "expected when the account was opened?"
                    ),
                    evidence_needed="account_profile",
                    rationale=(
                        "No account profile is available for this "
                        "account; activity cannot be tested against "
                        "a documented expectation."
                    ),
                )
            )
        return questions

    def _compose(self, state: _State) -> dict:
        composer = state["composer"]
        findings: list[InvestigationFinding] = []
        for index, draft in enumerate(state["drafts"], start=1):
            statement = composer.compose(
                StatementDraft(
                    template=draft.template,
                    values=draft.values,
                    allowed=draft.allowed,
                )
            )
            findings.append(
                InvestigationFinding(
                    finding_id=f"F-{index:03d}",
                    key=draft.key,
                    kind=draft.kind,
                    origin=draft.origin,
                    statement=statement,
                    citations=draft.citations,
                    figures=draft.figures,
                    weight=draft.weight,
                    direction=draft.direction,
                )
            )
        key_to_id = {f.key: f.finding_id for f in findings}
        counter = state["counter"]
        checks = [
            check.model_copy(
                update={
                    "counter_finding_ids": [
                        key_to_id[k] for k in check.counter_finding_ids
                    ]
                }
            )
            for check in counter.checks
        ]
        counter_ids = [
            f.finding_id for f in findings if f.direction == "against"
        ]
        counter = counter.model_copy(
            update={"checks": checks, "counter_finding_ids": counter_ids}
        )
        hypothesis = Hypothesis(
            label=state["label"],
            statement=_HYPOTHESIS_STATEMENTS[state["label"]],
            supporting_finding_ids=[
                f.finding_id for f in findings if f.direction == "supports"
            ],
            counter_finding_ids=counter_ids,
        )
        return {
            "findings": findings,
            "counter": counter,
            "hypothesis": hypothesis,
            "open_questions": self._open_questions(state),
        }

    def _verify(self, state: _State) -> dict:
        case = state["case"]
        existing = self._records.list_investigation_records(case.case_id)
        previous = existing[-1] if existing else None
        version = (previous.version + 1) if previous else 1
        fingerprint = _input_fingerprint(
            self._store, self._screening, self._typologies, case
        )
        record = InvestigationRecord(
            record_id=f"INV-{case.case_id}-V{version}",
            case_id=case.case_id,
            version=version,
            actor=state["actor"],
            model_profile=state["composer"].profile_name,
            input_fingerprint=fingerprint,
            findings=state["findings"],
            hypothesis=state["hypothesis"],
            counter_search=state["counter"],
            open_questions=state["open_questions"],
            prior_case_refs=state["prior_refs"],
            supersedes_record_id=previous.record_id if previous else None,
            diff=_record_diff(previous, state["findings"], state["label"]),
        )
        # The gate: nothing reaches persist unless this passes.
        self.verify_record(record)
        return {"record": record}

    def _persist(self, state: _State) -> dict:
        record = state["record"]
        content = record.model_dump_json(indent=2).encode("utf-8")
        item = self._evidence.add_item(
            case_id=record.case_id,
            kind="investigation_record",
            content=content,
            source_ref=f"investigation:{record.record_id}",
            captured_by=state["actor"],
        )
        final = record.model_copy(update={"evidence_seq": item.seq})
        self._records.add_investigation_record(final)
        self._store.append_audit(
            AuditEvent(
                case_id=record.case_id,
                event="investigation_recorded",
                actor=state["actor"],
                detail={
                    "record_id": record.record_id,
                    "version": str(record.version),
                    "findings": str(len(record.findings)),
                    "hypothesis": record.hypothesis.label,
                    "evidence_seq": str(item.seq),
                    "supersedes": record.supersedes_record_id or "",
                },
            )
        )
        if self._dispositions is not None and record.supersedes_record_id:
            # A disposition recorded against an older version of
            # this record now stands on a superseded basis (R5).
            flag_dispositions_stale(
                self._store,
                self._dispositions,
                record.case_id,
                current_record_version=record.version,
                actor=state["actor"],
            )
        logger.info(
            "investigation recorded for case %s: %s (%d findings, "
            "hypothesis %s)",
            record.case_id,
            record.record_id,
            len(record.findings),
            record.hypothesis.label,
        )
        return {"record": final}
