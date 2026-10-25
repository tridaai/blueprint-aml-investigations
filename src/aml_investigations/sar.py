"""SAR narrative drafting + the citation verifier (R6): Law 2.

R5's gate routes a case to SAR drafting (``escalate_sar`` →
``sar_pending``). This round builds the drafting itself — and the
verifier that decides whether a draft may stand as ready. Two
halves, one discipline:

**Drafting is assembly, not authorship.** The narrative is composed
through the repo's model port (``composer.py``): the deterministic
offline composer by default, a live profile behind the same port
refusing loudly until a key is wired. Every statement is assembled
from the case's current investigation record — restating a cited
finding, or filling a template with values read out of cited
evidence elements — so the draft carries its citations as it is
built, not as decoration added afterwards. Figures are copied from
code-computed findings as exact decimal strings; the drafting side
never computes money (Law 4) and never decides anything (Law 1):
drafting requires the analyst's escalate_sar disposition to already
stand on the case.

**Verification is code over the finished text.** The citation
verifier re-resolves every citation through R4's
:class:`CitationResolver` (the same resolver the investigation
record gate uses — there is no second one), re-checks every figure
against the cited records, requires every asserted value to appear
in the cited elements, binds every restated finding to the cited
record, and checks the narrative-level completeness rules: the
subject section stands, a statable flagged total is carried, and
*every open question in the record appears in the "what remains
unknown" section* — a narrative that hides what is not known fails
verification by construction. Verdicts are stored per statement;
the narrative is VERIFIED only when every statement verifies and
no narrative-level problem stands.

Versioning and standing follow the house pattern: drafts are
append-only versions on the case's hash chain (evidence kind
``sar_narrative``), verification runs are their own append-only
records (kind ``sar_narrative_verification``), and standing is
derived — superseded by a newer draft, **stale** when the record
it cites has been superseded (a verified narrative drops back; it
cannot proceed to approval on a moved basis), verified when the
latest verification passes, draft otherwise.

And the boundary this round never crosses, stated plainly: **no
SAR is ever filed by this system.** R6 ends at a verified draft —
ready for R7's dual-control approval, which is a second person's
act, and even an approved narrative is a sealed case file, not a
filing.
"""

from __future__ import annotations

import json
from decimal import Decimal

from .composer import (
    DEFAULT_PROFILE,
    NarrativeComposer,
    StatementDraft,
    get_composer,
    numeric_tokens,
    tokens_of,
    ungrounded_figures,
)
from .errors import (
    CaseNotFoundError,
    CitationResolutionError,
    NarrativeNotFoundError,
    SarNarrativeRefusedError,
)
from .evidence import EvidenceService, ensure_case_mutable
from .investigation import CitationResolver
from .logging_config import get_logger
from .models import (
    Alert,
    ApprovalOutcome,
    AuditEvent,
    Case,
    CaseStatus,
    Citation,
    DispositionOutcome,
    DispositionRecord,
    InvestigationFinding,
    InvestigationRecord,
    NarrativeSection,
    NarrativeStatement,
    NarrativeVerification,
    SarNarrative,
    StatementVerdict,
)
from .ports import (
    ApprovalStore,
    CaseStore,
    DispositionStore,
    InvestigationStore,
    SarNarrativeStore,
    SealStore,
)

logger = get_logger(__name__)

#: The verifier's identity on its records. Verification is a code
#: act; the record names the code, never a model.
VERIFIER_IDENTITY = "citation-verifier"

#: Figure keys on a typology finding that state a flagged total —
#: the amounts a SAR narrative must be able to carry. A record with
#: no typology finding carrying one of these cannot state its
#: flagged amounts, and drafting is refused rather than improvised.
TOTAL_FIGURE_KEYS = (
    "total_amount",
    "observation_amount",
    "burst_amount",
    "round_total",
    "credit_amount",
)

#: Figure keys that count the transactions a total covers.
COUNT_FIGURE_KEYS = (
    "transaction_count",
    "observation_count",
    "burst_count",
    "round_count",
)

#: Sections every narrative must carry, in filing order. The
#: branch section is conditional — it appears only when branch
#: facts are present in the cited evidence.
REQUIRED_SECTIONS = (
    "subject_identification",
    "activity_summary",
    "chronology",
    "amounts_and_instruments",
    "what_remains_unknown",
)

_SECTION_TITLES = {
    "subject_identification": "Subject identification",
    "activity_summary": "Activity summary",
    "chronology": "Chronology of the flagged activity",
    "amounts_and_instruments": "Amounts and instruments",
    "branch_office_facts": "Branch and office facts",
    "what_remains_unknown": "What remains unknown",
}


class SarNarrativeService:
    """Drafts SAR narratives from investigation records, and runs
    the citation verifier that decides whether a draft stands."""

    def __init__(
        self,
        store: CaseStore,
        records: InvestigationStore,
        dispositions: DispositionStore,
        narratives: SarNarrativeStore,
        evidence: EvidenceService,
        approval_store: ApprovalStore | None = None,
        seal_store: SealStore | None = None,
    ) -> None:
        self._store = store
        self._records = records
        self._dispositions = dispositions
        self._narratives = narratives
        self._evidence = evidence
        # R7: when the approval store is wired, standing knows the
        # dual-control gate's decisions (approved / rejected), and a
        # rejected draft no longer counts as the standing draft —
        # re-drafting composes the next version. When a seal store
        # is wired, drafting and verification refuse on a sealed
        # case like every other mutating path.
        self._approvals = approval_store
        self._seals = seal_store
        self._resolver = CitationResolver(store, evidence)

    # -- refusals -----------------------------------------------------

    def _refuse(
        self, case_id: str, actor: str, reason: str, message: str
    ) -> SarNarrativeRefusedError:
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="sar_draft_refused",
                detail={"reason": reason, "message": message},
            )
        )
        return SarNarrativeRefusedError(reason, message)

    def _require_case(self, case_id: str) -> Case:
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        return case

    # -- drafting -------------------------------------------------------

    def draft_narrative(
        self,
        case_id: str,
        *,
        actor: str,
        profile: str = DEFAULT_PROFILE,
    ) -> tuple[SarNarrative, NarrativeVerification]:
        """Draft (or return the standing draft of) the case's SAR
        narrative, then run the citation verifier over it.

        Lawful only in ``sar_pending``, only over the case's current
        investigation record, only on the standing of the
        escalate_sar disposition that routed the case here.
        """
        case = self._require_case(case_id)
        ensure_case_mutable(self._seals, case_id)
        if not actor or not actor.strip():
            raise self._refuse(
                case_id,
                actor or "anonymous",
                "actor_required",
                "drafting must name the actor running it — the "
                "draft records who (or what service) produced it",
            )
        if case.status is not CaseStatus.SAR_PENDING:
            raise self._refuse(
                case_id,
                actor,
                "case_not_sar_pending",
                f"case is {case.status.value}; SAR narrative "
                "drafting is lawful only for a case in sar_pending "
                "— the state the analyst gate's escalate_sar "
                "disposition routes a case to",
            )

        history = self._records.list_investigation_records(case_id)
        current = history[-1] if history else None
        if current is None:
            raise self._refuse(
                case_id,
                actor,
                "no_investigation_record",
                "the case holds no investigation record; there is "
                "nothing for a narrative to be drafted from",
            )

        routing = self._routing_disposition(case_id)
        if routing is None:
            raise self._refuse(
                case_id,
                actor,
                "sar_disposition_missing",
                "no escalate_sar disposition stands on this case; "
                "the narrative is drafted on an analyst's recorded "
                "decision to file, never on the drafting service's "
                "own initiative",
            )
        if (
            routing.record_id != current.record_id
            or routing.record_version != current.version
        ):
            raise self._refuse(
                case_id,
                actor,
                "sar_disposition_not_current",
                f"the escalate_sar disposition {routing.disposition_id} "
                f"relies on record {routing.record_id} version "
                f"{routing.record_version}, but the case's current "
                f"record is {current.record_id} version "
                f"{current.version}; a fresh disposition on the "
                "current record must route the case before drafting",
            )

        existing = self._narratives.list_narratives(case_id)
        if existing:
            latest = existing[-1]
            if (
                latest.record_id == current.record_id
                and latest.record_version == current.version
                and latest.model_profile == profile
                and not self._was_rejected(latest.narrative_id)
            ):
                verification = self._narratives.get_verification_for(
                    latest.narrative_id
                )
                if verification is None:
                    verification = self.verify_narrative(
                        case_id, latest.narrative_id
                    )
                return latest, verification

        alert = self._alert_payload(case_id)
        subject = self._subject_basis(case_id, current, alert)
        if subject is None:
            raise self._refuse(
                case_id,
                actor,
                "subject_identification_missing",
                "the record lacks a subject identification basis: "
                "no subject name with a date of birth or a recorded "
                "identifier stands in the case's evidence (alert "
                "payload or a corroborated screening hit), and a "
                "SAR narrative is not drafted about an unidentified "
                "subject",
            )
        if not self._statable_totals(current):
            raise self._refuse(
                case_id,
                actor,
                "flagged_amounts_not_statable",
                "no typology finding in the investigation record "
                "carries a flagged total (one of "
                + ", ".join(TOTAL_FIGURE_KEYS)
                + "), so the narrative cannot state the flagged "
                "amounts from findings — drafting is refused rather "
                "than letting the narrative total transactions itself",
            )

        composer = get_composer(profile)
        sections = self._compose_sections(
            case, current, alert, subject, composer
        )
        narrative = SarNarrative(
            case_id=case_id,
            version=(existing[-1].version + 1) if existing else 1,
            record_id=current.record_id,
            record_version=current.version,
            disposition_id=routing.disposition_id,
            model_profile=composer.profile_name,
            drafted_by=actor,
            supersedes_narrative_id=(
                existing[-1].narrative_id if existing else None
            ),
            sections=sections,
        )
        item = self._evidence.add_item(
            case_id=case_id,
            kind="sar_narrative",
            content=narrative.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"sar-narrative:{narrative.narrative_id}",
            captured_by=actor,
        )
        final = narrative.model_copy(update={"evidence_seq": item.seq})
        self._narratives.add_narrative(final)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="sar_narrative_drafted",
                detail={
                    "narrative_id": final.narrative_id,
                    "version": str(final.version),
                    "record_id": current.record_id,
                    "record_version": str(current.version),
                    "disposition_id": routing.disposition_id,
                    "model_profile": composer.profile_name,
                    "evidence_seq": str(item.seq),
                },
            )
        )
        logger.info(
            "SAR narrative drafted for case %s: %s (version %d, "
            "profile %s)",
            case_id,
            final.narrative_id,
            final.version,
            composer.profile_name,
        )
        verification = self.verify_narrative(case_id, final.narrative_id)
        return final, verification

    def _routing_disposition(self, case_id: str) -> DispositionRecord | None:
        """The disposition that routed the case to SAR drafting:
        the case's latest disposition, if it is an escalate_sar.
        A later disposition of any other outcome supersedes the
        routing — the case would not be standing in sar_pending on
        this service's account, and drafting refuses to guess."""
        records = self._dispositions.list_dispositions(case_id)
        if not records:
            return None
        latest = records[-1]
        if latest.outcome is not DispositionOutcome.ESCALATE_SAR:
            return None
        return latest

    def _alert_payload(self, case_id: str) -> Alert | None:
        for item in self._store.list_evidence(case_id):
            if item.kind == "alert_payload":
                content = self._evidence.read_item_content(case_id, item.seq)
                return Alert.model_validate_json(content.decode("utf-8"))
        return None

    def _alert_evidence_seq(self, case_id: str) -> int | None:
        for item in self._store.list_evidence(case_id):
            if item.kind == "alert_payload":
                return item.seq
        return None

    def _subject_basis(
        self,
        case_id: str,
        record: InvestigationRecord,
        alert: Alert | None,
    ) -> dict | None:
        """The subject identification basis: a subject name plus a
        disambiguator (date of birth or a recorded identifier),
        read from the alert payload's raw facts or from a
        corroborated screening hit in the record. None when the
        evidence identifies nobody — drafting then refuses."""
        name: str | None = None
        dob: str | None = None
        identifiers: list[str] = []
        if alert is not None:
            raw = alert.raw or {}
            if isinstance(raw.get("customer_name"), str):
                name = raw["customer_name"]
            if isinstance(raw.get("customer_dob"), str):
                dob = raw["customer_dob"]
            raw_ids = raw.get("customer_identifiers")
            if isinstance(raw_ids, list):
                identifiers = [str(i) for i in raw_ids if str(i)]
        if name is None or (dob is None and not identifiers):
            # Fall back to a corroborated screening hit: a resolved
            # hit element naming the subject, with strength beyond a
            # bare name match.
            for finding in record.findings:
                if finding.origin != "screening":
                    continue
                for citation in finding.citations:
                    try:
                        element = self._resolver.resolve(citation, case_id)
                    except CitationResolutionError:
                        continue
                    if not isinstance(element, dict):
                        continue
                    hit_name = element.get("subject_name")
                    corroborated = (
                        element.get("strength") == "strong"
                        or element.get("status") == "confirmed"
                    )
                    if isinstance(hit_name, str) and corroborated:
                        # The hit's corroboration (identifier/DOB
                        # match at screening) is itself the
                        # disambiguator; the entry's facts are not
                        # the subject's and are never restated as such.
                        name = name or hit_name
                        break
                if name is not None:
                    break
            if name is not None and dob is None and not identifiers:
                # The corroborated hit is itself the identification
                # basis (identifier/DOB corroboration at screening).
                return {
                    "name": name,
                    "dob": None,
                    "identifiers": [],
                    "from_hit": True,
                }
            return None
        return {
            "name": name,
            "dob": dob,
            "identifiers": identifiers,
            "from_hit": False,
        }

    def _statable_totals(
        self, record: InvestigationRecord
    ) -> dict[str, str]:
        """finding_id -> its flagged total, for every typology
        finding carrying one. Empty = the amounts cannot be stated
        from findings."""
        totals: dict[str, str] = {}
        for finding in record.findings:
            if finding.origin != "typology":
                continue
            for key in TOTAL_FIGURE_KEYS:
                if key in finding.figures:
                    totals[finding.finding_id] = finding.figures[key]
                    break
        return totals

    # -- composition ----------------------------------------------------

    def _cited_tokens(
        self, case_id: str, finding: InvestigationFinding
    ) -> set[Decimal]:
        tokens: set[Decimal] = set()
        for citation in finding.citations:
            try:
                resolved = self._resolver.resolve(citation, case_id)
            except CitationResolutionError:
                continue
            tokens |= tokens_of(resolved)
        return tokens

    def _restate(
        self,
        composer: NarrativeComposer,
        case_id: str,
        finding: InvestigationFinding,
    ) -> NarrativeStatement:
        """A statement restating one finding verbatim, composed
        through the model port: the port's figure gate re-checks
        the text against the finding's cited records before it may
        stand in the narrative."""
        allowed = self._cited_tokens(case_id, finding) | set().union(
            *(numeric_tokens(v) for v in finding.figures.values()), set()
        )
        template = finding.statement.replace("{", "{{").replace("}", "}}")
        text = composer.compose(
            StatementDraft(template=template, values={}, allowed=allowed)
        )
        return NarrativeStatement(
            statement_id="",  # assigned at section assembly
            text=text,
            citations=list(finding.citations),
            finding_ids=[finding.finding_id],
            figures=dict(finding.figures),
        )

    def _templated(
        self,
        composer: NarrativeComposer,
        *,
        template: str,
        values: dict[str, str],
        citations: list[Citation],
        case_id: str,
        finding_ids: list[str] | None = None,
        figures: dict[str, str] | None = None,
    ) -> NarrativeStatement:
        allowed: set[Decimal] = set()
        for citation in citations:
            try:
                resolved = self._resolver.resolve(citation, case_id)
            except CitationResolutionError:
                continue
            allowed |= tokens_of(resolved)
        for value in list(values.values()) + list((figures or {}).values()):
            allowed |= numeric_tokens(value)
        text = composer.compose(
            StatementDraft(template=template, values=values, allowed=allowed)
        )
        return NarrativeStatement(
            statement_id="",
            text=text,
            citations=list(citations),
            finding_ids=list(finding_ids or []),
            values=dict(values),
            figures=dict(figures or {}),
        )

    def _section(
        self, key: str, statements: list[NarrativeStatement]
    ) -> NarrativeSection:
        for index, statement in enumerate(statements, start=1):
            statement.statement_id = f"{key}-{index}"
        return NarrativeSection(
            key=key, title=_SECTION_TITLES[key], statements=statements
        )

    def _compose_sections(
        self,
        case: Case,
        record: InvestigationRecord,
        alert: Alert | None,
        subject: dict,
        composer: NarrativeComposer,
    ) -> list[NarrativeSection]:
        case_id = case.case_id
        sections: list[NarrativeSection] = []

        # -- subject identification --------------------------------
        subject_statements: list[NarrativeStatement] = []
        alert_seq = self._alert_evidence_seq(case_id)
        if alert is not None and alert_seq is not None and not subject["from_hit"]:
            subject_statements.append(
                self._templated(
                    composer,
                    template=(
                        "The subject of this report is {subject_name} "
                        "(customer {customer_id})."
                    ),
                    values={
                        "subject_name": subject["name"],
                        "customer_id": case.customer_id,
                    },
                    citations=[
                        Citation(
                            evidence_seq=alert_seq,
                            element="field:raw.customer_name",
                        ),
                        Citation(
                            evidence_seq=alert_seq,
                            element="field:customer_id",
                        ),
                    ],
                    case_id=case_id,
                )
            )
            if subject["dob"]:
                subject_statements.append(
                    self._templated(
                        composer,
                        template=(
                            "The subject's date of birth recorded on "
                            "the alert is {dob}."
                        ),
                        values={"dob": subject["dob"]},
                        citations=[
                            Citation(
                                evidence_seq=alert_seq,
                                element="field:raw.customer_dob",
                            )
                        ],
                        case_id=case_id,
                    )
                )
            for identifier in subject["identifiers"]:
                subject_statements.append(
                    self._templated(
                        composer,
                        template=(
                            "The subject's recorded identifiers "
                            "include {identifier}."
                        ),
                        values={"identifier": identifier},
                        citations=[
                            Citation(
                                evidence_seq=alert_seq,
                                element="field:raw.customer_identifiers",
                            )
                        ],
                        case_id=case_id,
                    )
                )
        for finding in record.findings:
            if finding.origin == "profile":
                subject_statements.append(
                    self._restate(composer, case_id, finding)
                )
        if subject["from_hit"]:
            for finding in record.findings:
                if finding.origin == "screening":
                    subject_statements.append(
                        self._restate(composer, case_id, finding)
                    )
        sections.append(
            self._section("subject_identification", subject_statements)
        )

        # -- activity summary ---------------------------------------
        activity: list[NarrativeStatement] = []
        if record.evidence_seq is not None:
            activity.append(
                self._templated(
                    composer,
                    template=(
                        "The investigation's working hypothesis is "
                        "{label}: {statement}"
                    ),
                    values={
                        "label": record.hypothesis.label,
                        "statement": record.hypothesis.statement,
                    },
                    citations=[
                        Citation(
                            evidence_seq=record.evidence_seq,
                            element="field:hypothesis",
                        )
                    ],
                    case_id=case_id,
                )
            )
        placed: set[str] = set()
        for direction in ("supports", "against"):
            for finding in record.findings:
                if finding.direction == direction:
                    activity.append(self._restate(composer, case_id, finding))
                    placed.add(finding.finding_id)
        for finding in record.findings:
            if (
                finding.origin == "screening"
                and finding.finding_id not in placed
            ):
                activity.append(self._restate(composer, case_id, finding))
                placed.add(finding.finding_id)
        sections.append(self._section("activity_summary", activity))

        # -- chronology ----------------------------------------------
        chronology: list[NarrativeStatement] = []
        for finding in record.findings:
            if finding.origin == "alert":
                chronology.append(self._restate(composer, case_id, finding))
        typology_findings = [
            f for f in record.findings if f.origin == "typology"
        ]
        for finding in sorted(
            typology_findings,
            key=lambda f: (self._window_start(case_id, f), f.key),
        ):
            chronology.append(self._restate(composer, case_id, finding))
        sections.append(self._section("chronology", chronology))

        # -- amounts and instruments ---------------------------------
        amounts: list[NarrativeStatement] = []
        cited_transactions: list[tuple[Citation, dict]] = []
        for finding in typology_findings:
            element = self._finding_element(case_id, finding)
            total_key = next(
                (k for k in TOTAL_FIGURE_KEYS if k in finding.figures),
                None,
            )
            if element is not None and total_key is not None:
                values = {
                    "typology_id": str(
                        element.get("typology_id") or finding.kind
                    ),
                    "pack_id": str(element.get("rule_pack_id", "")),
                    "pack_version": str(element.get("rule_pack_version", "")),
                    "amount": finding.figures[total_key],
                }
                # The figure's label is template vocabulary chosen by
                # code from the figure key — it names which computed
                # figure the sentence reports; the figure itself is
                # carried (and verified) as the statement's figure.
                figure_label = total_key.replace("_", " ")
                template = (
                    "The {typology_id} finding, computed under rule "
                    "pack {pack_id} version {pack_version}, reports "
                    f"a {figure_label} of {{amount}}"
                )
                count_key = next(
                    (k for k in COUNT_FIGURE_KEYS if k in finding.figures),
                    None,
                )
                if count_key is not None:
                    values["count"] = finding.figures[count_key]
                    template += " over {count} transactions"
                template += "."
                amounts.append(
                    self._templated(
                        composer,
                        template=template,
                        values=values,
                        citations=list(finding.citations),
                        case_id=case_id,
                        finding_ids=[finding.finding_id],
                        figures={total_key: finding.figures[total_key]},
                    )
                )
            for citation in finding.citations:
                try:
                    resolved = self._resolver.resolve(citation, case_id)
                except CitationResolutionError:
                    continue
                if isinstance(resolved, dict) and "transaction_id" in resolved:
                    cited_transactions.append((citation, resolved))
        channels = sorted(
            {str(t.get("channel")) for _, t in cited_transactions if t.get("channel")}
        )
        for channel in channels:
            channel_citations = [
                c for c, t in cited_transactions if t.get("channel") == channel
            ]
            amounts.append(
                self._templated(
                    composer,
                    template=(
                        "The flagged activity includes transactions "
                        "over the {channel} channel."
                    ),
                    values={"channel": channel},
                    citations=channel_citations,
                    case_id=case_id,
                )
            )
        cash_citations = [
            c for c, t in cited_transactions if t.get("cash") is True
        ]
        if cash_citations:
            amounts.append(
                self._templated(
                    composer,
                    template=(
                        "The flagged activity includes physical-currency "
                        "(cash) transactions."
                    ),
                    values={"instrument": "cash"},
                    citations=cash_citations,
                    case_id=case_id,
                )
            )
        sections.append(
            self._section("amounts_and_instruments", amounts)
        )

        # -- branch and office facts (only where present) ------------
        branch_citations = [
            c for c, t in cited_transactions if t.get("channel") == "branch"
        ]
        if branch_citations:
            sections.append(
                self._section(
                    "branch_office_facts",
                    [
                        self._templated(
                            composer,
                            template=(
                                "Part of the flagged activity was "
                                "conducted at a branch: the cited "
                                "transactions include branch-channel "
                                "transactions."
                            ),
                            values={"channel": "branch"},
                            citations=branch_citations,
                            case_id=case_id,
                        )
                    ],
                )
            )

        # -- what remains unknown --------------------------------------
        unknown: list[NarrativeStatement] = []
        if record.evidence_seq is not None:
            record_citation = Citation(
                evidence_seq=record.evidence_seq,
                element="field:open_questions",
            )
            if record.open_questions:
                for question in record.open_questions:
                    unknown.append(
                        self._templated(
                            composer,
                            template=(
                                "Open question: {question} The "
                                "evidence that would resolve it — "
                                "{evidence_needed} — is not on the "
                                "case file."
                            ),
                            values={
                                "question": question.question,
                                "evidence_needed": question.evidence_needed,
                            },
                            citations=[record_citation],
                            case_id=case_id,
                        )
                    )
            else:
                unknown.append(
                    self._templated(
                        composer,
                        template=(
                            "The investigation record records no "
                            "open questions."
                        ),
                        values={},
                        citations=[record_citation],
                        case_id=case_id,
                    )
                )
        sections.append(self._section("what_remains_unknown", unknown))
        return sections

    def _finding_element(
        self, case_id: str, finding: InvestigationFinding
    ) -> dict | None:
        """The typology finding element a record finding cites, if
        any — the code-computed finding behind the restatement,
        carrying the rule pack identity and figures."""
        for citation in finding.citations:
            if not citation.element.startswith("finding:"):
                continue
            try:
                resolved = self._resolver.resolve(citation, case_id)
            except CitationResolutionError:
                continue
            if isinstance(resolved, dict):
                return resolved
        return None

    def _window_start(
        self, case_id: str, finding: InvestigationFinding
    ) -> str:
        element = self._finding_element(case_id, finding)
        if element is not None and element.get("window_start"):
            return str(element["window_start"])
        return "9999-12-31"

    # -- verification -----------------------------------------------------

    def check_narrative(
        self, narrative: SarNarrative
    ) -> NarrativeVerification:
        """The citation verifier, as a pure check: verdicts over the
        given narrative against the record it cites. Stores nothing
        — :meth:`verify_narrative` is the storing entry point."""
        record = self._records.get_investigation_record(narrative.record_id)
        verdicts: list[StatementVerdict] = []
        narrative_problems: list[str] = []
        if record is None:
            narrative_problems.append(
                f"the cited investigation record {narrative.record_id} "
                "does not exist; no statement can be verified against it"
            )
            for section in narrative.sections:
                for statement in section.statements:
                    verdicts.append(
                        StatementVerdict(
                            statement_id=statement.statement_id,
                            section_key=section.key,
                            verified=False,
                            problems=["cited record does not exist"],
                        )
                    )
            return NarrativeVerification(
                narrative_id=narrative.narrative_id,
                case_id=narrative.case_id,
                verifier=VERIFIER_IDENTITY,
                all_verified=False,
                statement_verdicts=verdicts,
                narrative_problems=narrative_problems,
            )

        finding_ids = {f.finding_id for f in record.findings}
        for section in narrative.sections:
            for statement in section.statements:
                problems = self._verify_statement(
                    narrative, record, finding_ids, statement
                )
                verdicts.append(
                    StatementVerdict(
                        statement_id=statement.statement_id,
                        section_key=section.key,
                        verified=not problems,
                        problems=problems,
                    )
                )
        narrative_problems.extend(
            self._verify_completeness(narrative, record)
        )
        all_verified = all(v.verified for v in verdicts) and not narrative_problems
        return NarrativeVerification(
            narrative_id=narrative.narrative_id,
            case_id=narrative.case_id,
            verifier=VERIFIER_IDENTITY,
            all_verified=all_verified,
            statement_verdicts=verdicts,
            narrative_problems=narrative_problems,
        )

    def _verify_statement(
        self,
        narrative: SarNarrative,
        record: InvestigationRecord,
        finding_ids: set[str],
        statement: NarrativeStatement,
    ) -> list[str]:
        problems: list[str] = []
        if not statement.citations:
            problems.append(
                "statement carries no citations; a factual statement "
                "that cites nothing cannot be verified"
            )
            return problems
        resolved_elements: list[object] = []
        for citation in statement.citations:
            try:
                resolved_elements.append(
                    self._resolver.resolve(citation, narrative.case_id)
                )
            except CitationResolutionError as exc:
                problems.append(f"citation does not resolve: {exc}")
        cited_tokens: set[Decimal] = set()
        for element in resolved_elements:
            cited_tokens |= tokens_of(element)
        for finding_id in statement.finding_ids:
            if finding_id not in finding_ids:
                problems.append(
                    f"statement is bound to finding {finding_id}, "
                    "which is not in the cited investigation record"
                )
        for name, value in statement.figures.items():
            if not numeric_tokens(value) <= cited_tokens:
                problems.append(
                    f"figure {name}={value!r} does not appear in "
                    "the cited records"
                )
        figure_tokens = set().union(
            *(numeric_tokens(v) for v in statement.figures.values()), set()
        )
        stray = ungrounded_figures(
            statement.text, cited_tokens | figure_tokens
        )
        if stray:
            problems.append(
                "statement carries figure(s) not grounded in its "
                f"citations or figures: {', '.join(stray)}"
            )
        blob = json.dumps(resolved_elements, sort_keys=True, default=str)
        for name, value in statement.values.items():
            if not value:
                problems.append(f"value {name} is empty")
                continue
            if value in blob:
                continue
            tokens = numeric_tokens(value)
            if tokens and tokens <= cited_tokens and not any(
                ch.isalpha() for ch in value
            ):
                continue
            problems.append(
                f"value {name}={value!r} does not appear in the "
                "cited records; the claim does not map to a cited "
                "evidence element"
            )
        return problems

    def _verify_completeness(
        self, narrative: SarNarrative, record: InvestigationRecord
    ) -> list[str]:
        problems: list[str] = []
        sections = {s.key: s for s in narrative.sections}
        for key in REQUIRED_SECTIONS:
            section = sections.get(key)
            if section is None or not section.statements:
                problems.append(
                    f"required section {key!r} is missing or empty"
                )
        subject = sections.get("subject_identification")
        if subject is not None and subject.statements and not any(
            "subject_name" in s.values or s.finding_ids
            for s in subject.statements
        ):
            problems.append(
                "the subject identification section names no subject "
                "from the cited evidence"
            )
        totals = self._statable_totals(record)
        amounts = sections.get("amounts_and_instruments")
        stated = False
        if amounts is not None:
            record_totals = {Decimal(v) for v in totals.values()}
            for statement in amounts.statements:
                for value in statement.figures.values():
                    tokens = numeric_tokens(value)
                    if tokens and tokens <= record_totals:
                        stated = True
        if totals and not stated:
            problems.append(
                "the amounts section states none of the flagged "
                "totals the record's findings carry"
            )
        unknown = sections.get("what_remains_unknown")
        if record.open_questions:
            carried = set()
            if unknown is not None:
                for statement in unknown.statements:
                    if "evidence_needed" in statement.values:
                        carried.add(statement.values["evidence_needed"])
                    for question in record.open_questions:
                        if question.evidence_needed in statement.text:
                            carried.add(question.evidence_needed)
            for question in record.open_questions:
                if question.evidence_needed not in carried:
                    problems.append(
                        "open question naming "
                        f"{question.evidence_needed!r} is not "
                        "carried in the 'what remains unknown' "
                        "section; a narrative that hides what is "
                        "not known cannot verify"
                    )
        return problems

    def verify_narrative(
        self, case_id: str, narrative_id: str | None = None
    ) -> NarrativeVerification:
        """Run the verifier over a stored narrative and record the
        run (append-only store row + hash-chained evidence item)."""
        self._require_case(case_id)
        ensure_case_mutable(self._seals, case_id)
        if narrative_id is None:
            existing = self._narratives.list_narratives(case_id)
            if not existing:
                raise NarrativeNotFoundError(
                    f"case {case_id} holds no SAR narrative"
                )
            narrative = existing[-1]
        else:
            narrative = self._narratives.get_narrative(narrative_id)
            if narrative is None or narrative.case_id != case_id:
                raise NarrativeNotFoundError(
                    f"narrative {narrative_id} not found on case {case_id}"
                )
        verification = self.check_narrative(narrative)
        item = self._evidence.add_item(
            case_id=case_id,
            kind="sar_narrative_verification",
            content=verification.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"sar-verification:{verification.verification_id}",
            captured_by=VERIFIER_IDENTITY,
        )
        final = verification.model_copy(update={"evidence_seq": item.seq})
        self._narratives.add_verification(final)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=VERIFIER_IDENTITY,
                event=(
                    "sar_narrative_verified"
                    if final.all_verified
                    else "sar_narrative_verification_failed"
                ),
                detail={
                    "narrative_id": narrative.narrative_id,
                    "verification_id": final.verification_id,
                    "statements_failed": str(
                        sum(
                            1
                            for v in final.statement_verdicts
                            if not v.verified
                        )
                    ),
                    "narrative_problems": str(len(final.narrative_problems)),
                },
            )
        )
        logger.info(
            "SAR narrative %s verification for case %s: %s",
            narrative.narrative_id,
            case_id,
            "all verified" if final.all_verified else "FAILED",
        )
        return final

    # -- views ------------------------------------------------------------

    def current_narrative(self, case_id: str) -> SarNarrative | None:
        self._require_case(case_id)
        narratives = self._narratives.list_narratives(case_id)
        return narratives[-1] if narratives else None

    def narrative_history(self, case_id: str) -> list[SarNarrative]:
        self._require_case(case_id)
        return self._narratives.list_narratives(case_id)

    def latest_verification(
        self, narrative_id: str
    ) -> NarrativeVerification | None:
        return self._narratives.get_verification_for(narrative_id)

    def _was_rejected(self, narrative_id: str) -> bool:
        """True when the dual-control gate (R7) rejected this
        narrative version. A rejected version is decided: it keeps
        its verification history, but it is no longer the standing
        draft — re-drafting composes the next version."""
        if self._approvals is None:
            return False
        approval = self._approvals.get_approval_for(narrative_id)
        return (
            approval is not None
            and approval.outcome is ApprovalOutcome.REJECTED
        )

    def status_of(self, narrative: SarNarrative) -> str:
        """A narrative's derived standing: superseded (a newer
        draft exists), stale (the record it cites has been
        superseded — it cannot proceed to approval as-is), approved
        or rejected (the dual-control gate's decision, R7 — a
        rejected narrative is back at drafting standing), verified
        (the latest verification run passes every statement), or
        draft."""
        siblings = self._narratives.list_narratives(narrative.case_id)
        if any(n.version > narrative.version for n in siblings):
            return "superseded"
        history = self._records.list_investigation_records(narrative.case_id)
        current = history[-1] if history else None
        if current is None or (
            current.record_id != narrative.record_id
            or current.version != narrative.record_version
        ):
            return "stale"
        if self._approvals is not None:
            approval = self._approvals.get_approval_for(
                narrative.narrative_id
            )
            if approval is not None:
                return approval.outcome.value
        verification = self._narratives.get_verification_for(
            narrative.narrative_id
        )
        if verification is not None and verification.all_verified:
            return "verified"
        return "draft"

    def view(self, narrative: SarNarrative) -> dict:
        """The narrative as JSON, with its derived standing and its
        latest verification attached."""
        body = narrative.model_dump(mode="json")
        body["status"] = self.status_of(narrative)
        verification = self._narratives.get_verification_for(
            narrative.narrative_id
        )
        body["verification"] = (
            verification.model_dump(mode="json")
            if verification is not None
            else None
        )
        return body
