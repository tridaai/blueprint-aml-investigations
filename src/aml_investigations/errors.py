"""Domain errors for the AML investigations blueprint.

Every refusal the system makes is a typed error, so the API layer can
map it to a precise HTTP status and the audit log can record *why* a
transition or write was refused. Nothing fails silently.
"""


class AmlError(Exception):
    """Base class for all domain errors."""


class CaseNotFoundError(AmlError):
    """The named case does not exist in the case store."""


class AlertNotFoundError(AmlError):
    """The named alert does not exist in the alert source."""


class IllegalTransitionError(AmlError):
    """The requested case-state transition is not in the lawful table.

    This is Law 1 enforced mechanically: the state machine has no edge
    from an investigated state to a closed state except through an
    analyst disposition recorded at the gate.
    """

    def __init__(self, current: str, target: str, reason: str = "") -> None:
        self.current = current
        self.target = target
        self.reason = reason
        message = f"illegal transition: {current} -> {target}"
        if reason:
            message += f" ({reason})"
        super().__init__(message)


class DispositionRequiredError(IllegalTransitionError):
    """A closing transition was attempted without an analyst disposition."""

    def __init__(self, current: str, target: str) -> None:
        super().__init__(
            current,
            target,
            reason="a named analyst disposition with a reason code is required",
        )


class EvidenceChainError(AmlError):
    """Hash-chain verification failed for a case's evidence store."""


class EvidenceNotFoundError(AmlError):
    """The named evidence item does not exist on the case."""


class ScreeningError(AmlError):
    """Base class for screening (Law 3) refusals."""


class SnapshotImmutableError(ScreeningError):
    """A snapshot with this list kind + version already exists with
    different content. Snapshots never mutate: a corrected list must
    be ingested as a new version."""


class SnapshotNotFoundError(ScreeningError):
    """A pin named a list kind + version that has not been ingested."""


class ScreeningPinRequiredError(ScreeningError):
    """A screening run was requested without an explicit pinned
    snapshot set. Screening against 'whatever is current' is refused:
    the pin is what makes a result reproducible and auditable."""


class HitNotFoundError(ScreeningError):
    """The named screening hit does not exist."""


class TypologyError(AmlError):
    """Base class for typology-engine (Law 4) refusals."""


class RulePackImmutableError(TypologyError):
    """A rule pack with this id + version is already registered with
    different thresholds. Rule packs never mutate: a changed
    threshold is a new version, so findings keep the rules that
    produced them."""


class RulePackNotFoundError(TypologyError):
    """A typology run named a rule pack id + version that has not
    been registered."""


class NoTransactionsError(TypologyError):
    """A typology run was requested for a case with no ingested
    transactions. The engine reads only stored, evidence-backed
    transaction records — it never computes over ad-hoc input."""


class TransactionMismatchError(TypologyError):
    """A transaction batch named an account other than the case's
    account, or mixed accounts inside one batch."""


class TransactionConflictError(TypologyError):
    """A delivered batch re-uses a transaction id the case already
    holds with different content, outside an identical whole-batch
    re-delivery. A transaction id names one record forever:
    corrections arrive as new transactions with new ids, and a
    feed contradicting itself about an id it already delivered is
    refused before anything is written — never merged, never
    half-ingested, and never silently honoured on a retry."""


class InvestigationError(AmlError):
    """Base class for investigation-graph (R4) refusals."""


class InvestigationStateError(InvestigationError):
    """An investigation run was requested for a case that is not in
    the ``investigating`` state. The graph works a case that is
    being investigated; it does not reach into opened, assembling,
    or decided cases."""


class CitationResolutionError(InvestigationError):
    """A citation does not resolve: the evidence item does not
    exist, or the named element is not inside it. A finding whose
    citations do not resolve is refused at record time — this error
    is that refusal, and nothing is persisted when it is raised."""


class ComposerRefusalError(InvestigationError):
    """The narrative composer refused a statement: it would carry a
    figure that is not in the cited records or the finding's own
    code-computed figures. The composer assembles text from records;
    it does not invent figures."""


class ModelProfileNotConfiguredError(InvestigationError):
    """A live model profile was selected but is not configured in
    this deployment (no key). The profile interface exists; until a
    key is wired, selecting it is a loud refusal, never a silent
    fall-back to the offline composer."""


class InvestigationRefusedError(InvestigationError):
    """The assembled investigation record failed the record-time
    verification gate (citation resolution, figure provenance, or
    hypothesis discipline). Nothing is persisted."""


class DispositionError(AmlError):
    """Base class for disposition-gate (R5) refusals."""


class DispositionRefusedError(DispositionError):
    """A disposition or confirmation was refused at the analyst gate.

    Every refusal carries a named ``reason`` — the gate never says
    just "no": anonymous_or_system_actor, unknown_role,
    rationale_codes_required, unknown_rationale_code,
    case_not_awaiting_analyst, no_investigation_record,
    record_citation_not_current, unresolved_sanctions_hit,
    missing_review_period, missing_evidence_required,
    unknown_evidence_type, no_pending_confirmation,
    confirmer_role_not_l2, self_confirmation. The refusal is written
    to the case's audit log before it is raised.
    """

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(f"disposition refused [{reason}]: {message}")


class SarNarrativeError(AmlError):
    """Base class for SAR narrative (R6) refusals."""


class SarNarrativeRefusedError(SarNarrativeError):
    """SAR narrative drafting or verification was refused.

    Every refusal carries a named ``reason``: case_not_sar_pending,
    no_investigation_record, sar_disposition_missing,
    sar_disposition_not_current, subject_identification_missing,
    flagged_amounts_not_statable, narrative_record_missing. The
    refusal is written to the case's audit log before it is raised
    (drafting refusals; verification verdicts are records, not
    refusals — an unverifiable narrative is stored as a failed
    verification, never raised as one).
    """

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(f"SAR narrative refused [{reason}]: {message}")


class NarrativeNotFoundError(SarNarrativeError):
    """The named SAR narrative does not exist (on the named case)."""


class ApprovalError(AmlError):
    """Base class for dual-control approval (R7) refusals."""


class ApprovalRefusedError(ApprovalError):
    """A SAR narrative approval or rejection was refused at the
    second-person gate (Law 2's dual control).

    Every refusal carries a named ``reason``:
    anonymous_or_system_actor, unknown_role, case_not_sar_pending,
    no_narrative, already_decided, narrative_not_verified,
    approver_is_dispositioner, approver_is_drafter,
    rejection_codes_required, unknown_rejection_code,
    approval_reason_codes_not_applicable. The refusal is written to
    the case's audit log before it is raised.
    """

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(f"approval refused [{reason}]: {message}")


class SealingError(AmlError):
    """Base class for case sealing / legal hold / export (R7) refusals."""


class SealingRefusedError(SealingError):
    """A seal, unseal, legal-hold, or export action was refused.

    Every refusal carries a named ``reason``:
    anonymous_or_system_actor, officer_role_required,
    already_sealed, case_not_sealed, case_not_terminal,
    evidence_chain_broken, unknown_seal_purpose,
    legal_hold_blocks_archive, unknown_unseal_reason,
    unknown_hold_reason, already_on_hold, not_on_hold,
    unknown_hold_release_reason. The refusal is written to the
    case's audit log before it is raised.
    """

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(f"sealing refused [{reason}]: {message}")


class CaseSealedError(SealingRefusedError):
    """A mutating service path was attempted on a sealed case.

    A sealed case file is read-only (Law 5): the only writes it
    accepts are the sealing service's own custody records (seal,
    unseal, legal-hold events). Raised by every guarded service —
    evidence intake, screening, typologies, investigation,
    disposition, drafting — with this one named reason, so a sealed
    case refuses identically at every door.
    """

    def __init__(self, case_id: str, seal_id: str) -> None:
        self.case_id = case_id
        self.seal_id = seal_id
        super().__init__(
            "case_sealed",
            f"case {case_id} is sealed (seal {seal_id}); a sealed "
            "case file is read-only — unseal it by a named officer "
            "with a coded reason before any further work",
        )


class SanctionsHitBlocksCloseError(IllegalTransitionError):
    """A plain close was attempted on a case with an unresolved
    sanctions hit. The case is in a must-escalate posture: the lawful
    dispositions are escalate or file_sar, until an analyst clears
    the hit with a recorded reason."""

    def __init__(self, current: str, hit_ids: list[str]) -> None:
        self.hit_ids = hit_ids
        super().__init__(
            current,
            "closed",
            reason=(
                "unresolved sanctions hit(s) "
                + ", ".join(hit_ids)
                + " — disposition must be escalate or file_sar, or an "
                "analyst must clear the hit with a reason"
            ),
        )


class ContinuingReviewError(AmlError):
    """Base class for R9 continuing-activity review failures."""


class ContinuingReviewRefusedError(ContinuingReviewError):
    """The review action was refused, with a machine-readable
    reason: no_continuing_clock, prior_record_missing,
    no_investigation_record, review_already_open,
    cycle_already_answered, actor_required,
    review_citations_unresolvable, review_stale,
    review_superseded, already_dispositioned,
    anonymous_or_system_actor, unknown_role,
    rationale_codes_required, unknown_rationale_code,
    case_not_awaiting_analyst, record_citation_not_current.
    The refusal is audited before it is raised."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class ReviewNotFoundError(ContinuingReviewError):
    """The named review does not exist on this case."""


class QuarantineError(AmlError):
    """Base class for R10 quarantine failures."""


class QuarantineRefusedError(QuarantineError):
    """A quarantine action was refused, with a machine-readable
    reason: anonymous_or_system_actor, already_reviewed. The
    refusal is audited before it is raised."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class QuarantineNotFoundError(QuarantineError):
    """The named quarantine record does not exist on this case."""


class ProfileError(AmlError):
    """Base class for R11 KYC profile assembly failures."""


class CustomerNotFoundError(ProfileError):
    """No case in the store belongs to the named customer, so
    there is nothing to assemble a profile from."""


class ProfileNotFoundError(ProfileError):
    """No profile view has been assembled (and stored) for the
    named customer yet."""


class MediaError(AmlError):
    """Base class for adverse-media (R12) failures."""


class MediaRefusedError(MediaError):
    """A media search was refused, with a machine-readable
    reason: no_subject_facts (no name for the case's customer can
    be derived from any stored artefact, so there is nothing to
    search for). The refusal is audited before it is raised."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class MediaNotFoundError(MediaError):
    """The named media assessment does not exist on the named case."""


class ModelGatewayError(AmlError):
    """Base class for model gateway (R13) failures."""


class ModelProfileConfigError(ModelGatewayError):
    """The gateway configuration itself is invalid — refused at
    load/wiring time, before any call: a duplicate profile id, a
    live profile naming no endpoint, a profile whose model has no
    price-table entry, a malformed or negative price. The gateway
    is fail-closed about its own configuration: a deployment with
    a broken profile table does not start, and a call is never
    silently rerouted to a different profile to paper over it."""


class UnknownModelProfileError(ModelGatewayError):
    """A caller named a model profile the gateway does not hold.
    Refused loudly — the gateway never substitutes another
    profile for the one that was named."""


class ModelBudgetExceededError(ModelGatewayError):
    """A live-profile call was refused: the case's priced spend
    reached the deployment's per-case budget cap.

    The refusal happens before any transport is touched, and it
    is recorded (ledger budget event + case audit + chain item)
    before it is raised. The offline profile is not capped — it
    costs nothing — and continuing a case offline after a refusal
    is a normal, recorded path; the gateway itself never switches
    profiles."""

    def __init__(
        self,
        case_id: str,
        profile_id: str,
        cap: str,
        spent: str,
    ) -> None:
        self.case_id = case_id
        self.profile_id = profile_id
        self.cap_usd = cap
        self.spent_usd = spent
        super().__init__(
            f"model budget refused: case {case_id} has spent "
            f"{spent} USD of priced model calls, reaching the "
            f"per-case cap of {cap} USD; further live-profile "
            f"calls ({profile_id}) are refused — the offline "
            "profile remains available, and no profile is ever "
            "switched silently"
        )
