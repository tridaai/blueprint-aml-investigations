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
