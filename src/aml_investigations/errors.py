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
