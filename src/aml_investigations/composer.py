"""The model port: narrative composition behind named profiles.

Investigation findings carry narrative text, and the text is
produced here — through a port, never by the investigation graph
inline. Two rules bind every profile, enforced in code:

- A composer assembles a statement from values code computed out of
  cited records. It may not introduce a figure of its own: after
  rendering, every numeric token in the statement must appear in
  the allowed set (the cited records' tokens plus the finding's own
  code-computed figures). A statement that would carry an ungrounded
  figure is refused — :class:`ComposerRefusalError` — not edited
  into compliance.

- Profiles are named and explicit. ``offline`` (the default) is a
  deterministic stand-in composer: template assembly over the
  structured records, no model call, identical output for identical
  input. ``hosted-frontier`` is the live profile's interface,
  defined now and exercised when a deployment wires a key — until
  then, selecting it is a loud refusal
  (:class:`ModelProfileNotConfiguredError`), never a silent
  fall-back to offline.

R13 built the full gateway on this port (``gateway.py``): profiles
as governed data, real HTTP adapters for the live profiles, the
per-case budget, and the cost ledger. Where a gateway is wired —
every production wiring — services resolve their composer through
it, and the classes below serve the bare stacks (tests that build
services by hand): ``OfflineComposer`` renders identically either
way, and ``HostedFrontierComposer`` remains the loud refusal a
gateway-less stack gives for a live profile, so the two paths can
never disagree about whether a live call happened.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Protocol, runtime_checkable

from .errors import (
    ComposerRefusalError,
    InvestigationError,
    ModelProfileNotConfiguredError,
)

_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")


def numeric_tokens(text: str) -> set[Decimal]:
    """Every numeric token in a text, as Decimals.

    The same tokeniser runs over statements and over the cited
    records' JSON, so a figure is 'the same figure' on both sides of
    the comparison — '9500.00' in a record and '9500' in a statement
    are one Decimal, and a date's year/month/day are tokens on both
    sides too.
    """
    return {Decimal(m.group(0)) for m in _NUMBER_RE.finditer(text)}


def tokens_of(value: object) -> set[Decimal]:
    """Numeric tokens of an arbitrary JSON-shaped value."""
    blob = json.dumps(value, sort_keys=True, default=str)
    return numeric_tokens(blob)


def ungrounded_figures(statement: str, allowed: set[Decimal]) -> list[str]:
    """The statement's numeric tokens that are not in ``allowed``,
    rendered back as strings for error messages. Empty = grounded."""
    stray = numeric_tokens(statement) - set(allowed)
    return sorted(format(d, "f") for d in stray)


@dataclass
class StatementDraft:
    """One statement to compose: a template, the exact values code
    computed for its slots, and the allowed figure tokens (from the
    finding's cited records and its own figures)."""

    template: str
    values: dict[str, str] = field(default_factory=dict)
    allowed: set[Decimal] = field(default_factory=set)


@runtime_checkable
class NarrativeComposer(Protocol):
    """Composes one finding statement from a draft, or refuses."""

    profile_name: str

    def compose(self, draft: StatementDraft) -> str: ...


class OfflineComposer:
    """The deterministic offline profile (the default).

    Renders the draft's template with its values — values that code
    computed from cited records — and then applies the figure gate.
    Labelled a stand-in wherever it is recorded: the investigation
    record names the profile that produced its text.
    """

    profile_name = "offline"

    def compose(self, draft: StatementDraft) -> str:
        statement = draft.template.format(**draft.values)
        stray = ungrounded_figures(statement, draft.allowed)
        if stray:
            raise ComposerRefusalError(
                "statement would carry figure(s) not present in the "
                f"cited records or the finding's figures: {', '.join(stray)}"
            )
        return statement


class HostedFrontierComposer:
    """The live profile's interface for gateway-less stacks.

    The configured live path is the model gateway (R13,
    ``gateway.py``): its Anthropic adapter calls a hosted frontier
    model behind this same contract — the model receives the
    draft's values and the cited records, and its text passes the
    same figure gate before it may stand as a finding statement.
    A stack built without a gateway has no configured endpoint at
    all, so composing through this class is refused loudly rather
    than falling back.
    """

    profile_name = "hosted-frontier"

    def compose(self, draft: StatementDraft) -> str:
        raise ModelProfileNotConfiguredError(
            "model profile 'hosted-frontier' is not configured in this "
            "deployment (no API key wired); the investigation record "
            "would have to name a profile that did not produce its "
            "text, so the run is refused instead of falling back"
        )


_PROFILES: dict[str, type] = {
    OfflineComposer.profile_name: OfflineComposer,
    HostedFrontierComposer.profile_name: HostedFrontierComposer,
}

#: The profile a run uses when none is named.
DEFAULT_PROFILE = OfflineComposer.profile_name


def get_composer(profile: str) -> NarrativeComposer:
    cls = _PROFILES.get(profile)
    if cls is None:
        raise InvestigationError(
            f"unknown model profile {profile!r}; known profiles: "
            + ", ".join(sorted(_PROFILES))
        )
    return cls()


def known_profiles() -> list[str]:
    return sorted(_PROFILES)
