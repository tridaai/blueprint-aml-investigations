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


# ---------------------------------------------------------------------------
# Per-element grounding (R19): the red team's strengthening.
#
# Until R19 the verifiers grounded a statement's figures in the
# UNION of everything it cited: a token found anywhere in any cited
# element grounded the claim, wherever the statement put it. That
# let a drafting path transpose facts *between* cited elements —
# one transaction's amount wearing another's date, one
# counterparty's name riding on another's transaction, a component
# amount restated as the total — and still verify, because every
# token existed somewhere in the union. The checks below bind each
# claim to its own element:
#
# - a stated figure grounds only in an element that carries it
#   under the figure's own key (a ``total_amount`` must be found
#   as a ``total_amount`` — in a computed finding's figures, a
#   field citation's tail, a record's field — never as some other
#   element's ``amount``);
# - a stated value must appear inside ONE cited element, never
#   assembled across several;
# - when a statement cites two or more transactions, its figures,
#   dates and values may not be drawn exclusively from different
#   ones — that is a transposition, even when every token is real;
# - a statement using total language ("totalling", "in total",
#   "aggregate") must present a figure its citations actually
#   carry as a total.
#
# Legitimate composition already satisfies all four: composers
# read each figure from the element that carries it, under its
# key, and totals always come from computed findings (Law 4 —
# the drafting path never sums transactions itself).
# ---------------------------------------------------------------------------

_ISO_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_LONG_DATE_RE = re.compile(
    r"\b(?:January|February|March|April|May|June|July|August|"
    r"September|October|November|December)\s+\d{1,2},\s+\d{4}\b"
)

_TOTAL_TRIGGER_RE = re.compile(
    r"\b(total|totalling|totaling|totals|aggregate|aggregated|combined)\b",
    re.IGNORECASE,
)


def dates_in(text: str) -> list[str]:
    """Every date a statement text states, in the two shapes the
    drafters write: ISO (``2026-03-04``) and long form
    (``March 4, 2026``). Order of appearance, duplicates kept out."""
    found: list[tuple[int, str]] = []
    for pattern in (_ISO_DATE_RE, _LONG_DATE_RE):
        for match in pattern.finditer(text):
            found.append((match.start(), match.group(0)))
    return [value for _pos, value in sorted(found)]


@dataclass
class CitedElement:
    """One resolved citation, in the form the grounding checks
    consume: the citation's element ref, the resolved element
    (fenced, where the caller fences untrusted text), its JSON
    text, and its groundable (span-masked) numeric tokens."""

    ref: str
    resolved: object
    blob: str
    tokens: set[Decimal] = field(default_factory=set)


def _decimal_or_none(value: object) -> Decimal | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float, Decimal)):
        return Decimal(str(value))
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text:
            return None
        try:
            return Decimal(text)
        except Exception:
            return None
    return None


def _value_matches(carried: object, stated: object) -> bool:
    """A carried element value against a stated figure/value:
    numeric equality when both sides parse as numbers (``28800``
    the int, ``"28800"`` the string and ``"28800.00"`` are one
    figure), else an exact text comparison."""
    left = _decimal_or_none(carried)
    right = _decimal_or_none(stated)
    if left is not None and right is not None:
        return left == right
    return str(carried).strip().casefold() == str(stated).strip().casefold()


def _key_values(node: object, key: str) -> list[object]:
    """Every value carried under ``key`` anywhere inside a
    resolved element — its top level, a nested ``figures`` dict,
    a list member. A figure grounds under its key wherever in
    its own element that key honestly sits."""
    found: list[object] = []
    if isinstance(node, dict):
        if key in node:
            found.append(node[key])
        for child in node.values():
            found.extend(_key_values(child, key))
    elif isinstance(node, list):
        for child in node:
            found.extend(_key_values(child, key))
    return found


def _figure_grounding_refs(
    key: str, value: str, elements: list[CitedElement]
) -> set[str]:
    """The refs of the elements that carry ``value`` under
    ``key`` — a figure's grounding places, for the checks that
    care *where* a figure grounded."""
    refs: set[str] = set()
    for element in elements:
        if element.ref.startswith("field:"):
            tail = element.ref[len("field:"):].rsplit(".", 1)[-1]
            if tail == key and _value_matches(element.resolved, value):
                refs.add(element.ref)
        for carried in _key_values(element.resolved, key):
            if _value_matches(carried, value):
                refs.add(element.ref)
        if isinstance(element.resolved, (str, int, float)) and (
            element.ref.rsplit(":", 1)[-1] == key
            and _value_matches(element.resolved, value)
        ):
            refs.add(element.ref)
    return refs


def _figure_grounded(
    key: str, value: str, elements: list[CitedElement]
) -> bool:
    return bool(_figure_grounding_refs(key, value, elements))


def _total_grounded(number: str, elements: list[CitedElement]) -> bool:
    """Is ``number`` carried as a total by any cited element —
    under any key that names a total (``total_amount``,
    ``in_total`` …), or by a field citation to such a field?"""
    target = _decimal_or_none(number)
    if target is None:
        return False
    for element in elements:
        if element.ref.startswith("field:"):
            tail = element.ref[len("field:"):].rsplit(".", 1)[-1]
            if "total" in tail.casefold() and _value_matches(
                element.resolved, number
            ):
                return True
        stack = [element.resolved]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, child in node.items():
                    if "total" in key.casefold():
                        carried = _decimal_or_none(child)
                        if carried is not None and carried == target:
                            return True
                    stack.append(child)
            elif isinstance(node, list):
                stack.extend(node)
    return False


def _transposition_problems(
    text: str,
    values: dict[str, str],
    elements: list[CitedElement],
) -> list[str]:
    txn = [e for e in elements if e.ref.startswith("transaction:")]
    if len({e.ref for e in txn}) < 2:
        return []
    specifics: list[tuple[str, object]] = []
    for token in numeric_tokens(text):
        specifics.append(
            (f"figure {format(token, 'f')}", lambda e, t=token: t in e.tokens)
        )
    for day in dates_in(text):
        specifics.append((f"date {day}", lambda e, d=day: d in e.blob))
    for value in values.values():
        if value:
            specifics.append(
                (f"value {value!r}", lambda e, v=value: v in e.blob)
            )
    if not specifics:
        return []
    # Escape: one cited element — typically the computed finding
    # the statement restates — carries every specific itself, so
    # nothing was drawn from separate transactions at all.
    if any(
        all(fn(element) for _label, fn in specifics) for element in elements
    ):
        return []
    sources: dict[str, str] = {}
    for label, fn in specifics:
        refs = {e.ref for e in txn if fn(e)}
        if len(refs) == 1:
            sources[label] = next(iter(refs))
    if len(set(sources.values())) < 2:
        return []
    drawn = ", ".join(
        f"{label} from {ref}" for label, ref in sorted(sources.items())
    )
    return [
        "statement transposes facts between cited transactions: "
        f"{drawn}; a figure, date or value must come from the "
        "transaction it describes, not from another transaction "
        "the statement also cites"
    ]


def _total_problems(
    text: str,
    figures: dict[str, str],
    elements: list[CitedElement],
) -> list[str]:
    match = _TOTAL_TRIGGER_RE.search(text)
    if match is None:
        return []
    numbers = _NUMBER_RE.findall(text[match.start():])
    if not numbers:
        return []
    if any(_total_grounded(number, elements) for number in numbers):
        return []
    # Excuse: the "total" is a named, non-transaction figure the
    # statement itself carries — a profile's expected monthly
    # amount "totalling 30000" is a field the statement cites
    # under its own key, not a sum restated from components. The
    # excuse never applies to a figure grounded only in a
    # transaction element: that is exactly the subset restatement
    # this check exists to refuse.
    for key, value in figures.items():
        if not any(
            _decimal_or_none(number) == _decimal_or_none(value)
            for number in numbers
        ):
            continue
        refs = _figure_grounding_refs(key, value, elements)
        if any(not ref.startswith("transaction:") for ref in refs):
            return []
    return [
        f"statement uses total language ({match.group(0)!r}) but "
        "none of the figures that follow it ("
        + ", ".join(numbers)
        + ") is carried as a total by any cited element; a total "
        "traces to a computed finding, never to a component amount"
    ]


def grounding_problems(
    *,
    text: str,
    figures: dict[str, str],
    values: dict[str, str],
    elements: list[CitedElement],
) -> list[str]:
    """The R19 per-element grounding checks over one statement
    (or finding) and the elements it cites. Complements — never
    replaces — the callers' token checks: those ask whether a
    figure appears in the cited records at all; these ask
    whether it appears *in its own element, under its own key,
    alongside the facts it is stated with*."""
    problems: list[str] = []
    for key, value in figures.items():
        if not _figure_grounded(key, value, elements):
            problems.append(
                f"figure {key}={value!r} does not appear in the "
                "cited records under that name; a figure grounds "
                "only in an element that carries it under its "
                "own key"
            )
    if values and elements:
        combined = "\n".join(e.blob for e in elements)
        for name, value in values.items():
            if not value or value not in combined:
                continue  # the caller's union check names it
            if any(value in e.blob for e in elements):
                continue
            tokens = numeric_tokens(value)
            if (
                tokens
                and not any(ch.isalpha() for ch in value)
                and any(tokens <= e.tokens for e in elements)
            ):
                continue
            problems.append(
                f"value {name}={value!r} does not appear in any "
                "single cited element; a value may not be "
                "assembled across elements"
            )
    problems.extend(_transposition_problems(text, values, elements))
    problems.extend(_total_problems(text, figures, elements))
    return problems


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
