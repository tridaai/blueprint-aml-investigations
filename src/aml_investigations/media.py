"""Adverse media: the media port + similarity scoring in code (R12).

Screening (R2) matches a case's subjects against list snapshots —
names a vendor asserts are adverse. Adverse-media work is the
other half of the same discipline: a news feed returns *candidate*
articles for a name, and someone must decide which candidates are
actually about the customer, and what they actually say. In this
blueprint that decision is made the way every other decision here
is made — deterministically, in code, with the working shown:

- **The port.** ``AdverseMediaSource`` is a recall-oriented name
  search, exactly as a licensed news database behaves: it returns
  candidates, namesakes and loose matches included. A production
  deployment wires the licensed database behind the port; the
  blueprint ships a labelled reference corpus — stand-in data,
  never presented as real reporting.
- **Ingestion discipline.** An article enters a case only as an
  evidence item (kind ``adverse_media``) through the evidence
  funnel, and its text passes through R10's quarantine scanner
  with field precision, like every other untrusted text: an
  instruction planted in an article body is quarantined and
  fenced, never obeyed, never rendered unfenced.
- **Scoring in code.** Relevance is a versioned scorer over
  structure, not a model over prose: name-match strength (R2's
  deterministic matcher, reused), disambiguation signals read
  against the customer profile (date of birth, stated age,
  geography, occupation, associated entities, identifiers) —
  each signal's outcome and contribution recorded — and an
  adverse-category classification from a versioned keyword
  taxonomy, matched terms recorded. The output is a
  :class:`MediaAssessment`: a band (strong / possible /
  namesake_cleared / irrelevant) with its basis in words.
- **R2's namesake discipline, carried over.** A strong name
  match contradicted by the subject's date of birth is a
  different person: the band is ``namesake_cleared`` and the
  contradiction is named on the record — never silently dropped,
  never allowed to stand as a hit. An identifier match prevails
  over a date-of-birth contradiction, with the conflict recorded
  for an analyst, exactly as at screening.
- **Findings only.** An assessment is an artefact the
  investigation record may cite, with its band stated. It
  dispositions nothing, blocks nothing, and moves no case state:
  media never decides — the analyst does, at the gate.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .errors import (
    CaseNotFoundError,
    CustomerNotFoundError,
    MediaNotFoundError,
    MediaRefusedError,
)
from .evidence import EvidenceService, ensure_case_mutable
from .logging_config import get_logger
from .models import (
    Alert,
    AuditEvent,
    MediaArticle,
    MediaAssessment,
    MediaBand,
    MediaCategoryMatch,
    MediaNameMatch,
    MediaSignal,
)
from .ports import (
    AdverseMediaSource,
    CaseStore,
    MediaStore,
    SealStore,
    TypologyStore,
)
from .quarantine import iter_text_fields
from .screening import match_name, normalise_identifier, normalise_name

logger = get_logger(__name__)

#: The scorer's version, recorded on every assessment. A changed
#: scorer is a new version; assessments name the scorer that
#: produced them, so an old case's bands stay reproducible.
SCORER_VERSION = "2026.10.1"

#: The adverse-category taxonomy's version, likewise recorded.
TAXONOMY_VERSION = "2026.10.1"

ARTICLE_KIND = "adverse_media"
ASSESSMENT_KIND = "media_assessment"


# ---------------------------------------------------------------------------
# The adverse-category taxonomy (versioned data)
# ---------------------------------------------------------------------------

#: Category -> the terms that evidence it. Matching is literal,
#: case-insensitive, word-bounded, over headline + body: the
#: taxonomy is data an examiner can read, and every match records
#: the exact terms that fired. ``other`` carries the generic
#: adverse vocabulary — an article can be adverse without fitting
#: a named category, and the record says so honestly.
TAXONOMY: dict[str, tuple[str, ...]] = {
    "fraud": (
        "fraud",
        "wire fraud",
        "bank fraud",
        "securities fraud",
        "embezzlement",
        "embezzled",
        "ponzi scheme",
        "forgery",
        "forged documents",
        "identity theft",
        "misappropriation",
        "misappropriated",
    ),
    "corruption": (
        "corruption",
        "bribery",
        "bribed",
        "kickback",
        "kickbacks",
        "graft",
        "illicit payments",
    ),
    "sanctions_evasion": (
        "sanctions evasion",
        "evading sanctions",
        "sanctions violations",
        "sanctioned",
        "embargo",
        "export controls",
        "front company",
        "shell company",
    ),
    "organised_crime": (
        "organised crime",
        "organized crime",
        "cartel",
        "smuggling",
        "smuggled",
        "trafficking",
        "drug trafficking",
        "money mule",
        "criminal syndicate",
        "racketeering",
    ),
    "regulatory_action": (
        "regulatory action",
        "enforcement action",
        "consent order",
        "cease and desist",
        "regulatory fine",
        "regulator",
    ),
    "other": (
        "arrested",
        "charged",
        "indicted",
        "convicted",
        "pleaded guilty",
        "sentenced",
        "prison",
        "money laundering",
        "laundered",
        "investigation",
        "investigators",
        "probe",
        "raid",
        "seized",
        "fugitive",
    ),
}


def classify_categories(article: MediaArticle) -> list[MediaCategoryMatch]:
    """The taxonomy's verdict on one article: every category with
    at least one matched term, in taxonomy order, each carrying
    the exact terms that matched."""
    text = f"{article.headline}\n{article.body_text}".lower()
    found: list[MediaCategoryMatch] = []
    for category, terms in TAXONOMY.items():
        matched = sorted(
            {
                term
                for term in terms
                if re.search(r"\b" + re.escape(term) + r"\b", text)
            }
        )
        if matched:
            found.append(
                MediaCategoryMatch(category=category, matched_terms=matched)
            )
    return found


# ---------------------------------------------------------------------------
# Feeds (the source side of the port)
# ---------------------------------------------------------------------------


def _recall_match(query: str, article: MediaArticle) -> bool:
    """The loose recall a vendor search performs: an article is a
    candidate when any of its named subjects shares at least one
    normalised name token with the query. Precision is the
    scorer's job — the feed's job is not to miss."""
    query_tokens = set(normalise_name(query))
    if not query_tokens:
        return False
    return any(
        query_tokens & set(normalise_name(named))
        for named in article.subjects_named
    )


class ListMediaFeed:
    """AdverseMediaSource over an in-memory corpus (tests, embedding)."""

    def __init__(self, articles: list[MediaArticle]) -> None:
        self._articles = list(articles)

    def search(self, subject_name: str) -> list[MediaArticle]:
        hits = [a for a in self._articles if _recall_match(subject_name, a)]
        return sorted(hits, key=lambda a: a.article_id)


class ReferenceMediaFeed:
    """AdverseMediaSource over a JSON file of article records —
    the blueprint's labelled stand-in corpus."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._articles: list[MediaArticle] = []
        if self._path.exists():
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            for entry in payload.get("articles", []):
                self._articles.append(MediaArticle.model_validate(entry))

    def search(self, subject_name: str) -> list[MediaArticle]:
        hits = [a for a in self._articles if _recall_match(subject_name, a)]
        return sorted(hits, key=lambda a: a.article_id)


# ---------------------------------------------------------------------------
# Subject facts: what the bank's own records say about the subject
# ---------------------------------------------------------------------------


@dataclass
class SubjectFacts:
    """The subject facts an assessment is scored against, read
    from stored artefacts only: the assembled profile view (R11)
    when one is stored, and this case's alert payload — merged,
    because a view assembled before this case opened cannot carry
    this case's facts. ``profile_id``/``profile_version`` pin the
    view used, when one was used."""

    primary_name: str = ""
    names: list[str] = field(default_factory=list)  # primary first
    aliases: list[str] = field(default_factory=list)
    dobs: list[date] = field(default_factory=list)
    identifiers: list[str] = field(default_factory=list)
    geographies: list[str] = field(default_factory=list)
    occupations: list[str] = field(default_factory=list)
    associated_entities: list[str] = field(default_factory=list)
    profile_id: str | None = None
    profile_version: int | None = None
    facts_basis: str = "alert_payload"

    @property
    def surfaces(self) -> list[tuple[str, bool]]:
        """(name, is_alias) surfaces for matching, primary first."""
        out = [(n, False) for n in self.names]
        out += [(a, True) for a in self.aliases]
        return out


def _parse_date(value: object) -> date | None:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _string_values(raw: dict, keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value)
        elif isinstance(value, list):
            values.extend(str(v) for v in value if str(v).strip())
    return values


_GEOGRAPHY_KEYS = (
    "customer_city",
    "customer_state",
    "customer_country",
    "customer_jurisdiction",
    "customer_location",
    "customer_region",
)
_OCCUPATION_KEYS = (
    "customer_occupation",
    "customer_industry",
    "customer_profession",
)


# ---------------------------------------------------------------------------
# The scorer (pure, deterministic — no model, no clock)
# ---------------------------------------------------------------------------

_NAME_STRENGTH_BY_RULE = {
    "exact_name": "exact",
    "name_token_set": "token_set",
    "name_token_subset": "fuzzy",
    "name_token_overlap": "fuzzy",
}


def match_article_name(
    article: MediaArticle, facts: SubjectFacts
) -> MediaNameMatch:
    """Best name match over every (subject surface) x (article
    named subject) pair, under the screening matcher's rules."""
    best: tuple[float, str, str, str] | None = None
    for surface, _is_alias in facts.surfaces:
        surface_tokens = normalise_name(surface)
        for named in article.subjects_named:
            result = match_name(surface_tokens, normalise_name(named))
            if result is None:
                continue
            score, rule = result
            if best is None or score > best[0]:
                best = (score, rule, surface, named)
    if best is None:
        return MediaNameMatch(
            matched=False, strength="none", score=0.0, rule=""
        )
    score, rule, surface, named = best
    return MediaNameMatch(
        matched=True,
        strength=_NAME_STRENGTH_BY_RULE.get(rule, "fuzzy"),
        score=score,
        rule=rule,
        subject_surface=surface,
        article_surface=named,
    )


def _token_overlap(a_values: list[str], b_values: list[str]) -> str | None:
    """The first shared place/occupation token between two value
    lists, or None. Tokens shorter than three characters do not
    count ('in', 'us' are not geography)."""
    b_tokens: set[str] = set()
    for value in b_values:
        b_tokens |= {t for t in normalise_name(value) if len(t) >= 3}
    for value in a_values:
        for token in normalise_name(value):
            if len(token) >= 3 and token in b_tokens:
                return token
    return None


def _dob_signal(article: MediaArticle, facts: SubjectFacts) -> MediaSignal:
    if article.subject_dob is None:
        return MediaSignal(
            signal="dob",
            outcome="absent",
            contribution=0.0,
            detail="the article states no date of birth for the subject",
        )
    if not facts.dobs:
        return MediaSignal(
            signal="dob",
            outcome="absent",
            contribution=0.0,
            detail=(
                f"the article states a date of birth "
                f"({article.subject_dob.isoformat()}); the profile "
                "records none to test it against"
            ),
        )
    if article.subject_dob in facts.dobs:
        return MediaSignal(
            signal="dob",
            outcome="supports",
            contribution=0.25,
            detail=(
                f"article date of birth {article.subject_dob.isoformat()} "
                "matches the profile date of birth"
            ),
        )
    recorded = ", ".join(sorted(d.isoformat() for d in facts.dobs))
    return MediaSignal(
        signal="dob",
        outcome="contradicts",
        contribution=-0.25,
        detail=(
            f"article date of birth {article.subject_dob.isoformat()} "
            f"contradicts the profile date of birth on record ({recorded})"
        ),
    )


def _age_signal(article: MediaArticle, facts: SubjectFacts) -> MediaSignal:
    if article.subject_age is None or article.subject_dob is not None:
        return MediaSignal(
            signal="age",
            outcome="absent",
            contribution=0.0,
            detail=(
                "no separate age is scored (the article states a "
                "date of birth, or no age at all)"
            ),
        )
    if not facts.dobs:
        return MediaSignal(
            signal="age",
            outcome="absent",
            contribution=0.0,
            detail=(
                f"the article states an age ({article.subject_age}); "
                "the profile records no date of birth to test it against"
            ),
        )
    pub_year = article.published_on.year
    implied = {pub_year - article.subject_age, pub_year - article.subject_age - 1}
    closest = min(
        abs(dob.year - year) for dob in facts.dobs for year in implied
    )
    if closest <= 1:
        return MediaSignal(
            signal="age",
            outcome="supports",
            contribution=0.2,
            detail=(
                f"article age {article.subject_age} at publication "
                f"({article.published_on.isoformat()}) implies a birth "
                "year consistent with the profile date of birth"
            ),
        )
    if closest >= 3:
        return MediaSignal(
            signal="age",
            outcome="contradicts",
            contribution=-0.2,
            detail=(
                f"article age {article.subject_age} at publication "
                f"({article.published_on.isoformat()}) implies a birth "
                "year inconsistent with the profile date of birth by "
                f"{closest} years"
            ),
        )
    return MediaSignal(
        signal="age",
        outcome="absent",
        contribution=0.0,
        detail=(
            f"article age {article.subject_age} is too coarse to "
            "confirm or contradict the profile date of birth"
        ),
    )


def _identifier_signal(
    article: MediaArticle, facts: SubjectFacts
) -> MediaSignal:
    if not article.identifiers:
        return MediaSignal(
            signal="identifier",
            outcome="absent",
            contribution=0.0,
            detail="the article states no identifier for the subject",
        )
    subject_ids = {normalise_identifier(i) for i in facts.identifiers}
    matched = [
        i
        for i in article.identifiers
        if normalise_identifier(i) in subject_ids
    ]
    if matched:
        return MediaSignal(
            signal="identifier",
            outcome="supports",
            contribution=0.3,
            detail=(
                "article identifier(s) "
                + ", ".join(sorted(matched))
                + " match identifier(s) on the customer profile"
            ),
        )
    return MediaSignal(
        signal="identifier",
        outcome="absent",
        contribution=0.0,
        detail=(
            "the article states identifier(s) that do not match the "
            "profile; articles rarely print full identifiers, so a "
            "non-match is recorded, not counted against"
        ),
    )


def _geography_signal(
    article: MediaArticle, facts: SubjectFacts
) -> MediaSignal:
    article_places = list(article.locations)
    if article.jurisdiction:
        article_places.append(article.jurisdiction)
    if not article_places:
        return MediaSignal(
            signal="geography",
            outcome="absent",
            contribution=0.0,
            detail="the article places the subject nowhere",
        )
    if not facts.geographies:
        return MediaSignal(
            signal="geography",
            outcome="absent",
            contribution=0.0,
            detail=(
                "the article places the subject in "
                + ", ".join(article_places)
                + "; the profile records no geography to test it against"
            ),
        )
    shared = _token_overlap(article_places, facts.geographies)
    if shared is not None:
        return MediaSignal(
            signal="geography",
            outcome="supports",
            contribution=0.1,
            detail=(
                "article geography ("
                + ", ".join(article_places)
                + ") shares '"
                + shared
                + "' with the profile geography ("
                + ", ".join(facts.geographies)
                + ")"
            ),
        )
    return MediaSignal(
        signal="geography",
        outcome="contradicts",
        contribution=-0.1,
        detail=(
            "article geography ("
            + ", ".join(article_places)
            + ") does not overlap the profile geography ("
            + ", ".join(facts.geographies)
            + ") — a soft signal only: people move, and geography "
            "alone never clears a match"
        ),
    )


def _occupation_signal(
    article: MediaArticle, facts: SubjectFacts
) -> MediaSignal:
    if not article.occupations:
        return MediaSignal(
            signal="occupation",
            outcome="absent",
            contribution=0.0,
            detail="the article attributes no occupation to the subject",
        )
    if not facts.occupations:
        return MediaSignal(
            signal="occupation",
            outcome="absent",
            contribution=0.0,
            detail=(
                "the article attributes occupation(s) "
                + ", ".join(article.occupations)
                + "; the profile records none to test them against"
            ),
        )
    shared = _token_overlap(article.occupations, facts.occupations)
    if shared is not None:
        return MediaSignal(
            signal="occupation",
            outcome="supports",
            contribution=0.1,
            detail=(
                "article occupation ("
                + ", ".join(article.occupations)
                + ") shares '"
                + shared
                + "' with the profile occupation ("
                + ", ".join(facts.occupations)
                + ")"
            ),
        )
    return MediaSignal(
        signal="occupation",
        outcome="contradicts",
        contribution=-0.05,
        detail=(
            "article occupation ("
            + ", ".join(article.occupations)
            + ") does not overlap the profile occupation ("
            + ", ".join(facts.occupations)
            + ")"
        ),
    )


def _entities_signal(
    article: MediaArticle, facts: SubjectFacts
) -> MediaSignal:
    if not article.associated_entities:
        return MediaSignal(
            signal="associated_entities",
            outcome="absent",
            contribution=0.0,
            detail="the article associates no other entities with the subject",
        )
    known = {" ".join(normalise_name(e)) for e in facts.associated_entities}
    matched = [
        e
        for e in article.associated_entities
        if " ".join(normalise_name(e)) in known
    ]
    if matched:
        return MediaSignal(
            signal="associated_entities",
            outcome="supports",
            contribution=round(0.15 * min(len(matched), 2), 4),
            detail=(
                "article-associated entities "
                + ", ".join(sorted(matched))
                + " stand on the customer's own record (counterparties)"
            ),
        )
    return MediaSignal(
        signal="associated_entities",
        outcome="absent",
        contribution=0.0,
        detail=(
            "the article associates other entities with the subject; "
            "none stand on the customer's record — recorded, not "
            "counted against (an article names many entities)"
        ),
    )


_HARD_SIGNALS = ("dob", "age")


def assess_article(
    article: MediaArticle,
    facts: SubjectFacts,
    *,
    case_id: str,
    customer_id: str,
    as_of: date,
    actor: str,
) -> MediaAssessment:
    """Score one article against the subject facts. Pure: same
    article, same facts, same versions — same assessment (ids and
    timestamps aside). The band decision is ordered rules, stated
    on the record in ``band_basis``:

    1. no name match -> ``irrelevant``
    2. a hard contradiction (date of birth, or stated age) with
       no identifier match -> ``namesake_cleared``, the
       contradiction named (R2's discipline)
    3. an identifier match -> ``strong`` (an identifier prevails
       over a contradicting date of birth, the conflict recorded
       for an analyst — R2's rule again)
    4. an exact / token-set name match corroborated by at least
       one supporting signal -> ``strong``
    5. anything else that matched a name -> ``possible``
    """
    name_match = match_article_name(article, facts)
    categories = classify_categories(article)
    age_days = (as_of - article.published_on).days
    if not name_match.matched:
        return MediaAssessment(
            case_id=case_id,
            customer_id=customer_id,
            article_id=article.article_id,
            subject_name=facts.primary_name,
            name_match=name_match,
            signals=[],
            categories=categories,
            score=0.0,
            band=MediaBand.IRRELEVANT,
            band_basis=(
                "no name match: none of the article's named subjects "
                "matches the subject's recorded names or aliases under "
                "the deterministic matcher — the article is not about "
                "this subject on any evidence the scorer can see"
            ),
            published_on=article.published_on,
            article_age_days=age_days,
            as_of=as_of,
            scorer_version=SCORER_VERSION,
            taxonomy_version=TAXONOMY_VERSION,
            profile_id=facts.profile_id,
            profile_version=facts.profile_version,
            facts_basis=facts.facts_basis,
            assessed_by=actor,
        )
    signals = [
        _identifier_signal(article, facts),
        _dob_signal(article, facts),
        _age_signal(article, facts),
        _geography_signal(article, facts),
        _occupation_signal(article, facts),
        _entities_signal(article, facts),
    ]
    by_signal = {s.signal: s for s in signals}
    score = round(
        min(
            1.0,
            max(
                0.0,
                0.6 * name_match.score
                + sum(s.contribution for s in signals),
            ),
        ),
        4,
    )
    hard = [
        s
        for s in signals
        if s.signal in _HARD_SIGNALS and s.outcome == "contradicts"
    ]
    identifier_match = by_signal["identifier"].outcome == "supports"
    supporting = [s for s in signals if s.outcome == "supports"]
    if hard and not identifier_match:
        band = MediaBand.NAMESAKE_CLEARED
        basis = (
            f"name match ({name_match.strength}, score "
            f"{name_match.score}) is contradicted: {hard[0].detail} — "
            "the article names a different person (a namesake); "
            "cleared with the contradiction recorded, never dropped "
            "and never left standing as a hit"
        )
    elif identifier_match:
        band = MediaBand.STRONG
        basis = (
            "identifier corroboration: "
            + by_signal["identifier"].detail
            + " — an identifier match prevails"
        )
        if hard:
            basis += (
                "; a hard contradiction is also recorded ("
                + hard[0].detail
                + ") and stands for analyst review, as at screening"
            )
    elif name_match.strength in ("exact", "token_set") and supporting:
        band = MediaBand.STRONG
        basis = (
            f"{name_match.strength} name match corroborated by "
            + ", ".join(s.signal for s in supporting)
        )
    else:
        band = MediaBand.POSSIBLE
        reasons: list[str] = []
        if name_match.strength == "fuzzy":
            reasons.append(
                f"the name match is fuzzy only ({name_match.rule}, "
                f"score {name_match.score})"
            )
        if not supporting:
            reasons.append("no disambiguation signal corroborates it")
        soft = [
            s
            for s in signals
            if s.outcome == "contradicts" and s.signal not in _HARD_SIGNALS
        ]
        for signal in soft:
            reasons.append(f"{signal.signal} does not corroborate: {signal.detail}")
        basis = "possible match: " + "; ".join(reasons)
    return MediaAssessment(
        case_id=case_id,
        customer_id=customer_id,
        article_id=article.article_id,
        subject_name=facts.primary_name,
        name_match=name_match,
        signals=signals,
        categories=categories,
        score=score,
        band=band,
        band_basis=basis,
        published_on=article.published_on,
        article_age_days=age_days,
        as_of=as_of,
        scorer_version=SCORER_VERSION,
        taxonomy_version=TAXONOMY_VERSION,
        profile_id=facts.profile_id,
        profile_version=facts.profile_version,
        facts_basis=facts.facts_basis,
        assessed_by=actor,
    )


# ---------------------------------------------------------------------------
# The service: search, ingest, assess, record
# ---------------------------------------------------------------------------


class AdverseMediaService:
    """Searches the media port for a case's subject, ingests the
    candidate articles as evidence, scores them in code, and
    records the assessments.

    The service writes exactly two things: evidence items (the
    articles, the assessments) and assessment rows behind the
    MediaStore port. It holds no workflow reference and touches
    no case state — media is a findings path, and the case's
    standing after a search is exactly what it was before it.
    """

    def __init__(
        self,
        store: CaseStore,
        media_store: MediaStore,
        evidence: EvidenceService,
        source: AdverseMediaSource,
        *,
        seal_store: SealStore | None = None,
        quarantine=None,
        profile_service=None,
        typology_store: TypologyStore | None = None,
    ) -> None:
        self._store = store
        self._media = media_store
        self._evidence = evidence
        self._source = source
        self._seals = seal_store
        # R10 (Law 7): when wired, each ingested article's text
        # fields are scanned with field precision as the article
        # lands and matches are quarantined on the case chain —
        # the same treatment every untrusted text in this system
        # gets. The article itself is never rejected or edited.
        self._quarantine = quarantine
        # R11: when wired, subject facts are read from the
        # customer's assembled profile view when one is stored
        # (pinned on the assessment), merged with this case's own
        # alert payload facts.
        self._profiles = profile_service
        self._typologies = typology_store

    # -- subject facts --------------------------------------------

    def _alert_for(self, case_id: str) -> Alert | None:
        for item in self._store.list_evidence(case_id):
            if item.kind == "alert_payload":
                content = self._evidence.read_item_content(case_id, item.seq)
                return Alert.model_validate_json(content.decode("utf-8"))
        return None

    def derive_facts(self, case_id: str) -> SubjectFacts:
        """The subject facts for a case's customer, from stored
        artefacts only. Raises nothing — an empty ``primary_name``
        is the caller's refusal signal."""
        case = self._store.get_case(case_id)
        facts = SubjectFacts()
        if case is None:
            return facts
        view = None
        if self._profiles is not None:
            view = self._profiles.stored_view(case.customer_id)
        if view is not None:
            facts.profile_id = view.profile_id
            facts.profile_version = view.version
            facts.facts_basis = "profile_view"
            for fact in view.identity_facts:
                if fact.field == "name":
                    if "(recorded alias)" in fact.source_ref:
                        if fact.value not in facts.aliases:
                            facts.aliases.append(fact.value)
                    elif fact.value not in facts.names:
                        facts.names.append(fact.value)
                elif fact.field == "dob":
                    parsed = _parse_date(fact.value)
                    if parsed is not None and parsed not in facts.dobs:
                        facts.dobs.append(parsed)
                elif fact.field == "identifier":
                    if fact.value not in facts.identifiers:
                        facts.identifiers.append(fact.value)
            for counterparty in self._view_counterparties(case.customer_id):
                if counterparty not in facts.associated_entities:
                    facts.associated_entities.append(counterparty)
        alert = self._alert_for(case_id)
        if alert is not None:
            raw = alert.raw or {}
            name = raw.get("customer_name")
            if isinstance(name, str) and name and name not in facts.names:
                facts.names.insert(0, name)
            for alias in raw.get("customer_aliases", []) or []:
                if str(alias) not in facts.aliases:
                    facts.aliases.append(str(alias))
            dob = _parse_date(raw.get("customer_dob"))
            if dob is not None and dob not in facts.dobs:
                facts.dobs.append(dob)
            for identifier in raw.get("customer_identifiers", []) or []:
                if str(identifier) not in facts.identifiers:
                    facts.identifiers.append(str(identifier))
            for value in _string_values(raw, _GEOGRAPHY_KEYS):
                if value not in facts.geographies:
                    facts.geographies.append(value)
            for value in _string_values(raw, _OCCUPATION_KEYS):
                if value not in facts.occupations:
                    facts.occupations.append(value)
            for counterparty in raw.get("counterparties", []) or []:
                if isinstance(counterparty, dict) and counterparty.get("name"):
                    cname = str(counterparty["name"])
                    if cname not in facts.associated_entities:
                        facts.associated_entities.append(cname)
        if self._typologies is not None:
            for other in self._store.list_cases():
                if other.customer_id != case.customer_id:
                    continue
                for txn in self._typologies.list_transactions(other.case_id):
                    if (
                        txn.counterparty
                        and txn.counterparty not in facts.associated_entities
                    ):
                        facts.associated_entities.append(txn.counterparty)
        if facts.names:
            facts.primary_name = facts.names[0]
        return facts

    def _view_counterparties(self, customer_id: str) -> list[str]:
        if self._profiles is None:
            return []
        try:
            views = self._profiles.counterparties_for_customer(customer_id)
        except CustomerNotFoundError:
            return []
        return [v.name_raw for v in views]

    # -- ingestion --------------------------------------------------

    def _article_seq(self, case_id: str, article_id: str) -> int | None:
        for item in self._store.list_evidence(case_id):
            if item.kind != ARTICLE_KIND:
                continue
            content = self._evidence.read_item_content(case_id, item.seq)
            try:
                article = MediaArticle.model_validate_json(
                    content.decode("utf-8")
                )
            except Exception:
                continue
            if article.article_id == article_id:
                return item.seq
        return None

    def _ingest_article(
        self, case_id: str, article: MediaArticle, *, actor: str
    ) -> int:
        existing = self._article_seq(case_id, article.article_id)
        if existing is not None:
            return existing
        item = self._evidence.add_item(
            case_id,
            kind=ARTICLE_KIND,
            content=article.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"adverse-media-feed:{article.article_id}",
            captured_by=actor,
        )
        # R10 (Law 7): the article's text is untrusted — a news
        # corpus is written by people outside the bank, and an
        # instruction planted in an article body is quarantined
        # as a case event exactly as one in a transaction memo
        # is. Field labels are the article's own field paths, the
        # same labels citations address.
        if self._quarantine is not None:
            payload = article.model_dump(mode="json")
            fields: dict[str, str] = {}
            for key, value in payload.items():
                fields.update(iter_text_fields(value, key))
            self._quarantine.record_scan(
                case_id,
                source_kind=ARTICLE_KIND,
                evidence_seq=item.seq,
                fields=fields,
                actor=actor,
            )
        return item.seq

    # -- the search ---------------------------------------------------

    def search_case_media(
        self, case_id: str, *, actor: str, as_of: date
    ) -> list[MediaAssessment]:
        """Search the media port for the case's subject, ingest
        every candidate as evidence, score each in code, and
        record the assessments. Idempotent per article: a
        re-search returns the recorded assessments and ingests
        nothing twice — a re-assessment under a changed scorer
        is a deliberate act, not a side effect of searching."""
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        ensure_case_mutable(self._seals, case_id)
        facts = self.derive_facts(case_id)
        if not facts.primary_name:
            self._store.append_audit(
                AuditEvent(
                    case_id=case_id,
                    actor=actor,
                    event="media_search_refused",
                    detail={"reason": "no_subject_facts"},
                )
            )
            raise MediaRefusedError(
                "no_subject_facts",
                f"case {case_id}: no name for customer "
                f"{case.customer_id} can be derived from any stored "
                "artefact (no profile view, no alert payload name) — "
                "there is nothing to search the media feed for",
            )
        candidates: dict[str, MediaArticle] = {}
        for surface, _is_alias in facts.surfaces:
            for article in self._source.search(surface):
                candidates.setdefault(article.article_id, article)
        existing = {
            a.article_id: a for a in self._media.list_assessments(case_id)
        }
        results: list[MediaAssessment] = []
        for article_id in sorted(candidates):
            article = candidates[article_id]
            if article_id in existing:
                results.append(existing[article_id])
                continue
            article_seq = self._ingest_article(case_id, article, actor=actor)
            assessment = assess_article(
                article,
                facts,
                case_id=case_id,
                customer_id=case.customer_id,
                as_of=as_of,
                actor=actor,
            )
            assessment = assessment.model_copy(
                update={"article_evidence_seq": article_seq}
            )
            item = self._evidence.add_item(
                case_id,
                kind=ASSESSMENT_KIND,
                content=assessment.model_dump_json(indent=2).encode("utf-8"),
                source_ref=f"media-assessment:{assessment.assessment_id}",
                captured_by=actor,
            )
            assessment = assessment.model_copy(
                update={"evidence_seq": item.seq}
            )
            self._media.add_assessment(assessment)
            self._store.append_audit(
                AuditEvent(
                    case_id=case_id,
                    actor=actor,
                    event="media_assessed",
                    detail={
                        "assessment_id": assessment.assessment_id,
                        "article_id": article.article_id,
                        "band": assessment.band.value,
                        "score": assessment.score,
                        "scorer_version": assessment.scorer_version,
                        "taxonomy_version": assessment.taxonomy_version,
                        "article_evidence_seq": article_seq,
                    },
                )
            )
            results.append(assessment)
        logger.info(
            "media search",
            extra={
                "case_id": case_id,
                "event": "media_search",
                "candidates": len(candidates),
                "assessed": len(results),
            },
        )
        return sorted(results, key=lambda a: a.article_id)

    # -- reads ---------------------------------------------------------

    def list_assessments(self, case_id: str) -> list[MediaAssessment]:
        if self._store.get_case(case_id) is None:
            raise CaseNotFoundError(case_id)
        return self._media.list_assessments(case_id)

    def get_assessment(
        self, case_id: str, assessment_id: str
    ) -> MediaAssessment:
        if self._store.get_case(case_id) is None:
            raise CaseNotFoundError(case_id)
        assessment = self._media.get_assessment(assessment_id)
        if assessment is None or assessment.case_id != case_id:
            raise MediaNotFoundError(
                f"case {case_id} holds no media assessment {assessment_id}"
            )
        return assessment
