"""KYC profile assembly + counterparty views (R11).

An analyst opening a case should not have to re-gather what the
bank already knows. This service assembles that knowledge into a
customer **profile view**: a derived artefact built in code from
stored artefacts only — alert payloads on case chains, screening
runs and hits, account profiles, transaction records, disposition
records, approvals. Nothing in a view is hand-entered, and every
identity fact carries the stored artefact it was read from.

Assembly discipline:

- **Conflicts are shown, never merged.** ``name`` and ``dob`` are
  single-valued identity attributes: two distinct values on
  record stand side by side, flagged ``identity_conflict``, and
  no value is promoted over another. Identifiers are multi-valued
  (a passport and a licence are both facts), so every identifier
  stands as its own fact without a conflict flag.
- **The view is content-addressed and append-only.** The content
  hash covers the derived facts; rebuilding over unchanged
  inputs returns the stored view, and changed inputs append the
  next version. Freshness is computed at an ``as_of`` passed in —
  no wall-clock reads inside the derivation (the clocks' rule).
- **Counterparty money is computed in code** (Law 4): Decimal
  totals over stored transactions, with first/last seen, the
  screening state of the name, and the shared-counterparty links
  — counterparties standing on more than one customer's cases —
  computed exactly. Display names pass through R10's quarantine
  fencing; stored values are never touched by a fence.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import date
from decimal import Decimal

from .dispositions import DispositionService
from .errors import (
    CaseNotFoundError,
    CustomerNotFoundError,
    ProfileNotFoundError,
)
from .evidence import EvidenceService
from .logging_config import get_logger
from .models import (
    Alert,
    ApprovalOutcome,
    AuditEvent,
    Case,
    CaseStatus,
    CounterpartyScreening,
    CounterpartyView,
    FreshnessEntry,
    IdentityConflict,
    IdentityFact,
    ProfileAccount,
    ProfileCaseEntry,
    ProfileScreeningEntry,
    ProfileScreeningHit,
    ProfileView,
    SharedCounterparty,
)
from .ports import (
    ApprovalStore,
    CaseStore,
    ProfileStore,
    ScreeningStore,
    TypologyStore,
)

logger = get_logger(__name__)

#: The freshness policy's version. A view records the version it
#: was judged under, so a later policy revision never silently
#: re-reads an old view's stale flags.
FRESHNESS_POLICY_VERSION = "2026.10.1"

#: Per-class corroboration limits, in days, as data — the policy
#: the freshness derivation reads. Identity and account facts are
#: re-corroborated annually in a KYC cycle; screening goes stale
#: fastest because lists move; activity is the customer's own
#: transaction record, judged over a half-year window.
FRESHNESS_LIMITS_DAYS: dict[str, int] = {
    "identity": 365,
    "account": 365,
    "screening": 90,
    "activity": 180,
}

#: Fact classes in their stated order on the view.
FACT_CLASSES = ("identity", "account", "screening", "activity")


def _normalise_name(name: str) -> str:
    """The grouping key for a counterparty name: whitespace
    collapsed, case folded. Grouping is a computation over the
    stored names; the stored names themselves never change."""
    return " ".join(name.split()).casefold()


class _CounterpartyAgg:
    """Running aggregate for one (counterparty, customer) slice."""

    def __init__(self) -> None:
        self.total_in = Decimal("0")
        self.total_out = Decimal("0")
        self.count = 0
        self.first_seen = None
        self.last_seen = None
        self.currencies: set[str] = set()
        self.case_ids: set[str] = set()
        self.account_ids: set[str] = set()
        self.raw_forms: Counter = Counter()
        self.fenced_forms: dict[str, str] = {}


class ProfileService:
    """Assembles profile views and counterparty views.

    Reads every port it needs and writes exactly one thing: new
    profile-view versions behind the ProfileStore. It decides
    nothing about any case — it gathers, with provenance.
    """

    def __init__(
        self,
        store: CaseStore,
        screening_store: ScreeningStore,
        typology_store: TypologyStore,
        profile_store: ProfileStore,
        evidence: EvidenceService,
        dispositions: DispositionService | None = None,
        approval_store: ApprovalStore | None = None,
        quarantine=None,
    ) -> None:
        self._store = store
        self._screening = screening_store
        self._typologies = typology_store
        self._profiles = profile_store
        self._evidence = evidence
        self._dispositions = dispositions
        self._approvals = approval_store
        # R10 (Law 7): when wired, counterparty display names are
        # fenced from the quarantine records on each batch they
        # rode in on. Storage is never touched by a fence.
        self._quarantine = quarantine

    # -- assembly ---------------------------------------------------

    def assemble_profile(
        self, customer_id: str, *, as_of: date, actor: str
    ) -> ProfileView:
        """Assemble (or return) the customer's profile view.

        Rebuilding over unchanged inputs returns the stored view;
        changed inputs append the next version. Raises
        :class:`CustomerNotFoundError` when no case in the store
        belongs to the customer — there is nothing to assemble
        from, and an empty profile would be a fabrication.
        """
        cases = self._customer_cases(customer_id)
        if not cases:
            raise CustomerNotFoundError(
                f"no cases on record for customer {customer_id}"
            )
        facts, alias_facts = self._identity_facts(cases)
        conflicts = self._identity_conflicts(facts)
        accounts = self._accounts(cases)
        case_history = self._case_history(cases)
        screening_history = self._screening_history(cases)
        freshness = self._freshness(cases, facts, as_of)
        content = {
            "customer_id": customer_id,
            "as_of": as_of.isoformat(),
            "freshness_policy_version": FRESHNESS_POLICY_VERSION,
            "identity_facts": [
                f.model_dump(mode="json") for f in facts + alias_facts
            ],
            "identity_conflicts": [
                c.model_dump(mode="json") for c in conflicts
            ],
            "accounts": [a.model_dump(mode="json") for a in accounts],
            "case_history": [e.model_dump(mode="json") for e in case_history],
            "screening_history": [
                e.model_dump(mode="json") for e in screening_history
            ],
            "freshness": [f.model_dump(mode="json") for f in freshness],
            "source_case_ids": [c.case_id for c in cases],
        }
        blob = json.dumps(content, sort_keys=True, default=str).encode("utf-8")
        content_hash = hashlib.sha256(blob).hexdigest()
        profile_id = f"prof-{content_hash[:16]}"
        existing = self._profiles.get_profile_view(profile_id)
        if existing is not None:
            return existing
        stored = self._profiles.list_profile_views(customer_id)
        view = ProfileView(
            profile_id=profile_id,
            customer_id=customer_id,
            version=(stored[-1].version + 1) if stored else 1,
            content_hash=content_hash,
            as_of=as_of,
            freshness_policy_version=FRESHNESS_POLICY_VERSION,
            identity_facts=facts + alias_facts,
            identity_conflicts=conflicts,
            accounts=accounts,
            case_history=case_history,
            screening_history=screening_history,
            freshness=freshness,
            source_case_ids=[c.case_id for c in cases],
        )
        self._profiles.add_profile_view(view)
        self._store.append_audit(
            AuditEvent(
                actor=actor,
                event="profile_assembled",
                detail={
                    "customer_id": customer_id,
                    "profile_id": view.profile_id,
                    "version": view.version,
                    "content_hash": view.content_hash,
                    "as_of": as_of.isoformat(),
                    "conflicts": len(view.identity_conflicts),
                },
            )
        )
        logger.info(
            "profile assembled",
            extra={
                "customer_id": customer_id,
                "event": "profile_assembled",
                "profile_id": view.profile_id,
                "version": view.version,
            },
        )
        return view

    # -- stored views -------------------------------------------------

    def latest_view(self, customer_id: str) -> ProfileView:
        view = self._profiles.latest_profile_view(customer_id)
        if view is None:
            raise ProfileNotFoundError(
                f"no profile view assembled for customer {customer_id}"
            )
        return view

    def view_history(self, customer_id: str) -> list[ProfileView]:
        if not self._customer_cases(customer_id):
            raise CustomerNotFoundError(
                f"no cases on record for customer {customer_id}"
            )
        return self._profiles.list_profile_views(customer_id)

    def profile_for_case(self, case_id: str) -> ProfileView:
        """The latest stored view for a case's customer — the
        per-case read the console and the investigation use."""
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        return self.latest_view(case.customer_id)

    def stored_view(self, customer_id: str) -> ProfileView | None:
        """The latest stored view, or None — the investigation
        assembly's read, which consumes a view when one exists
        and proceeds without one when none does."""
        return self._profiles.latest_profile_view(customer_id)

    # -- assembly pieces ----------------------------------------------

    def _customer_cases(self, customer_id: str) -> list[Case]:
        cases = [
            c for c in self._store.list_cases() if c.customer_id == customer_id
        ]
        return sorted(cases, key=lambda c: (c.detected_on, c.case_id))

    def _alert_for(self, case: Case) -> tuple[Alert | None, int | None]:
        for item in self._store.list_evidence(case.case_id):
            if item.kind == "alert_payload":
                content = self._evidence.read_item_content(case.case_id, item.seq)
                return (
                    Alert.model_validate_json(content.decode("utf-8")),
                    item.seq,
                )
        return None, None

    def _identity_facts(self, cases) -> tuple[list[IdentityFact], list[IdentityFact]]:
        """Identity facts from stored artefacts, in case order.

        Sources: each case's alert payload (name, recorded
        aliases, date of birth, identifiers) and the screening
        record (the customer's name as screening recorded it,
        per hit). Alias facts are returned separately: an alias
        is a declared alternate, listed as a fact but never
        counted as a conflict with the primary name.
        """
        facts: list[IdentityFact] = []
        alias_facts: list[IdentityFact] = []
        for case in cases:
            alert, payload_seq = self._alert_for(case)
            if alert is not None:
                raw = alert.raw or {}
                ref = f"alert {alert.alert_id} raw payload"
                name = raw.get("customer_name")
                if name:
                    facts.append(
                        IdentityFact(
                            field="name",
                            value=str(name),
                            source_kind="alert_payload",
                            source_case_id=case.case_id,
                            source_ref=ref,
                            evidence_seq=payload_seq,
                        )
                    )
                for alias in raw.get("customer_aliases", []):
                    alias_facts.append(
                        IdentityFact(
                            field="name",
                            value=str(alias),
                            source_kind="alert_payload",
                            source_case_id=case.case_id,
                            source_ref=f"{ref} (recorded alias)",
                            evidence_seq=payload_seq,
                        )
                    )
                dob = raw.get("customer_dob")
                if dob:
                    facts.append(
                        IdentityFact(
                            field="dob",
                            value=str(dob),
                            source_kind="alert_payload",
                            source_case_id=case.case_id,
                            source_ref=ref,
                            evidence_seq=payload_seq,
                        )
                    )
                for identifier in raw.get("customer_identifiers", []):
                    facts.append(
                        IdentityFact(
                            field="identifier",
                            value=str(identifier),
                            source_kind="alert_payload",
                            source_case_id=case.case_id,
                            source_ref=ref,
                            evidence_seq=payload_seq,
                        )
                    )
            runs = {
                r.run_id: r for r in self._screening.list_screening_runs(case.case_id)
            }
            seen_screening_names: set[tuple[str, str]] = set()
            for hit in self._screening.list_hits(case.case_id):
                if hit.subject_role != "customer":
                    continue
                key = (hit.subject_name, hit.hit_id)
                if key in seen_screening_names:
                    continue
                seen_screening_names.add(key)
                run = runs.get(hit.run_id)
                facts.append(
                    IdentityFact(
                        field="name",
                        value=hit.subject_name,
                        source_kind="screening",
                        source_case_id=case.case_id,
                        source_ref=(
                            f"screening hit {hit.hit_id} on "
                            f"{hit.list_kind.value} {hit.snapshot_version}"
                        ),
                        evidence_seq=run.evidence_seq if run else None,
                    )
                )
        return facts, alias_facts

    @staticmethod
    def _identity_conflicts(facts: list[IdentityFact]) -> list[IdentityConflict]:
        """Distinct values of the single-valued fields (name,
        dob) stand as conflicts. Identifiers are multi-valued by
        nature and never conflict with each other."""
        conflicts: list[IdentityConflict] = []
        for field in ("name", "dob"):
            field_facts = [f for f in facts if f.field == field]
            values = sorted({f.value for f in field_facts})
            if len(values) > 1:
                conflicts.append(
                    IdentityConflict(
                        field=field, values=values, facts=field_facts
                    )
                )
        return conflicts

    def _accounts(self, cases) -> list[ProfileAccount]:
        accounts: list[ProfileAccount] = []
        seen: dict[str, ProfileAccount] = {}
        for case in cases:
            entry = seen.get(case.account_id)
            if entry is None:
                profile = self._typologies.get_account_profile(case.account_id)
                entry = ProfileAccount(
                    account_id=case.account_id,
                    profile_present=profile is not None,
                    opened_on=profile.opened_on if profile else None,
                    account_type=profile.account_type if profile else None,
                    expected_monthly_amount=(
                        profile.expected_monthly_amount if profile else None
                    ),
                    expected_monthly_count=(
                        profile.expected_monthly_count if profile else None
                    ),
                    case_ids=[],
                )
                seen[case.account_id] = entry
                accounts.append(entry)
            entry.case_ids.append(case.case_id)
        return accounts

    def _case_history(self, cases) -> list[ProfileCaseEntry]:
        entries: list[ProfileCaseEntry] = []
        for case in cases:
            outcome: str | None = None
            standing: str | None = None
            if self._dispositions is not None:
                history = self._dispositions.history(case.case_id)
                if history:
                    latest = history[-1]
                    outcome = latest.outcome.value
                    standing = self._dispositions.status_of(latest)
            approved = False
            if self._approvals is not None:
                approved = any(
                    a.outcome is ApprovalOutcome.APPROVED
                    for a in self._approvals.list_approvals(case.case_id)
                )
            entries.append(
                ProfileCaseEntry(
                    case_id=case.case_id,
                    alert_id=case.alert_id,
                    rule_id=case.rule_id,
                    severity=case.severity,
                    status=case.status,
                    detected_on=case.detected_on,
                    disposition_outcome=outcome,
                    disposition_standing=standing,
                    filed_sar=case.status is CaseStatus.FILED_SAR,
                    narrative_approved=approved,
                )
            )
        return entries

    def _screening_history(self, cases) -> list[ProfileScreeningEntry]:
        entries: list[ProfileScreeningEntry] = []
        for case in cases:
            hits = self._screening.list_hits(case.case_id)
            runs = sorted(
                self._screening.list_screening_runs(case.case_id),
                key=lambda r: (r.run_at, r.run_id),
            )
            for run in runs:
                for pin in run.pins:
                    entries.append(
                        ProfileScreeningEntry(
                            case_id=case.case_id,
                            list_kind=pin.list_kind,
                            snapshot_version=pin.version,
                            run_id=run.run_id,
                            screened_at=run.run_at,
                            hits=[
                                ProfileScreeningHit(
                                    hit_id=h.hit_id,
                                    subject_name=h.subject_name,
                                    subject_role=h.subject_role,
                                    entry_name=h.entry_name,
                                    status=h.status,
                                    strength=h.strength,
                                    basis=h.basis,
                                    cleared_reason=h.cleared_reason,
                                    status_reason=h.status_reason,
                                )
                                for h in hits
                                if h.run_id == run.run_id
                                and h.snapshot_id == pin.snapshot_id
                            ],
                        )
                    )
        return entries

    def _freshness(
        self, cases, facts: list[IdentityFact], as_of: date
    ) -> list[FreshnessEntry]:
        identity_dates = {
            c.detected_on for c in cases if any(
                f.source_case_id == c.case_id for f in facts
            )
        }
        for case in cases:
            for run in self._screening.list_screening_runs(case.case_id):
                if any(f.source_case_id == case.case_id for f in facts):
                    identity_dates.add(run.run_at.date())
        screening_dates = {
            run.run_at.date()
            for case in cases
            for run in self._screening.list_screening_runs(case.case_id)
        }
        activity_dates = {
            txn.posted_at.date()
            for case in cases
            for txn in self._typologies.list_transactions(case.case_id)
        }
        corroborated: dict[str, date | None] = {
            "identity": max(identity_dates) if identity_dates else None,
            "account": max((c.detected_on for c in cases), default=None),
            "screening": max(screening_dates) if screening_dates else None,
            "activity": max(activity_dates) if activity_dates else None,
        }
        entries: list[FreshnessEntry] = []
        for fact_class in FACT_CLASSES:
            last = corroborated[fact_class]
            limit = FRESHNESS_LIMITS_DAYS[fact_class]
            stale = last is None or (as_of - last).days > limit
            entries.append(
                FreshnessEntry(
                    fact_class=fact_class,
                    last_corroborated_on=last,
                    stale=stale,
                    limit_days=limit,
                    policy_version=FRESHNESS_POLICY_VERSION,
                )
            )
        return entries

    # -- counterparty views --------------------------------------------

    def _aggregate(self) -> dict[str, dict[str, _CounterpartyAgg]]:
        """Aggregate every stored transaction by counterparty and
        customer: ``{name_key: {customer_id: aggregate}}``.

        Iteration is deterministic (cases by id, transactions in
        store order), so display-form choice and fencing are
        reproducible. Raw forms are counted per slice; the
        canonical raw form is the most frequent (ties break to
        the first seen)."""
        by_name: dict[str, dict[str, _CounterpartyAgg]] = {}
        cases = sorted(self._store.list_cases(), key=lambda c: c.case_id)
        for case in cases:
            for txn in self._typologies.list_transactions(case.case_id):
                if not txn.counterparty:
                    continue
                key = _normalise_name(txn.counterparty)
                per_customer = by_name.setdefault(key, {})
                agg = per_customer.setdefault(
                    case.customer_id, _CounterpartyAgg()
                )
                if txn.direction == "credit":
                    agg.total_in += txn.amount
                else:
                    agg.total_out += txn.amount
                agg.count += 1
                agg.raw_forms[txn.counterparty] += 1
                agg.currencies.add(txn.currency)
                agg.case_ids.add(case.case_id)
                agg.account_ids.add(txn.account_id)
                if agg.first_seen is None or txn.posted_at < agg.first_seen:
                    agg.first_seen = txn.posted_at
                if agg.last_seen is None or txn.posted_at > agg.last_seen:
                    agg.last_seen = txn.posted_at
        self._apply_fencing(by_name, cases)
        return by_name

    def _apply_fencing(self, by_name, cases) -> None:
        """Fill each aggregate's fenced display forms from the
        quarantine records on the batches its transactions rode
        in on. A name is fenced per (case, batch item, field);
        the first fenced form found for a raw form wins."""
        if self._quarantine is None:
            return
        for case in cases:
            batches = self._typologies.list_transaction_batches(case.case_id)
            txns = self._typologies.list_transactions(case.case_id)
            if not batches or not txns:
                continue
            by_seq = {b.evidence_seq: b for b in batches if b.evidence_seq}
            for txn in txns:
                if not txn.counterparty:
                    continue
                key = _normalise_name(txn.counterparty)
                per_customer = by_name.get(key, {})
                agg = per_customer.get(case.customer_id)
                if agg is None or txn.counterparty in agg.fenced_forms:
                    continue
                for seq in sorted(by_seq):
                    fenced = self._quarantine.fence_field(
                        case.case_id,
                        seq,
                        f"transaction:{txn.transaction_id}.counterparty",
                        txn.counterparty,
                    )
                    if fenced != txn.counterparty:
                        agg.fenced_forms[txn.counterparty] = fenced
                        break

    @staticmethod
    def _canonical_raw(agg: _CounterpartyAgg) -> str:
        return agg.raw_forms.most_common(1)[0][0]

    def _display_name(self, agg: _CounterpartyAgg) -> tuple[str, str]:
        raw = self._canonical_raw(agg)
        return agg.fenced_forms.get(raw, raw), raw

    def _screening_for(self, key: str) -> list[CounterpartyScreening]:
        found: list[CounterpartyScreening] = []
        for case in sorted(self._store.list_cases(), key=lambda c: c.case_id):
            for hit in self._screening.list_hits(case.case_id):
                if _normalise_name(hit.subject_name) == key:
                    found.append(
                        CounterpartyScreening(
                            case_id=case.case_id,
                            hit_id=hit.hit_id,
                            list_kind=hit.list_kind,
                            snapshot_version=hit.snapshot_version,
                            status=hit.status,
                            entry_name=hit.entry_name,
                        )
                    )
        return sorted(found, key=lambda s: (s.case_id, s.hit_id))

    def _counterparty_view(
        self, key: str, agg: _CounterpartyAgg, customer_ids: list[str]
    ) -> CounterpartyView:
        display, raw = self._display_name(agg)
        return CounterpartyView(
            name=display,
            name_raw=raw,
            total_in=agg.total_in,
            total_out=agg.total_out,
            transaction_count=agg.count,
            first_seen=agg.first_seen,
            last_seen=agg.last_seen,
            currencies=sorted(agg.currencies),
            customer_ids=customer_ids,
            case_ids=sorted(agg.case_ids),
            account_ids=sorted(agg.account_ids),
            screening=self._screening_for(key),
        )

    def counterparties_for_customer(
        self, customer_id: str
    ) -> list[CounterpartyView]:
        """Every counterparty on the customer's cases, with the
        customer's own totals and the full customer link set."""
        if not self._customer_cases(customer_id):
            raise CustomerNotFoundError(
                f"no cases on record for customer {customer_id}"
            )
        by_name = self._aggregate()
        views: list[CounterpartyView] = []
        for key in sorted(by_name):
            per_customer = by_name[key]
            if customer_id not in per_customer:
                continue
            views.append(
                self._counterparty_view(
                    key, per_customer[customer_id], sorted(per_customer)
                )
            )
        return views

    def counterparty_detail(
        self, customer_id: str, name: str
    ) -> CounterpartyView:
        key = _normalise_name(name)
        for view in self.counterparties_for_customer(customer_id):
            if _normalise_name(view.name_raw) == key:
                return view
        raise ProfileNotFoundError(
            f"counterparty {name!r} not found on customer "
            f"{customer_id}'s cases"
        )

    def shared_counterparties(self) -> list[SharedCounterparty]:
        """Counterparties standing on more than one customer's
        cases — the network signal, computed exactly."""
        by_name = self._aggregate()
        shared: list[SharedCounterparty] = []
        for key in sorted(by_name):
            per_customer = by_name[key]
            if len(per_customer) < 2:
                continue
            total_in = sum(
                (a.total_in for a in per_customer.values()), Decimal("0")
            )
            total_out = sum(
                (a.total_out for a in per_customer.values()), Decimal("0")
            )
            count = sum(a.count for a in per_customer.values())
            case_ids = sorted(
                {cid for a in per_customer.values() for cid in a.case_ids}
            )
            # Display form: fence from any customer's slice that
            # carries one; the canonical raw from the largest slice.
            biggest = max(
                per_customer.values(), key=lambda a: a.count
            )
            raw = self._canonical_raw(biggest)
            display = raw
            for agg in per_customer.values():
                if raw in agg.fenced_forms:
                    display = agg.fenced_forms[raw]
                    break
            shared.append(
                SharedCounterparty(
                    name=display,
                    name_raw=raw,
                    customer_ids=sorted(per_customer),
                    case_ids=case_ids,
                    transaction_count=count,
                    total_in=total_in,
                    total_out=total_out,
                )
            )
        return shared
