"""The typology engine: deterministic money patterns, in code.

Law 4 lives here. Totals, structuring patterns, velocity and
threshold tests are computed by pure functions over stored
transaction records — a model never computes money, and no check in
this module reads anything that did not arrive through an
evidence-backed ingestion.

Every check is a pure function of (transactions, account profile,
rule pack) returning finding drafts. The rules are versioned data
(the ``RulePack``): each finding records the pack id + version whose
thresholds produced it, a pack never mutates once registered, and
changing a threshold means registering a new version — so findings
from different versions coexist and stay distinguishable.

Re-running the engine over the same stored input under the same
pack is idempotent: the run's input fingerprint (transaction ids +
batch hashes + profile) returns the existing run instead of
duplicating findings or evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal

from .errors import (
    CaseNotFoundError,
    NoTransactionsError,
    RulePackImmutableError,
    RulePackNotFoundError,
    TransactionMismatchError,
    TypologyError,
)
from .evidence import EvidenceService
from .logging_config import get_logger
from .models import (
    AccountProfile,
    AuditEvent,
    RulePack,
    Transaction,
    TransactionBatch,
    TypologyFinding,
    TypologyRun,
)
from .ports import CaseStore, RulePackSource, TransactionSource, TypologyStore

logger = get_logger(__name__)

_RATIO_PLACES = Decimal("0.0001")
_DAILY_PLACES = Decimal("0.000001")


def _dec(value: Decimal) -> str:
    """Exact decimal string for a finding figure."""
    return format(value, "f")


def _ratio(value: Decimal) -> str:
    return _dec(value.quantize(_RATIO_PLACES, rounding=ROUND_HALF_UP))


def _daily(value: Decimal) -> str:
    return _dec(value.quantize(_DAILY_PLACES, rounding=ROUND_HALF_UP))


def rule_pack_content_hash(pack: RulePack) -> str:
    """SHA-256 over the pack's identity + thresholds, canonically.

    The hash changes iff the rules change — it is what registration
    compares to refuse a same-version edit.
    """
    canonical = {
        "pack_id": pack.pack_id,
        "version": pack.version,
        "thresholds": {
            name: (_dec(value) if isinstance(value, Decimal) else value)
            for name, value in sorted(
                pack.model_dump(exclude={"pack_id", "version", "source_note", "content_hash"}).items()
            )
        },
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def canonical_transactions_bytes(transactions: list[Transaction]) -> bytes:
    """Canonical byte form of a transaction batch: sorted by id,
    amounts as decimal strings — the batch's evidence content and the
    basis of its content hash."""
    ordered = sorted(transactions, key=lambda t: t.transaction_id)
    payload = [t.model_dump(mode="json") for t in ordered]
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sorted(txns: list[Transaction]) -> list[Transaction]:
    return sorted(txns, key=lambda t: (t.posted_at, t.transaction_id))


# ---------------------------------------------------------------------------
# Finding drafts (the pure checks return these; the service wraps them)
# ---------------------------------------------------------------------------


@dataclass
class _Draft:
    typology_id: str
    variant: str | None
    transaction_ids: list[str]
    figures: dict[str, str]
    window_start: date | None
    window_end: date | None
    detail: str


# ---------------------------------------------------------------------------
# The checks — pure, deterministic, no I/O
# ---------------------------------------------------------------------------


def check_structuring(txns: list[Transaction], pack: RulePack) -> list[_Draft]:
    """Cash transactions clustered just under the CTR threshold.

    Only physical-cash transactions inside the band
    [band_low, ctr_threshold) are structuring material, and cash-in
    and cash-out are aggregated separately (the CTR applies to
    each). Same-day clusters are reported first and claim their
    transactions; multi-day clusters are then sought in what
    remains, over anchored windows of ``structuring_window_days``
    starting at each remaining transaction, with overlapping
    qualifying windows merged — so one pattern yields one finding,
    never a stack of near-duplicates.
    """
    drafts: list[_Draft] = []
    band = [
        t
        for t in txns
        if t.cash and pack.structuring_band_low <= t.amount < pack.structuring_ctr_threshold
    ]
    for direction in ("credit", "debit"):
        side = [t for t in band if t.direction == direction]
        if not side:
            continue
        claimed: set[str] = set()
        by_day: dict[date, list[Transaction]] = {}
        for txn in side:
            by_day.setdefault(txn.posted_at.date(), []).append(txn)
        for day in sorted(by_day):
            group = _sorted(by_day[day])
            total = sum((t.amount for t in group), Decimal("0"))
            if len(group) >= pack.structuring_min_count and total >= pack.structuring_ctr_threshold:
                drafts.append(
                    _Draft(
                        typology_id="structuring",
                        variant="same_day",
                        transaction_ids=[t.transaction_id for t in group],
                        figures={
                            "total_amount": _dec(total),
                            "transaction_count": str(len(group)),
                            "direction": direction,
                            "ctr_threshold": _dec(pack.structuring_ctr_threshold),
                            "band_low": _dec(pack.structuring_band_low),
                        },
                        window_start=day,
                        window_end=day,
                        detail=(
                            f"{len(group)} cash {direction}s totalling {_dec(total)} "
                            f"on {day.isoformat()}, each inside the "
                            f"[{_dec(pack.structuring_band_low)}, "
                            f"{_dec(pack.structuring_ctr_threshold)}) band under "
                            "the CTR threshold"
                        ),
                    )
                )
                claimed.update(t.transaction_id for t in group)
        remaining = [t for t in side if t.transaction_id not in claimed]
        windows: list[tuple[date, date, list[Transaction]]] = []
        for anchor in remaining:
            start = anchor.posted_at.date()
            end = start + timedelta(days=pack.structuring_window_days - 1)
            members = [
                t for t in remaining if start <= t.posted_at.date() <= end
            ]
            total = sum((t.amount for t in members), Decimal("0"))
            if (
                len(members) >= pack.structuring_min_count
                and total >= pack.structuring_ctr_threshold
            ):
                windows.append((start, end, members))
        merged = _merge_windows(windows)
        for start, end, members in merged:
            members = _sorted(members)
            total = sum((t.amount for t in members), Decimal("0"))
            drafts.append(
                _Draft(
                    typology_id="structuring",
                    variant="multi_day",
                    transaction_ids=[t.transaction_id for t in members],
                    figures={
                        "total_amount": _dec(total),
                        "transaction_count": str(len(members)),
                        "direction": direction,
                        "ctr_threshold": _dec(pack.structuring_ctr_threshold),
                        "band_low": _dec(pack.structuring_band_low),
                        "window_days": str(pack.structuring_window_days),
                    },
                    window_start=start,
                    window_end=end,
                    detail=(
                        f"{len(members)} cash {direction}s totalling {_dec(total)} "
                        f"across {start.isoformat()}..{end.isoformat()}, each "
                        f"inside the [{_dec(pack.structuring_band_low)}, "
                        f"{_dec(pack.structuring_ctr_threshold)}) band under "
                        "the CTR threshold"
                    ),
                )
            )
    return drafts


def _merge_windows(
    windows: list[tuple[date, date, list[Transaction]]],
) -> list[tuple[date, date, list[Transaction]]]:
    """Merge qualifying windows that share any transaction."""
    merged: list[tuple[date, date, list[Transaction]]] = []
    for start, end, members in sorted(windows, key=lambda w: (w[0], w[1])):
        member_ids = {t.transaction_id for t in members}
        target = None
        for existing in merged:
            if member_ids & {t.transaction_id for t in existing[2]}:
                target = existing
                break
        if target is None:
            merged.append((start, end, list(members)))
        else:
            idx = merged.index(target)
            known = {t.transaction_id for t in target[2]}
            combined = list(target[2]) + [t for t in members if t.transaction_id not in known]
            merged[idx] = (min(target[0], start), max(target[1], end), combined)
    return merged


def check_velocity(txns: list[Transaction], pack: RulePack) -> list[_Draft]:
    """Activity in the stream's last days vs the account's own baseline.

    The observation window is the last ``velocity_observation_days``
    ending at the latest transaction; the baseline is everything
    before it. The rule fires on the count multiple (computed in
    code, reported alongside the amount multiple); an account
    without enough baseline history is not judged — no finding,
    rather than a multiple computed over a fortnight.
    """
    if not txns:
        return []
    last_date = max(t.posted_at.date() for t in txns)
    obs_start = last_date - timedelta(days=pack.velocity_observation_days - 1)
    observation = [t for t in txns if t.posted_at.date() >= obs_start]
    baseline = [t for t in txns if t.posted_at.date() < obs_start]
    if not baseline:
        return []
    first_date = min(t.posted_at.date() for t in baseline)
    baseline_days = (obs_start - first_date).days
    if baseline_days < pack.velocity_min_baseline_days:
        return []
    obs_count = len(observation)
    if obs_count < pack.velocity_min_observation_count:
        return []
    obs_amount = sum((t.amount for t in observation), Decimal("0"))
    base_amount = sum((t.amount for t in baseline), Decimal("0"))
    count_multiple = (Decimal(obs_count) * Decimal(baseline_days)) / (
        Decimal(len(baseline)) * Decimal(pack.velocity_observation_days)
    )
    amount_multiple = (
        (obs_amount * Decimal(baseline_days))
        / (base_amount * Decimal(pack.velocity_observation_days))
        if base_amount > 0
        else Decimal("0")
    )
    if count_multiple.quantize(_RATIO_PLACES, rounding=ROUND_HALF_UP) < pack.velocity_count_multiple:
        return []
    baseline_daily_count = Decimal(len(baseline)) / Decimal(baseline_days)
    return [
        _Draft(
            typology_id="velocity",
            variant=None,
            transaction_ids=[t.transaction_id for t in _sorted(observation)],
            figures={
                "observation_count": str(obs_count),
                "observation_amount": _dec(obs_amount),
                "baseline_count": str(len(baseline)),
                "baseline_amount": _dec(base_amount),
                "baseline_days": str(baseline_days),
                "baseline_daily_count": _daily(baseline_daily_count),
                "count_multiple": _ratio(count_multiple),
                "amount_multiple": _ratio(amount_multiple),
            },
            window_start=obs_start,
            window_end=last_date,
            detail=(
                f"{obs_count} transactions in the {pack.velocity_observation_days} "
                f"days to {last_date.isoformat()} against a baseline of "
                f"{_daily(baseline_daily_count)} per day over {baseline_days} "
                f"days — a count multiple of {_ratio(count_multiple)}x "
                f"(rule threshold {pack.velocity_count_multiple}x)"
            ),
        )
    ]


def check_dormancy_then_burst(
    txns: list[Transaction], profile: AccountProfile | None, pack: RulePack
) -> list[_Draft]:
    """A long silence, then sudden activity.

    Gaps are measured between consecutive activity dates; the
    account's opening date (from its profile) starts the first gap,
    so an account opened and left idle for a year before its first
    transaction is measured too. Each qualifying gap is judged on
    the burst that follows it: the transactions inside
    ``dormancy_burst_days`` of activity resuming.
    """
    if not txns:
        return []
    activity_dates = sorted({t.posted_at.date() for t in txns})
    boundaries: list[date] = []
    if profile is not None and profile.opened_on not in activity_dates:
        boundaries.append(profile.opened_on)
    boundaries.extend(activity_dates)
    boundaries.sort()
    drafts: list[_Draft] = []
    for previous, resumed in zip(boundaries, boundaries[1:]):
        gap_days = (resumed - previous).days
        if gap_days < pack.dormancy_min_gap_days:
            continue
        burst_end = resumed + timedelta(days=pack.dormancy_burst_days - 1)
        burst = [
            t for t in txns if resumed <= t.posted_at.date() <= burst_end
        ]
        burst_total = sum((t.amount for t in burst), Decimal("0"))
        if (
            len(burst) >= pack.dormancy_min_burst_count
            and burst_total >= pack.dormancy_min_burst_amount
        ):
            drafts.append(
                _Draft(
                    typology_id="dormancy_then_burst",
                    variant=None,
                    transaction_ids=[t.transaction_id for t in _sorted(burst)],
                    figures={
                        "gap_days": str(gap_days),
                        "gap_start": previous.isoformat(),
                        "gap_end": resumed.isoformat(),
                        "burst_count": str(len(burst)),
                        "burst_amount": _dec(burst_total),
                    },
                    window_start=resumed,
                    window_end=burst_end,
                    detail=(
                        f"no activity for {gap_days} days "
                        f"({previous.isoformat()}..{resumed.isoformat()}), then "
                        f"{len(burst)} transactions totalling {_dec(burst_total)} "
                        f"within {pack.dormancy_burst_days} days of resumption"
                    ),
                )
            )
    return drafts


def check_round_amount(txns: list[Transaction], pack: RulePack) -> list[_Draft]:
    """Round-amount pattern: whole multiples of the round unit.

    Legitimate payments are rarely exact multiples of 1,000 again
    and again; a stream dominated by them is a structuring/smurfing
    cousin worth an analyst's look. Fires only when count, share of
    the stream, and total all clear their thresholds together — a
    handful of round rent payments in a varied stream stays quiet.
    """
    if not txns:
        return []
    round_txns = [
        t
        for t in txns
        if t.amount >= pack.round_min_amount and t.amount % pack.round_unit == 0
    ]
    round_total = sum((t.amount for t in round_txns), Decimal("0"))
    share = Decimal(len(round_txns)) / Decimal(len(txns))
    if (
        len(round_txns) < pack.round_min_count
        or share.quantize(_RATIO_PLACES, rounding=ROUND_HALF_UP) < pack.round_min_share
        or round_total < pack.round_min_total
    ):
        return []
    ordered = _sorted(round_txns)
    return [
        _Draft(
            typology_id="round_amount",
            variant=None,
            transaction_ids=[t.transaction_id for t in ordered],
            figures={
                "round_count": str(len(round_txns)),
                "total_count": str(len(txns)),
                "round_total": _dec(round_total),
                "round_share": _ratio(share),
                "round_unit": _dec(pack.round_unit),
            },
            window_start=min(t.posted_at.date() for t in txns),
            window_end=max(t.posted_at.date() for t in txns),
            detail=(
                f"{len(round_txns)} of {len(txns)} transactions are whole "
                f"multiples of {_dec(pack.round_unit)} at or above "
                f"{_dec(pack.round_min_amount)}, totalling {_dec(round_total)} "
                f"— a round share of {_ratio(share)}"
            ),
        )
    ]


def check_rapid_in_out(txns: list[Transaction], pack: RulePack) -> list[_Draft]:
    """Funds in, funds straight back out, minimal retention.

    Each credit at or above ``in_out_min_amount`` opens a lot.
    Debits inside the window are allocated to the earliest open lot
    (a debit can split across lots); a lot whose allocated debits
    reach the pass-through fraction of the credit is a finding,
    with the retained remainder stated exactly.
    """
    window = timedelta(hours=pack.in_out_window_hours)
    lots: list[dict] = []
    for txn in _sorted(txns):
        if txn.direction == "credit" and txn.amount >= pack.in_out_min_amount:
            lots.append(
                {
                    "credit": txn,
                    "remaining": txn.amount,
                    "allocated": Decimal("0"),
                    "debit_ids": [],
                }
            )
        elif txn.direction == "debit":
            unallocated = txn.amount
            for lot in lots:
                if unallocated <= 0:
                    break
                credit = lot["credit"]
                if not (credit.posted_at <= txn.posted_at <= credit.posted_at + window):
                    continue
                if lot["remaining"] <= 0:
                    continue
                take = min(unallocated, lot["remaining"])
                lot["remaining"] -= take
                lot["allocated"] += take
                if txn.transaction_id not in lot["debit_ids"]:
                    lot["debit_ids"].append(txn.transaction_id)
                unallocated -= take
    drafts: list[_Draft] = []
    for lot in lots:
        credit: Transaction = lot["credit"]
        allocated: Decimal = lot["allocated"]
        if allocated < pack.in_out_pass_through_fraction * credit.amount:
            continue
        retained = credit.amount - allocated
        pass_through = allocated / credit.amount
        drafts.append(
            _Draft(
                typology_id="rapid_in_out",
                variant=None,
                transaction_ids=[credit.transaction_id] + lot["debit_ids"],
                figures={
                    "credit_amount": _dec(credit.amount),
                    "disbursed_amount": _dec(allocated),
                    "retained_amount": _dec(retained),
                    "pass_through": _ratio(pass_through),
                    "window_hours": str(pack.in_out_window_hours),
                },
                window_start=credit.posted_at.date(),
                window_end=(credit.posted_at + window).date(),
                detail=(
                    f"credit of {_dec(credit.amount)} on "
                    f"{credit.posted_at.date().isoformat()} disbursed "
                    f"{_dec(allocated)} within {pack.in_out_window_hours}h, "
                    f"retaining {_dec(retained)}"
                ),
            )
        )
    return drafts


def run_all_checks(
    txns: list[Transaction], profile: AccountProfile | None, pack: RulePack
) -> list[_Draft]:
    """Every check in the pack, in a fixed order, over the sorted stream."""
    ordered = _sorted(txns)
    drafts: list[_Draft] = []
    drafts.extend(check_structuring(ordered, pack))
    drafts.extend(check_velocity(ordered, pack))
    drafts.extend(check_dormancy_then_burst(ordered, profile, pack))
    drafts.extend(check_round_amount(ordered, pack))
    drafts.extend(check_rapid_in_out(ordered, pack))
    return drafts


# ---------------------------------------------------------------------------
# The service: rule packs, ingestion, runs
# ---------------------------------------------------------------------------


def input_fingerprint(
    transactions: list[Transaction],
    batches: list[TransactionBatch],
    profile: AccountProfile | None,
) -> str:
    """Hash of the exact stored input a run computes over:
    transaction ids, the batch hashes they arrived in, and the
    account profile. Same input + same pack => same run."""
    canonical = {
        "transaction_ids": sorted(t.transaction_id for t in transactions),
        "batch_hashes": sorted(b.content_sha256 for b in batches),
        "profile": profile.model_dump(mode="json") if profile else None,
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class TypologyService:
    """Rule-pack registration, evidence-backed transaction
    ingestion, and engine runs. One service owns every write path,
    which is what keeps runs idempotent and findings attributable
    to a pack version."""

    def __init__(
        self,
        store: CaseStore,
        typology_store: TypologyStore,
        evidence: EvidenceService,
    ) -> None:
        self._store = store
        self._typology = typology_store
        self._evidence = evidence

    # -- rule packs -----------------------------------------------------

    def register_rule_pack(
        self, pack: RulePack, *, actor: str = "rule-book"
    ) -> RulePack:
        """Register one rule pack. Idempotent for identical content;
        refused (RulePackImmutableError) when the same id + version
        arrives with different thresholds — that is a changed rule,
        and a changed rule is a new version, never an edit."""
        digest = rule_pack_content_hash(pack)
        if pack.content_hash and pack.content_hash != digest:
            raise TypologyError(
                f"rule pack {pack.pack_id} {pack.version}: declared "
                "content_hash does not match its thresholds"
            )
        pack = pack.model_copy(update={"content_hash": digest})
        existing = self._typology.get_rule_pack(pack.pack_id, pack.version)
        if existing is not None:
            if existing.content_hash == digest:
                return existing
            raise RulePackImmutableError(
                f"rule pack {pack.pack_id} version {pack.version} is "
                f"already registered with different thresholds (hash "
                f"{existing.content_hash[:12]}…); register the changed "
                "rules as a new version"
            )
        self._typology.save_rule_pack(pack)
        self._store.append_audit(
            AuditEvent(
                case_id=None,
                actor=actor,
                event="rule_pack_registered",
                detail={
                    "pack_id": pack.pack_id,
                    "version": pack.version,
                    "content_hash": digest,
                },
            )
        )
        logger.info(
            "rule pack registered",
            extra={
                "event": "rule_pack_registered",
                "pack_id": pack.pack_id,
                "version": pack.version,
            },
        )
        return pack

    def register_from_source(
        self, source: RulePackSource, *, actor: str = "rule-book"
    ) -> list[RulePack]:
        return [self.register_rule_pack(p, actor=actor) for p in source.list_rule_packs()]

    # -- transaction ingestion -------------------------------------------

    def ingest_transactions(
        self,
        case_id: str,
        transactions: list[Transaction],
        *,
        source_ref: str,
        actor: str,
    ) -> TransactionBatch:
        """Ingest one batch of transactions into a case's file.

        The batch's canonical content becomes a hash-chained
        evidence item; the engine later reads only the stored
        records created here. Re-delivering the identical batch is
        an idempotent no-op returning the existing batch. A batch
        naming an account other than the case's — or mixing accounts
        — is refused: a case's stream is one account's stream.
        """
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        if not transactions:
            raise TypologyError("an empty transaction batch carries no evidence")
        accounts = {t.account_id for t in transactions}
        if accounts != {case.account_id}:
            raise TransactionMismatchError(
                f"case {case_id} is for account {case.account_id}; batch "
                f"covers {sorted(accounts)}"
            )
        content = canonical_transactions_bytes(transactions)
        digest = hashlib.sha256(content).hexdigest()
        existing = self._typology.get_transaction_batch(case_id, digest)
        if existing is not None:
            return existing
        batch = TransactionBatch(
            case_id=case_id,
            account_id=case.account_id,
            source_ref=source_ref,
            content_sha256=digest,
            transaction_count=len(transactions),
            ingested_by=actor,
        )
        item = self._evidence.add_item(
            case_id,
            kind="transaction_batch",
            content=content,
            source_ref=source_ref,
            captured_by=actor,
        )
        batch = batch.model_copy(update={"evidence_seq": item.seq})
        self._typology.add_transaction_batch(batch)
        self._typology.add_transactions(case_id, batch.batch_id, transactions)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="transactions_ingested",
                detail={
                    "batch_id": batch.batch_id,
                    "account_id": case.account_id,
                    "transactions": len(transactions),
                    "content_sha256": digest,
                    "evidence_seq": item.seq,
                },
            )
        )
        logger.info(
            "transactions ingested",
            extra={
                "case_id": case_id,
                "event": "transactions_ingested",
                "transactions": len(transactions),
            },
        )
        return batch

    def ingest_from_source(
        self,
        case_id: str,
        source: TransactionSource,
        *,
        actor: str = "core-banking-feed",
    ) -> TransactionBatch:
        """Pull the case account's profile + stream from the
        transaction feed and ingest them. The profile is stored as
        core-banking reference data; the transactions are
        evidence-backed by ``ingest_transactions``."""
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        profile = source.get_profile(case.account_id)
        if profile is not None:
            self._typology.save_account_profile(profile)
        transactions = source.get_transactions(case.account_id)
        return self.ingest_transactions(
            case_id,
            transactions,
            source_ref=f"core-banking:{case.account_id}",
            actor=actor,
        )

    # -- engine runs -------------------------------------------------------

    def run_typologies(
        self,
        case_id: str,
        pack_id: str,
        version: str,
        *,
        actor: str,
    ) -> TypologyRun:
        """Run every check in the named pack over the case's stored
        transactions. Persists the findings as records AND as a
        hash-chained ``typology_findings`` evidence item. Idempotent
        per (case, pack, input fingerprint)."""
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        pack = self._typology.get_rule_pack(pack_id, version)
        if pack is None:
            raise RulePackNotFoundError(
                f"no registered rule pack {pack_id!r} version {version!r}"
            )
        transactions = self._typology.list_transactions(case_id)
        if not transactions:
            raise NoTransactionsError(
                f"case {case_id}: no ingested transactions — the engine "
                "reads only stored, evidence-backed records"
            )
        profile = self._typology.get_account_profile(case.account_id)
        batches = self._typology.list_transaction_batches(case_id)
        fingerprint = input_fingerprint(transactions, batches, profile)
        existing = self._typology.get_typology_run_by_fingerprint(
            case_id, pack_id, version, fingerprint
        )
        if existing is not None:
            return existing

        run = TypologyRun(
            case_id=case_id,
            account_id=case.account_id,
            actor=actor,
            rule_pack_id=pack_id,
            rule_pack_version=version,
            input_fingerprint=fingerprint,
            transaction_count=len(transactions),
        )
        drafts = run_all_checks(transactions, profile, pack)
        findings = [
            TypologyFinding(
                case_id=case_id,
                run_id=run.run_id,
                typology_id=draft.typology_id,
                variant=draft.variant,
                account_id=case.account_id,
                rule_pack_id=pack_id,
                rule_pack_version=version,
                transaction_ids=draft.transaction_ids,
                figures=draft.figures,
                window_start=draft.window_start,
                window_end=draft.window_end,
                detail=draft.detail,
            )
            for draft in drafts
        ]
        for finding in findings:
            self._typology.add_finding(finding)
        run = run.model_copy(update={"finding_count": len(findings)})

        content = json.dumps(
            {
                "run": run.model_dump(mode="json"),
                "findings": [f.model_dump(mode="json") for f in findings],
            },
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        item = self._evidence.add_item(
            case_id,
            kind="typology_findings",
            content=content,
            source_ref=f"typologies:{run.run_id}",
            captured_by=actor,
        )
        run = run.model_copy(update={"evidence_seq": item.seq})
        self._typology.add_typology_run(run)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="typology_run",
                detail={
                    "run_id": run.run_id,
                    "rule_pack_id": pack_id,
                    "rule_pack_version": version,
                    "transactions": len(transactions),
                    "findings": len(findings),
                    "evidence_seq": item.seq,
                },
            )
        )
        logger.info(
            "typology run",
            extra={
                "case_id": case_id,
                "event": "typology_run",
                "run_id": run.run_id,
                "findings": len(findings),
            },
        )
        return run

    def list_findings(
        self, case_id: str, run_id: str | None = None
    ) -> list[TypologyFinding]:
        if self._store.get_case(case_id) is None:
            raise CaseNotFoundError(case_id)
        findings = self._typology.list_findings(case_id)
        if run_id is not None:
            findings = [f for f in findings if f.run_id == run_id]
        return sorted(findings, key=_finding_sort_key)


#: Presentation order for findings: engine check order, then variant,
#: then window, then first transaction — identical on every read.
_TYPOLOGY_ORDER = {
    "structuring": 0,
    "velocity": 1,
    "dormancy_then_burst": 2,
    "round_amount": 3,
    "rapid_in_out": 4,
}
_VARIANT_ORDER = {"same_day": 0, "multi_day": 1}


def _finding_sort_key(finding: TypologyFinding):
    return (
        _TYPOLOGY_ORDER.get(finding.typology_id, 99),
        _VARIANT_ORDER.get(finding.variant or "", 0),
        finding.window_start.isoformat() if finding.window_start else "",
        finding.transaction_ids[0] if finding.transaction_ids else "",
        finding.finding_id,
    )
