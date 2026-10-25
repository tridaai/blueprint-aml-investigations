"""R3 typology engine: the five deterministic checks, rule-pack
versioning, evidence-backed ingestion, and idempotent runs.

Law 4: the model never computes money — these tests grade the
arithmetic itself, including the negative controls. A typology that
fires on the clean control account is a failed gate, not a nuance.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from aml_investigations.errors import (
    NoTransactionsError,
    RulePackImmutableError,
    RulePackNotFoundError,
    TransactionMismatchError,
    TypologyError,
)
from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.models import (
    AccountProfile,
    Alert,
    RulePack,
    Transaction,
)
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.stores import InMemoryCaseStore, SqlCaseStore
from aml_investigations.transactions import (
    ListTransactionFeed,
    ReferenceTransactionFeed,
)
from aml_investigations.typologies import (
    TypologyService,
    check_dormancy_then_burst,
    check_rapid_in_out,
    check_round_amount,
    check_structuring,
    check_velocity,
    run_all_checks,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

ACCOUNT = "ACCT-T-1"
PROFILE = AccountProfile(
    account_id=ACCOUNT,
    customer_id="CUST-T-1",
    opened_on=date(2025, 1, 1),
    account_type="personal_checking",
)
#: Profile for the service tests: opened shortly before the March
#: 2026 streams they ingest, so no opening dormancy gap exists.
SERVICE_PROFILE = AccountProfile(
    account_id=ACCOUNT,
    customer_id="CUST-T-1",
    opened_on=date(2026, 2, 1),
    account_type="personal_checking",
)


def at(day: date, hour: int = 10) -> datetime:
    return datetime.combine(day, time(hour, 0), tzinfo=timezone.utc)


def txn(
    tid: str,
    day: date,
    amount: str,
    *,
    direction: str = "credit",
    cash: bool = False,
    channel: str = "wire",
    hour: int = 10,
    account: str = ACCOUNT,
) -> Transaction:
    return Transaction(
        transaction_id=tid,
        account_id=account,
        posted_at=at(day, hour),
        direction=direction,
        amount=Decimal(amount),
        channel=channel,
        cash=cash,
    )


def pack(**overrides) -> RulePack:
    return RulePack(pack_id="test-pack", version="1.0", **overrides)


# ---------------------------------------------------------------------------
# Structuring
# ---------------------------------------------------------------------------


def test_structuring_multi_day_window():
    txns = [
        txn("T1", date(2026, 3, 2), "9500", cash=True, channel="branch"),
        txn("T2", date(2026, 3, 4), "9600", cash=True, channel="branch"),
        txn("T3", date(2026, 3, 6), "9700", cash=True, channel="branch"),
    ]
    drafts = check_structuring(txns, pack())
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.variant == "multi_day"
    assert draft.transaction_ids == ["T1", "T2", "T3"]
    assert draft.figures["total_amount"] == "28800"
    assert draft.figures["transaction_count"] == "3"
    assert draft.window_start == date(2026, 3, 2)


def test_structuring_same_day_takes_precedence():
    day = date(2026, 3, 2)
    txns = [
        txn("T1", day, "9900", cash=True, channel="branch", hour=9),
        txn("T2", day, "9950", cash=True, channel="branch", hour=12),
        txn("T3", day, "9800", cash=True, channel="branch", hour=15),
    ]
    drafts = check_structuring(txns, pack())
    assert len(drafts) == 1
    assert drafts[0].variant == "same_day"
    assert drafts[0].figures["total_amount"] == "29650"


def test_structuring_band_edges_and_cash_only():
    txns = [
        # below the band: invisible to the rule
        txn("T1", date(2026, 3, 2), "8999.99", cash=True, channel="branch"),
        # exactly at the band floor: counts
        txn("T2", date(2026, 3, 2), "9000", cash=True, channel="branch"),
        txn("T3", date(2026, 3, 3), "9100", cash=True, channel="branch"),
        txn("T4", date(2026, 3, 4), "9200", cash=True, channel="branch"),
        # at the CTR threshold itself: reportable, not structuring band
        txn("T5", date(2026, 3, 4), "10000", cash=True, channel="branch"),
        # in-band amount but not cash: invisible
        txn("T6", date(2026, 3, 4), "9500", cash=False, channel="wire"),
    ]
    drafts = check_structuring(txns, pack())
    assert len(drafts) == 1
    assert drafts[0].transaction_ids == ["T2", "T3", "T4"]
    assert drafts[0].figures["total_amount"] == "27300"


def test_structuring_count_gate_two_large_deposits_do_not_fire():
    txns = [
        txn("T1", date(2026, 3, 2), "9900", cash=True, channel="branch"),
        txn("T2", date(2026, 3, 3), "9900", cash=True, channel="branch"),
    ]
    assert check_structuring(txns, pack()) == []


def test_structuring_cash_out_is_its_own_aggregation():
    txns = [
        txn("T1", date(2026, 3, 2), "9500", direction="debit", cash=True, channel="branch"),
        txn("T2", date(2026, 3, 3), "9500", direction="debit", cash=True, channel="branch"),
        txn("T3", date(2026, 3, 4), "9500", direction="debit", cash=True, channel="branch"),
    ]
    drafts = check_structuring(txns, pack())
    assert len(drafts) == 1
    assert drafts[0].figures["direction"] == "debit"


def test_negative_control_regular_payroll_adjacent_deposits():
    """The scope's named control: a business depositing 9,500 in
    cash every ten days for months. Each deposit sits in the band,
    but no window aggregates over the threshold and no window ever
    holds the minimum count — so nothing fires, on any check."""
    txns = []
    day = date(2026, 1, 5)
    for i in range(9):
        txns.append(
            txn(f"C{i}", day, "9500", cash=True, channel="branch")
        )
        day += timedelta(days=10)
    profile = AccountProfile(
        account_id=ACCOUNT,
        customer_id="CUST-T-1",
        opened_on=date(2025, 12, 1),
        account_type="business_checking",
    )
    assert run_all_checks(txns, profile, pack()) == []


# ---------------------------------------------------------------------------
# Velocity
# ---------------------------------------------------------------------------


def _velocity_stream():
    txns = []
    first = date(2026, 1, 1)
    for i in range(60):  # baseline: one transaction every four days
        txns.append(txn(f"B{i}", first + timedelta(days=4 * i), "100.00"))
    burst_first = first + timedelta(days=250)
    for j in range(10):  # observation: ten in the last three days
        txns.append(
            txn(f"O{j}", burst_first + timedelta(days=j % 3), "250.00", hour=9 + j)
        )
    return txns, burst_first + timedelta(days=2)


def test_velocity_fires_with_exact_figures():
    txns, last_day = _velocity_stream()
    drafts = check_velocity(txns, pack())
    assert len(drafts) == 1
    draft = drafts[0]
    figures = draft.figures
    assert figures["observation_count"] == "10"
    assert figures["observation_amount"] == "2500.00"
    assert figures["baseline_count"] == "60"
    assert figures["baseline_amount"] == "6000.00"
    baseline_days = int(figures["baseline_days"])
    expected = (Decimal(10) * baseline_days / (Decimal(60) * 7)).quantize(
        Decimal("0.0001")
    )
    assert figures["count_multiple"] == format(expected, "f")
    assert draft.window_end == last_day
    assert len(draft.transaction_ids) == 10


def test_velocity_needs_a_real_baseline():
    txns = [
        txn(f"T{i}", date(2026, 3, 1) + timedelta(days=i), "100.00")
        for i in range(20)
    ]
    assert check_velocity(txns, pack()) == []  # 19 days of history is not a baseline


def test_velocity_steady_account_stays_quiet():
    txns = [
        txn(f"T{i}", date(2026, 1, 1) + timedelta(days=i), "100.00")
        for i in range(120)
    ]
    assert check_velocity(txns, pack()) == []


# ---------------------------------------------------------------------------
# Dormancy-then-burst
# ---------------------------------------------------------------------------


def test_dormancy_then_burst_after_silence():
    txns = [
        txn("T1", date(2025, 1, 10), "100.00"),
        txn("T2", date(2026, 3, 1), "6000.00"),
        txn("T3", date(2026, 3, 2), "7000.00"),
    ]
    drafts = check_dormancy_then_burst(txns, PROFILE, pack())
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.figures["gap_days"] == str((date(2026, 3, 1) - date(2025, 1, 10)).days)
    assert draft.figures["burst_amount"] == "13000.00"
    assert draft.transaction_ids == ["T2", "T3"]


def test_dormancy_gap_can_start_at_account_opening():
    profile = AccountProfile(
        account_id=ACCOUNT,
        customer_id="CUST-T-1",
        opened_on=date(2025, 1, 1),
        account_type="personal_checking",
    )
    txns = [
        txn("T1", date(2025, 9, 1), "8000.00"),
        txn("T2", date(2025, 9, 1), "9000.00", hour=15),
    ]
    drafts = check_dormancy_then_burst(txns, profile, pack())
    assert len(drafts) == 1
    assert drafts[0].figures["gap_start"] == "2025-01-01"
    assert drafts[0].figures["gap_days"] == "243"


def test_dormancy_small_resumption_stays_quiet():
    txns = [
        txn("T1", date(2025, 1, 10), "100.00"),
        txn("T2", date(2026, 3, 1), "150.00"),  # one small transaction is not a burst
    ]
    assert check_dormancy_then_burst(txns, PROFILE, pack()) == []


# ---------------------------------------------------------------------------
# Round amounts
# ---------------------------------------------------------------------------


def test_round_amount_fires_on_dominant_round_stream():
    txns = []
    day = date(2026, 3, 1)
    for i, amount in enumerate(
        ["10000", "10000", "10000", "25000", "25000", "5000", "5000", "5000"]
    ):
        txns.append(txn(f"R{i}", day + timedelta(days=i), amount))
    for j, amount in enumerate(["123.45", "987.10", "45.00", "2300.75"]):
        txns.append(txn(f"N{j}", day + timedelta(days=10 + j), amount, direction="debit"))
    drafts = check_round_amount(txns, pack())
    assert len(drafts) == 1
    figures = drafts[0].figures
    assert figures["round_count"] == "8"
    assert figures["total_count"] == "12"
    assert figures["round_total"] == "95000"
    assert figures["round_share"] == "0.6667"


def test_round_amount_varied_business_stream_stays_quiet():
    txns = [
        txn(f"T{i}", date(2026, 3, 1) + timedelta(days=i), amount)
        for i, amount in enumerate(
            ["2500.00", "10000", "4321.10", "999.99", "5000", "12345.67"]
        )
    ]
    # two round transactions out of six: neither count nor share clears
    assert check_round_amount(txns, pack()) == []


# ---------------------------------------------------------------------------
# Rapid in-out
# ---------------------------------------------------------------------------


def test_rapid_in_out_full_pass_through():
    day = date(2026, 3, 2)
    txns = [
        txn("C1", day, "50000", hour=9),
        txn("D1", day, "20000", direction="debit", hour=14),
        txn("D2", day + timedelta(days=1), "26000", direction="debit", hour=9),
    ]
    drafts = check_rapid_in_out(txns, pack())
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.transaction_ids == ["C1", "D1", "D2"]
    assert draft.figures["credit_amount"] == "50000"
    assert draft.figures["disbursed_amount"] == "46000"
    assert draft.figures["retained_amount"] == "4000"


def test_rapid_in_out_partial_retention_stays_quiet():
    day = date(2026, 3, 2)
    txns = [
        txn("C1", day, "50000", hour=9),
        txn("D1", day, "40000", direction="debit", hour=14),  # 80% out, 20% kept
    ]
    assert check_rapid_in_out(txns, pack()) == []


def test_rapid_in_out_outside_window_stays_quiet():
    day = date(2026, 3, 2)
    txns = [
        txn("C1", day, "50000", hour=9),
        txn("D1", day + timedelta(days=5), "49000", direction="debit", hour=9),
    ]
    assert check_rapid_in_out(txns, pack()) == []


def test_rapid_in_out_debit_splits_across_credits():
    day = date(2026, 3, 2)
    txns = [
        txn("C1", day, "30000", hour=9),
        txn("C2", day, "30000", hour=10),
        txn("D1", day, "50000", direction="debit", hour=20),
    ]
    drafts = check_rapid_in_out(txns, pack())
    assert len(drafts) == 1  # C1 fully passed through; C2 only 2/3
    assert drafts[0].transaction_ids == ["C1", "D1"]
    assert drafts[0].figures["retained_amount"] == "0"


def test_rapid_in_out_small_credit_ignored():
    day = date(2026, 3, 2)
    txns = [
        txn("C1", day, "9500", hour=9),
        txn("D1", day, "9500", direction="debit", hour=10),
    ]
    assert check_rapid_in_out(txns, pack()) == []


# ---------------------------------------------------------------------------
# The service: packs, ingestion, runs
# ---------------------------------------------------------------------------


class _Stack:
    def __init__(self, tmp_path: Path):
        self.store = InMemoryCaseStore()
        self.objects = LocalObjectStore(tmp_path / "objects")
        self.evidence = EvidenceService(self.store, self.objects)
        self.typologies = TypologyService(self.store, self.store, self.evidence)
        feed = ListAlertFeed(
            [
                Alert(
                    alert_id="ALRT-TYPO-1",
                    rule_id="TM-STRUCTURING-01",
                    customer_id="CUST-T-1",
                    account_id=ACCOUNT,
                    severity="high",
                    detected_on="2026-03-10",
                    summary="Typology service test case.",
                )
            ]
        )
        self.intake = IntakeService(self.store, feed, self.evidence)
        self.case = self.intake.open_case("ALRT-TYPO-1")


def _structuring_stream() -> list[Transaction]:
    return [
        txn("S1", date(2026, 3, 2), "9500", cash=True, channel="branch"),
        txn("S2", date(2026, 3, 4), "9600", cash=True, channel="branch"),
        txn("S3", date(2026, 3, 6), "9700", cash=True, channel="branch"),
    ]


def test_rule_pack_registration_is_immutable(tmp_path):
    stack = _Stack(tmp_path)
    registered = stack.typologies.register_rule_pack(pack())
    assert registered.content_hash
    again = stack.typologies.register_rule_pack(pack())
    assert again.content_hash == registered.content_hash  # idempotent
    with pytest.raises(RulePackImmutableError):
        stack.typologies.register_rule_pack(pack(structuring_band_low=Decimal("8000")))


def test_rule_pack_declared_hash_mismatch_refused(tmp_path):
    stack = _Stack(tmp_path)
    bad = pack().model_copy(update={"content_hash": "0" * 64})
    with pytest.raises(TypologyError):
        stack.typologies.register_rule_pack(bad)


def test_run_requires_ingested_transactions_and_known_pack(tmp_path):
    stack = _Stack(tmp_path)
    stack.typologies.register_rule_pack(pack())
    with pytest.raises(NoTransactionsError):
        stack.typologies.run_typologies(stack.case.case_id, "test-pack", "1.0", actor="svc")
    stack.typologies.ingest_transactions(
        stack.case.case_id,
        _structuring_stream(),
        source_ref="core-banking:ACCT-T-1",
        actor="svc",
    )
    with pytest.raises(RulePackNotFoundError):
        stack.typologies.run_typologies(stack.case.case_id, "nope", "9.9", actor="svc")


def test_ingestion_is_evidence_backed_and_idempotent(tmp_path):
    stack = _Stack(tmp_path)
    stack.typologies.register_rule_pack(pack())
    before = len(stack.store.list_evidence(stack.case.case_id))
    batch = stack.typologies.ingest_transactions(
        stack.case.case_id,
        _structuring_stream(),
        source_ref="core-banking:ACCT-T-1",
        actor="svc",
    )
    assert batch.evidence_seq is not None
    items = stack.store.list_evidence(stack.case.case_id)
    assert len(items) == before + 1
    assert items[-1].kind == "transaction_batch"
    assert stack.evidence.verify_chain(stack.case.case_id)
    again = stack.typologies.ingest_transactions(
        stack.case.case_id,
        _structuring_stream(),
        source_ref="core-banking:ACCT-T-1",
        actor="svc",
    )
    assert again.batch_id == batch.batch_id
    assert len(stack.store.list_evidence(stack.case.case_id)) == before + 1


def test_ingestion_refuses_foreign_or_mixed_accounts(tmp_path):
    stack = _Stack(tmp_path)
    foreign = [txn("X1", date(2026, 3, 2), "100", account="ACCT-OTHER")]
    with pytest.raises(TransactionMismatchError):
        stack.typologies.ingest_transactions(
            stack.case.case_id, foreign, source_ref="feed", actor="svc"
        )
    mixed = _structuring_stream() + foreign
    with pytest.raises(TransactionMismatchError):
        stack.typologies.ingest_transactions(
            stack.case.case_id, mixed, source_ref="feed", actor="svc"
        )


def test_run_persists_findings_as_records_and_evidence(tmp_path):
    stack = _Stack(tmp_path)
    stack.typologies.register_rule_pack(pack())
    feed = ListTransactionFeed([SERVICE_PROFILE], {ACCOUNT: _structuring_stream()})
    stack.typologies.ingest_from_source(stack.case.case_id, feed, actor="svc")
    run = stack.typologies.run_typologies(
        stack.case.case_id, "test-pack", "1.0", actor="svc"
    )
    assert run.finding_count == 1
    assert run.evidence_seq is not None
    findings = stack.typologies.list_findings(stack.case.case_id)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.typology_id == "structuring"
    assert finding.rule_pack_id == "test-pack"
    assert finding.rule_pack_version == "1.0"
    assert finding.figures["total_amount"] == "28800"
    kinds = [i.kind for i in stack.store.list_evidence(stack.case.case_id)]
    assert "typology_findings" in kinds
    assert stack.evidence.verify_chain(stack.case.case_id)


def test_rerun_same_pack_same_input_is_idempotent(tmp_path):
    stack = _Stack(tmp_path)
    stack.typologies.register_rule_pack(pack())
    feed = ListTransactionFeed([SERVICE_PROFILE], {ACCOUNT: _structuring_stream()})
    stack.typologies.ingest_from_source(stack.case.case_id, feed, actor="svc")
    first = stack.typologies.run_typologies(
        stack.case.case_id, "test-pack", "1.0", actor="svc"
    )
    evidence_count = len(stack.store.list_evidence(stack.case.case_id))
    second = stack.typologies.run_typologies(
        stack.case.case_id, "test-pack", "1.0", actor="svc"
    )
    assert second.run_id == first.run_id
    assert len(stack.typologies.list_findings(stack.case.case_id)) == 1
    assert len(stack.store.list_evidence(stack.case.case_id)) == evidence_count
    assert len(stack.store.list_typology_runs(stack.case.case_id)) == 1


def test_new_pack_version_adds_a_distinguishable_run(tmp_path):
    stack = _Stack(tmp_path)
    stack.typologies.register_rule_pack(pack())  # band starts at 9000
    stack.typologies.register_rule_pack(
        RulePack(pack_id="test-pack", version="2.0", structuring_band_low=Decimal("8000"))
    )
    stream = [
        txn("S1", date(2026, 3, 2), "8700", cash=True, channel="branch"),
        txn("S2", date(2026, 3, 3), "8800", cash=True, channel="branch"),
        txn("S3", date(2026, 3, 4), "8900", cash=True, channel="branch"),
    ]
    feed = ListTransactionFeed([SERVICE_PROFILE], {ACCOUNT: stream})
    stack.typologies.ingest_from_source(stack.case.case_id, feed, actor="svc")
    run_v1 = stack.typologies.run_typologies(
        stack.case.case_id, "test-pack", "1.0", actor="svc"
    )
    assert run_v1.finding_count == 0  # below the v1 band: quiet
    run_v2 = stack.typologies.run_typologies(
        stack.case.case_id, "test-pack", "2.0", actor="svc"
    )
    assert run_v2.run_id != run_v1.run_id
    assert run_v2.finding_count == 1
    findings = stack.typologies.list_findings(stack.case.case_id)
    assert len(findings) == 1
    assert findings[0].rule_pack_version == "2.0"
    assert findings[0].figures["total_amount"] == "26400"
    assert len(stack.store.list_typology_runs(stack.case.case_id)) == 2


def test_sql_store_typology_round_trip(tmp_path):
    store = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects)
    typologies = TypologyService(store, store, evidence)
    feed = ListAlertFeed(
        [
            Alert(
                alert_id="ALRT-TYPO-SQL",
                rule_id="TM-STRUCTURING-01",
                customer_id="CUST-T-1",
                account_id=ACCOUNT,
                severity="high",
                detected_on="2026-03-10",
                summary="SQL typology round trip.",
            )
        ]
    )
    intake = IntakeService(store, feed, evidence)
    case = intake.open_case("ALRT-TYPO-SQL")
    typologies.register_rule_pack(pack())
    txn_feed = ListTransactionFeed([SERVICE_PROFILE], {ACCOUNT: _structuring_stream()})
    typologies.ingest_from_source(case.case_id, txn_feed, actor="svc")
    run = typologies.run_typologies(case.case_id, "test-pack", "1.0", actor="svc")
    assert run.finding_count == 1

    reopened = SqlCaseStore.sqlite(tmp_path / "aml.db", REPO_ROOT / "migrations")
    persisted = reopened.list_findings(case.case_id)
    assert len(persisted) == 1
    assert persisted[0].figures["total_amount"] == "28800"
    assert persisted[0].rule_pack_version == "1.0"
    assert len(reopened.list_transactions(case.case_id)) == 3
    assert reopened.get_account_profile(ACCOUNT) is not None


# ---------------------------------------------------------------------------
# The reference feed: the seed alerts' patterns, actually in the streams
# ---------------------------------------------------------------------------


def test_reference_feed_streams_grade_as_designed():
    feed = ReferenceTransactionFeed(REPO_ROOT / "data" / "transaction_streams.json")
    reference_pack = RulePack(pack_id="harborline-typologies", version="2026.10.1")

    def drafts_for(account: str):
        return run_all_checks(
            feed.get_transactions(account), feed.get_profile(account), reference_pack
        )

    structuring = drafts_for("ACCT-5001")
    assert [(d.typology_id, d.variant) for d in structuring] == [
        ("structuring", "multi_day")
    ]
    assert structuring[0].transaction_ids == [
        "TXN-9001",
        "TXN-9002",
        "TXN-9003",
        "TXN-9004",
        "TXN-9005",
    ]
    assert structuring[0].figures["total_amount"] == "47700.00"

    velocity = drafts_for("ACCT-5002")
    assert [d.typology_id for d in velocity] == ["velocity"]
    assert velocity[0].figures["observation_count"] == "14"
    assert velocity[0].figures["observation_amount"] == "50646.90"
    assert velocity[0].figures["count_multiple"] == "31.3750"

    dormant = drafts_for("ACCT-5003")
    assert [d.typology_id for d in dormant] == [
        "dormancy_then_burst",
        "rapid_in_out",
    ]
    assert dormant[0].figures["gap_days"] == "798"
    assert dormant[1].figures["retained_amount"] == "500.00"

    assert drafts_for("ACCT-5004") == []  # the clean control stays clean
