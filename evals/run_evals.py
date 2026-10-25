"""Eval gate for Blueprint #15 — AML Alert Investigation & Case File Agent.

Runs the scenarios against an in-memory stack (no disk, no network,
no keys) and reports the counters that exist so far. Later rounds
extend this gate: citation support (R4/R6), clock compliance (R8),
injection quarantine (R10), trap suites (R15).

Zero-tolerance counters:
  - cases closed without an analyst disposition ... must be 0
  - unlawful transitions accepted .................. must be 0
  - evidence chains failing verification ........... must be 0
  - duplicate cases per alert ...................... must be 0
  - screening runs accepted without a pin (R2) ..... must be 0
  - stale screenings left unflagged (R2) ........... must be 0
  - plain closes accepted over a sanctions hit (R2)  must be 0
  - planted typologies missed (R3) ................. must be 0
  - typology false fires on controls (R3) .......... must be 0
  - typology figure mismatches (R3) ................ must be 0
  - typology runs not idempotent (R3) .............. must be 0
  - findings without their rule version (R3) ....... must be 0
  - rule-pack mutations accepted (R3) .............. must be 0
  - typology runs over unstored data accepted (R3).. must be 0

Exit code 0 iff the gate passes.
"""

from __future__ import annotations

import sys
import tempfile
from datetime import date, datetime, time, timedelta, timezone  # noqa: E402
from decimal import Decimal  # noqa: E402
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aml_investigations.errors import (  # noqa: E402
    IllegalTransitionError,
    NoTransactionsError,
    RulePackImmutableError,
    ScreeningPinRequiredError,
)
from aml_investigations.evidence import EvidenceService  # noqa: E402
from aml_investigations.intake import IntakeService, ListAlertFeed  # noqa: E402
from aml_investigations.models import (  # noqa: E402
    AccountProfile,
    Alert,
    CaseStatus,
    Disposition,
    HitStatus,
    ListEntry,
    ListKind,
    ListSnapshot,
    RulePack,
    Transaction,
)
from aml_investigations.object_store import LocalObjectStore  # noqa: E402
from aml_investigations.screening import ScreeningService  # noqa: E402
from aml_investigations.stores import InMemoryCaseStore  # noqa: E402
from aml_investigations.transactions import ListTransactionFeed  # noqa: E402
from aml_investigations.typologies import TypologyService  # noqa: E402
from aml_investigations.workflow import CaseWorkflow  # noqa: E402

ALERTS = [
    Alert(
        alert_id="EVAL-001",
        rule_id="TM-STRUCTURING-01",
        customer_id="CUST-1001",
        account_id="ACCT-5001",
        severity="high",
        detected_on="2026-10-20",
        summary="Planted structuring pattern.",
    ),
    Alert(
        alert_id="EVAL-002",
        rule_id="TM-VELOCITY-03",
        customer_id="CUST-1002",
        account_id="ACCT-5002",
        severity="medium",
        detected_on="2026-10-21",
        summary="Planted velocity pattern.",
    ),
    Alert(
        alert_id="EVAL-003",
        rule_id="TM-STRUCTURING-01",
        customer_id="CUST-1004",
        account_id="ACCT-5004",
        severity="low",
        detected_on="2026-10-22",
        summary="Clean control.",
    ),
    Alert(
        alert_id="EVAL-004",
        rule_id="TM-STRUCTURING-01",
        customer_id="CUST-1001",
        account_id="ACCT-5001",
        severity="high",
        detected_on="2026-10-22",
        summary="Screening delta trap: clean on list v1, listed in v2.",
        raw={
            "customer_name": "Daniel Okafor",
            "customer_dob": "1985-03-04",
            "customer_identifiers": ["PP-NG-2210"],
            "counterparties": [{"name": "Viktor Petrov", "dob": "1979-06-02"}],
        },
    ),
]


def _snapshot(kind, version, published_at, entries):
    return ListSnapshot(
        list_kind=kind,
        version=version,
        published_at=published_at,
        source_note="eval feed",
        entries=entries,
    )


SANCTIONS_V1 = _snapshot(
    ListKind.SANCTIONS,
    "2026.10.1",
    "2026-10-01T00:00:00Z",
    [
        ListEntry(
            entry_id="SDN-1001",
            name="Viktor Petrov",
            dob="1962-04-11",
            identifiers=["PP-XK-4471"],
        )
    ],
)
SANCTIONS_V2 = _snapshot(
    ListKind.SANCTIONS,
    "2026.10.2",
    "2026-10-24T00:00:00Z",
    SANCTIONS_V1.entries
    + [
        ListEntry(
            entry_id="SDN-1004",
            name="Daniel Okafor",
            dob="1985-03-04",
            identifiers=["PP-NG-2210"],
        )
    ],
)
PEP_V1 = _snapshot(
    ListKind.PEP,
    "2026.10.1",
    "2026-10-01T00:00:00Z",
    [ListEntry(entry_id="PEP-2001", name="Helena Voss", dob="1968-09-19")],
)


def _typo_alert(alert_id: str, account_id: str, detected_on: str) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="TM-TYPOLOGY-EVAL",
        customer_id="CUST-EVAL",
        account_id=account_id,
        severity="high",
        detected_on=detected_on,
        summary="Typology engine eval case.",
    )


TYPO_ALERTS = [
    _typo_alert("EVAL-101", "ACCT-E101", "2026-03-07"),
    _typo_alert("EVAL-102", "ACCT-E102", "2026-03-04"),
    _typo_alert("EVAL-103", "ACCT-E103", "2026-09-11"),
    _typo_alert("EVAL-104", "ACCT-E104", "2026-10-22"),
    _typo_alert("EVAL-105", "ACCT-E105", "2026-03-15"),
    _typo_alert("EVAL-106", "ACCT-E106", "2026-03-27"),
    _typo_alert("EVAL-107", "ACCT-E107", "2026-03-05"),
]


def main() -> int:
    counters = {
        "cases_opened": 0,
        "closed_without_disposition": 0,
        "unlawful_transitions_accepted": 0,
        "chains_failed": 0,
        "duplicate_cases": 0,
        "audit_gaps": 0,
        "screening_without_pin": 0,
        "stale_screening_unflagged": 0,
        "sanctions_close_blocked_violations": 0,
        "delta_hits_missed": 0,
        # R3 typology counters
        "typology_cases_run": 0,
        "typology_findings_verified": 0,
        "typology_expected_missed": 0,
        "typology_false_fires": 0,
        "typology_figure_mismatches": 0,
        "typology_runs_not_idempotent": 0,
        "findings_without_rule_version": 0,
        "rule_pack_mutations_accepted": 0,
        "typology_run_without_data_accepted": 0,
    }

    store = InMemoryCaseStore()
    objects = LocalObjectStore(Path(tempfile.mkdtemp(prefix="aml-evals-")))
    evidence = EvidenceService(store, objects)
    workflow = CaseWorkflow(store, screening_store=store)
    intake = IntakeService(store, ListAlertFeed(list(ALERTS)), evidence)
    screening = ScreeningService(store, store, evidence)

    # Scenario 1: every alert opens exactly one case, even on re-delivery.
    case_ids = {}
    for alert in ALERTS:
        case = intake.open_case(alert.alert_id)
        again = intake.open_case(alert.alert_id)
        case_ids[alert.alert_id] = case.case_id
        counters["cases_opened"] += 1
        if again.case_id != case.case_id:
            counters["duplicate_cases"] += 1

    # Scenario 2: no case can be closed or SAR-filed without a
    # disposition, from any state, and no unlawful jump is accepted.
    for alert in ALERTS:
        case_id = case_ids[alert.alert_id]
        for target in (CaseStatus.CLOSED, CaseStatus.FILED_SAR, CaseStatus.INVESTIGATING):
            try:
                workflow.transition(case_id, target, actor="eval-probe")
                counters["unlawful_transitions_accepted"] += 1
            except IllegalTransitionError:
                pass

    # Scenario 3: the lawful path works and closes only via the gate.
    sar_case = case_ids["EVAL-001"]
    for target in (
        CaseStatus.ASSEMBLING,
        CaseStatus.INVESTIGATING,
        CaseStatus.AWAITING_ANALYST,
    ):
        workflow.transition(sar_case, target, actor="investigation-service")
    try:
        workflow.transition(sar_case, CaseStatus.FILED_SAR, actor="analyst:j.rivera")
        counters["closed_without_disposition"] += 1
    except IllegalTransitionError:
        pass
    workflow.transition(
        sar_case,
        CaseStatus.FILED_SAR,
        actor="analyst:j.rivera",
        disposition=Disposition(
            analyst="j.rivera",
            decision="file_sar",
            reason_code="STRUCTURING_CONFIRMED",
        ),
    )

    # Scenario 4: every case's evidence chain verifies, and every case
    # carries a complete audit trail (opened at minimum).
    for case_id in case_ids.values():
        try:
            evidence.verify_chain(case_id)
        except Exception:
            counters["chains_failed"] += 1
        events = [e.event for e in store.list_audit(case_id)]
        if "case_opened" not in events:
            counters["audit_gaps"] += 1

    # Scenario 5 (R2): the stale-list trap. The EVAL-004 case screens
    # clean on sanctions 2026.10.1 (its counterparty is a namesake —
    # same name as a listed person, different date of birth). The v2
    # delta adds the customer himself: ingest must flag the case
    # STALE_SCREENING, the re-screen must surface the hit, and a
    # plain close over the open hit must be refused.
    delta_case = case_ids["EVAL-004"]
    screening.ingest_snapshot(SANCTIONS_V1, actor="eval-feed")
    screening.ingest_snapshot(PEP_V1, actor="eval-feed")

    # 5a: screening without a pinned snapshot set is refused.
    try:
        screening.screen_case(delta_case, {}, actor="eval-probe")
        counters["screening_without_pin"] += 1
    except ScreeningPinRequiredError:
        pass

    # 5b: clean on v1 — no open hits; the namesake clears with a reason.
    run_v1 = screening.screen_case(
        delta_case,
        {ListKind.SANCTIONS: "2026.10.1", ListKind.PEP: "2026.10.1"},
        actor="screening-service",
    )
    if run_v1.open_hits != 0 or run_v1.cleared_hits != 1:
        counters["delta_hits_missed"] += 1

    # 5c: the v2 delta lands — the case must be flagged stale.
    screening.ingest_snapshot(SANCTIONS_V2, actor="eval-feed")
    flagged = store.get_case(delta_case)
    if not flagged.screening_stale or "STALE_SCREENING" not in flagged.flags:
        counters["stale_screening_unflagged"] += 1

    # 5d: re-screen on v2 — the customer surfaces as a sanctions hit,
    # the stale flag clears, and the SANCTIONS_HIT flag is visible.
    run_v2 = screening.screen_case(
        delta_case,
        {ListKind.SANCTIONS: "2026.10.2", ListKind.PEP: "2026.10.1"},
        actor="screening-service",
    )
    delta_hits = [
        h
        for h in store.list_hits(delta_case)
        if h.run_id == run_v2.run_id
        and h.list_kind is ListKind.SANCTIONS
        and h.status is HitStatus.OPEN
    ]
    refreshed = store.get_case(delta_case)
    if (
        len(delta_hits) != 1
        or delta_hits[0].entry_id != "SDN-1004"
        or refreshed.screening_stale
        or "SANCTIONS_HIT" not in refreshed.flags
    ):
        counters["delta_hits_missed"] += 1

    # 5e: a plain close over the unresolved hit is refused; the
    # lawful escalate path works.
    for target in (
        CaseStatus.ASSEMBLING,
        CaseStatus.INVESTIGATING,
        CaseStatus.AWAITING_ANALYST,
    ):
        workflow.transition(delta_case, target, actor="investigation-service")
    try:
        workflow.transition(
            delta_case,
            CaseStatus.CLOSED,
            actor="analyst:j.rivera",
            disposition=Disposition(
                analyst="j.rivera", decision="close", reason_code="BENIGN"
            ),
        )
        counters["sanctions_close_blocked_violations"] += 1
    except IllegalTransitionError:
        pass
    workflow.transition(
        delta_case,
        CaseStatus.ESCALATED,
        actor="analyst:j.rivera",
        disposition=Disposition(
            analyst="j.rivera", decision="escalate", reason_code="SANCTIONS_HIT"
        ),
    )
    try:
        evidence.verify_chain(delta_case)
    except Exception:
        counters["chains_failed"] += 1

    # -- Scenario 6 (R3): the typology engine grades exactly. -------------
    # Every planted pattern must be found with the exact transaction
    # set and exact Decimal figures; the control accounts must stay
    # silent; a re-run must not duplicate; every finding must carry
    # its rule-pack version.
    typologies = TypologyService(store, store, evidence)
    pack_v1 = RulePack(pack_id="eval-pack", version="1.0")
    pack_v2 = RulePack(
        pack_id="eval-pack", version="2.0", structuring_band_low=Decimal("8000")
    )
    typologies.register_rule_pack(pack_v1)
    typologies.register_rule_pack(pack_v2)
    try:
        typologies.register_rule_pack(
            RulePack(pack_id="eval-pack", version="1.0", structuring_min_count=9)
        )
        counters["rule_pack_mutations_accepted"] += 1
    except RulePackImmutableError:
        pass

    def etxn(tid, account, day, amount, direction="credit", cash=False,
             channel="wire", hour=10):
        return Transaction(
            transaction_id=tid,
            account_id=account,
            posted_at=datetime.combine(day, time(hour, 0), tzinfo=timezone.utc),
            direction=direction,
            amount=Decimal(amount),
            channel=channel,
            cash=cash,
        )

    typo_intake = IntakeService(store, ListAlertFeed(TYPO_ALERTS), evidence)

    def run_typo_case(alert_id, profile, stream, version="1.0"):
        case_id = typo_intake.open_case(alert_id).case_id
        feed = ListTransactionFeed([profile], {profile.account_id: stream})
        typologies.ingest_from_source(case_id, feed, actor="eval-feed")
        run = typologies.run_typologies(
            case_id, "eval-pack", version, actor="eval-runner"
        )
        counters["typology_cases_run"] += 1
        return case_id, run

    def check_findings(case_id, run_id, expected):
        """expected: list of (typology_id, variant, txn_ids, {figure: value})."""
        actual = [
            f for f in typologies.list_findings(case_id) if f.run_id == run_id
        ]
        seen = set()
        for typology_id, variant, txn_ids, figures in expected:
            match = next(
                (
                    f
                    for f in actual
                    if f.typology_id == typology_id and f.variant == variant
                ),
                None,
            )
            if match is None:
                counters["typology_expected_missed"] += 1
                continue
            seen.add(match.finding_id)
            if match.transaction_ids != txn_ids:
                counters["typology_expected_missed"] += 1
                continue
            bad = [k for k, v in figures.items() if match.figures.get(k) != v]
            if bad:
                counters["typology_figure_mismatches"] += 1
                continue
            if not match.rule_pack_id or not match.rule_pack_version:
                counters["findings_without_rule_version"] += 1
                continue
            counters["typology_findings_verified"] += 1
        counters["typology_false_fires"] += len(
            [f for f in actual if f.finding_id not in seen]
        )

    def profile(account, opened):
        return AccountProfile(
            account_id=account,
            customer_id="CUST-EVAL",
            opened_on=opened,
            account_type="business_checking",
        )

    # E101: structuring, multi-day variant.
    case_id, run = run_typo_case(
        "EVAL-101",
        profile("ACCT-E101", date(2026, 2, 1)),
        [
            etxn("E101-1", "ACCT-E101", date(2026, 3, 2), "9500", cash=True, channel="branch"),
            etxn("E101-2", "ACCT-E101", date(2026, 3, 4), "9600", cash=True, channel="branch"),
            etxn("E101-3", "ACCT-E101", date(2026, 3, 6), "9700", cash=True, channel="branch"),
        ],
    )
    check_findings(case_id, run.run_id, [
        ("structuring", "multi_day", ["E101-1", "E101-2", "E101-3"],
         {"total_amount": "28800", "transaction_count": "3"}),
    ])

    # E102: structuring, same-day variant.
    case_id, run = run_typo_case(
        "EVAL-102",
        profile("ACCT-E102", date(2026, 2, 1)),
        [
            etxn("E102-1", "ACCT-E102", date(2026, 3, 3), "9900", cash=True, channel="branch", hour=9),
            etxn("E102-2", "ACCT-E102", date(2026, 3, 3), "9950", cash=True, channel="branch", hour=12),
            etxn("E102-3", "ACCT-E102", date(2026, 3, 3), "9800", cash=True, channel="branch", hour=15),
        ],
    )
    check_findings(case_id, run.run_id, [
        ("structuring", "same_day", ["E102-1", "E102-2", "E102-3"],
         {"total_amount": "29650"}),
    ])

    # E103: velocity against the account's own baseline.
    stream = []
    first = date(2026, 1, 1)
    for i in range(60):
        stream.append(
            etxn(f"E103-B{i}", "ACCT-E103", first + timedelta(days=4 * i), "100.00")
        )
    burst_first = first + timedelta(days=250)
    for j in range(10):
        stream.append(
            etxn(f"E103-O{j}", "ACCT-E103", burst_first + timedelta(days=j % 3),
                 "250.00", hour=9 + j)
        )
    # Findings list transactions chronologically (store order).
    burst_ids = [
        t.transaction_id
        for t in sorted(
            (t for t in stream if t.transaction_id.startswith("E103-O")),
            key=lambda t: t.posted_at,
        )
    ]
    case_id, run = run_typo_case(
        "EVAL-103", profile("ACCT-E103", date(2025, 12, 15)), stream
    )
    check_findings(case_id, run.run_id, [
        ("velocity", None, burst_ids,
         {"observation_count": "10", "observation_amount": "2500.00",
          "baseline_count": "60", "baseline_amount": "6000.00",
          "count_multiple": "5.8571", "amount_multiple": "14.6429"}),
    ])

    # E104: dormancy-then-burst plus rapid in-out on the same movement.
    case_id, run = run_typo_case(
        "EVAL-104",
        profile("ACCT-E104", date(2024, 6, 3)),
        [
            etxn("E104-1", "ACCT-E104", date(2024, 6, 5), "2400.00"),
            etxn("E104-2", "ACCT-E104", date(2024, 8, 14), "96.20", direction="debit"),
            etxn("E104-3", "ACCT-E104", date(2026, 10, 21), "85000.00", hour=9),
            etxn("E104-4", "ACCT-E104", date(2026, 10, 21), "84500.00", direction="debit", hour=16),
        ],
    )
    check_findings(case_id, run.run_id, [
        ("dormancy_then_burst", None, ["E104-3", "E104-4"],
         {"gap_days": "798", "burst_amount": "169500.00"}),
        ("rapid_in_out", None, ["E104-3", "E104-4"],
         {"credit_amount": "85000.00", "disbursed_amount": "84500.00",
          "retained_amount": "500.00", "pass_through": "0.9941"}),
    ])

    # E105: round-amount dominance.
    stream = []
    base = date(2026, 3, 1)
    round_ids = []
    for i, amount in enumerate(
        ["10000", "10000", "10000", "25000", "25000", "5000", "5000", "5000"]
    ):
        tid = f"E105-R{i}"
        round_ids.append(tid)
        stream.append(etxn(tid, "ACCT-E105", base + timedelta(days=i), amount))
    for j, amount in enumerate(["123.45", "987.10", "45.00", "2300.75"]):
        stream.append(
            etxn(f"E105-N{j}", "ACCT-E105", base + timedelta(days=10 + j), amount,
                 direction="debit")
        )
    case_id, run = run_typo_case(
        "EVAL-105", profile("ACCT-E105", date(2026, 2, 1)), stream
    )
    check_findings(case_id, run.run_id, [
        ("round_amount", None, round_ids,
         {"round_count": "8", "round_total": "95000", "round_share": "0.6667"}),
    ])

    # E106: the control — regular 9,500 cash deposits, ten days
    # apart, for three months. In the band every time; never an
    # aggregation. Zero findings of any typology, zero tolerance.
    stream = []
    day = date(2026, 1, 5)
    for i in range(9):
        stream.append(
            etxn(f"E106-{i}", "ACCT-E106", day, "9500", cash=True, channel="branch")
        )
        day += timedelta(days=10)
    case_id, run = run_typo_case(
        "EVAL-106", profile("ACCT-E106", date(2025, 12, 1)), stream
    )
    check_findings(case_id, run.run_id, [])  # any actual finding = a false fire

    # E107: pack versions coexist. v1 stays silent on sub-band
    # deposits; v2 (band lowered to 8,000) fires; a v1 re-run is the
    # same run, not a duplicate.
    case_id, run_v1 = run_typo_case(
        "EVAL-107",
        profile("ACCT-E107", date(2026, 2, 1)),
        [
            etxn("E107-1", "ACCT-E107", date(2026, 3, 2), "8700", cash=True, channel="branch"),
            etxn("E107-2", "ACCT-E107", date(2026, 3, 3), "8800", cash=True, channel="branch"),
            etxn("E107-3", "ACCT-E107", date(2026, 3, 4), "8900", cash=True, channel="branch"),
        ],
    )
    check_findings(case_id, run_v1.run_id, [])
    run_v2 = typologies.run_typologies(
        case_id, "eval-pack", "2.0", actor="eval-runner"
    )
    check_findings(case_id, run_v2.run_id, [
        ("structuring", "multi_day", ["E107-1", "E107-2", "E107-3"],
         {"total_amount": "26400"}),
    ])
    findings_before = len(typologies.list_findings(case_id))
    rerun = typologies.run_typologies(
        case_id, "eval-pack", "1.0", actor="eval-runner"
    )
    if rerun.run_id != run_v1.run_id or len(typologies.list_findings(case_id)) != findings_before:
        counters["typology_runs_not_idempotent"] += 1
    try:
        evidence.verify_chain(case_id)
    except Exception:
        counters["chains_failed"] += 1

    # A run over a case with no stored transactions is refused.
    bare_case = case_ids["EVAL-002"]
    try:
        typologies.run_typologies(bare_case, "eval-pack", "1.0", actor="eval-runner")
        counters["typology_run_without_data_accepted"] += 1
    except NoTransactionsError:
        pass

    print("Blueprint #15 evals — R1+R2+R3 counters")
    for key, value in counters.items():
        print(f"  {key}: {value}")
    zero_tolerance = [
        "closed_without_disposition",
        "unlawful_transitions_accepted",
        "chains_failed",
        "duplicate_cases",
        "audit_gaps",
        "screening_without_pin",
        "stale_screening_unflagged",
        "sanctions_close_blocked_violations",
        "delta_hits_missed",
        "typology_expected_missed",
        "typology_false_fires",
        "typology_figure_mismatches",
        "typology_runs_not_idempotent",
        "findings_without_rule_version",
        "rule_pack_mutations_accepted",
        "typology_run_without_data_accepted",
    ]
    passed = all(counters[k] == 0 for k in zero_tolerance) and counters["cases_opened"] == len(ALERTS)
    print("GATE: PASS" if passed else "GATE: FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
