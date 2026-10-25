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
  - investigation citations failing to resolve (R4)  must be 0
  - unresolvable findings accepted at record time (R4) must be 0
  - investigation hypotheses incomplete (R4) ....... must be 0
  - structuring cases missing open questions (R4) ... must be 0
  - statement figures not tracing to citations (R4). must be 0
  - investigation re-runs duplicating records (R4).. must be 0
  - investigation hypotheses wrong on planted cases (R4) must be 0
  - anonymous/system dispositions accepted (R5) .... must be 0
  - dispositions without a record accepted (R5) .... must be 0
  - sanctions-blocked closures accepted (R5) ...... must be 0
  - self-confirmations accepted (R5) ............... must be 0
  - free-text-only rationale accepted (R5) ......... must be 0
  - stale dispositions left unflagged (R5) ......... must be 0
  - superseded-record citations accepted (R5) ...... must be 0
  - wrong clock deadlines computed (R8) ............ must be 0
  - wrong clock boundary states (R8) ............... must be 0
  - overdue clocks missing from the queue (R8) ..... must be 0
  - ended clocks still escalated (R8) .............. must be 0
  - duplicate escalation events recorded (R8) ...... must be 0
  - terminal-without-disposition undetected (R8) ... must be 0
  - SAR drafts for non-sar_pending cases (R6) ...... must be 0
  - unverifiable statements marked verified (R6).. must be 0
  - figures outside the cited records accepted (R6)  must be 0
  - open questions hidden by a narrative (R6) ..... must be 0
  - stale narratives still standing verified (R6). must be 0
  - SAR self-approvals accepted (R7) .............. must be 0
  - dispositioner approvals accepted (R7) ......... must be 0
  - unverified/stale narrative approvals (R7) ..... must be 0
  - anonymous narrative approvals accepted (R7)... must be 0
  - mutations of a sealed case accepted (R7) ...... must be 0
  - tampered exports passing verification (R7) .... must be 0
  - seals with an incomplete manifest accepted (R7) must be 0

Exit code 0 iff the gate passes.
"""

from __future__ import annotations

import base64
import sys
import tempfile
from datetime import date, datetime, time, timedelta, timezone  # noqa: E402
from decimal import Decimal  # noqa: E402
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aml_investigations.approval import SarApprovalService  # noqa: E402
from aml_investigations.clocks import RegulatoryClockService  # noqa: E402
from aml_investigations.composer import numeric_tokens, tokens_of  # noqa: E402
from aml_investigations.dispositions import (  # noqa: E402
    FLAG_DISPOSITION_STALE,
    DispositionService,
)
from aml_investigations.errors import (  # noqa: E402
    ApprovalRefusedError,
    CaseSealedError,
    DispositionRefusedError,
    IllegalTransitionError,
    InvestigationRefusedError,
    NoTransactionsError,
    RulePackImmutableError,
    SarNarrativeRefusedError,
    ScreeningPinRequiredError,
    SealingRefusedError,
)
from aml_investigations.evidence import EvidenceService  # noqa: E402
from aml_investigations.intake import (  # noqa: E402
    IntakeService,
    ListAlertFeed,
    ReferenceAlertFeed,
)
from aml_investigations.investigation import (  # noqa: E402
    CitationResolver,
    InvestigationService,
)
from aml_investigations.models import (  # noqa: E402
    AccountProfile,
    Alert,
    ApprovalOutcome,
    Case,
    CaseStatus,
    ClockState,
    ConfirmationOutcome,
    Disposition,
    DispositionOutcome,
    DispositionRecord,
    HitStatus,
    ListEntry,
    ListKind,
    ListSnapshot,
    RulePack,
    Transaction,
)
from aml_investigations.object_store import LocalObjectStore  # noqa: E402
from aml_investigations.sar import SarNarrativeService  # noqa: E402
from aml_investigations.screening import (  # noqa: E402
    ReferenceScreeningFeed,
    ScreeningService,
)
from aml_investigations.sealing import (  # noqa: E402
    CaseSealingService,
    seal_hash_for,
    verify_export_package,
)
from aml_investigations.stores import InMemoryCaseStore  # noqa: E402
from aml_investigations.transactions import (  # noqa: E402
    ListTransactionFeed,
    ReferenceRulePackFeed,
    ReferenceTransactionFeed,
)
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
        # R4 investigation counters
        "investigation_records_built": 0,
        "investigation_citation_failures": 0,
        "investigation_unresolvable_accepted": 0,
        "investigation_hypothesis_incomplete": 0,
        "investigation_hypothesis_wrong": 0,
        "investigation_open_questions_missing": 0,
        "investigation_figure_provenance_failures": 0,
        "investigation_rerun_duplicated": 0,
        # R5 disposition counters
        "dispositions_recorded": 0,
        "disposition_anonymous_accepted": 0,
        "disposition_without_record_accepted": 0,
        "disposition_sanctions_blocked_accepted": 0,
        "disposition_self_confirmation_accepted": 0,
        "disposition_free_text_only_accepted": 0,
        "disposition_stale_unflagged": 0,
        "disposition_stale_citation_accepted": 0,
        "disposition_positive_paths_failed": 0,
        # R6 SAR narrative counters
        "sar_narratives_drafted": 0,
        "sar_narratives_verified": 0,
        "sar_draft_non_sar_pending_accepted": 0,
        "sar_unverifiable_marked_verified": 0,
        "sar_figure_not_in_records_accepted": 0,
        "sar_open_questions_omitted": 0,
        "sar_stale_still_verified": 0,
        "sar_positive_paths_failed": 0,
        # R7 approval + sealing counters
        "approvals_recorded": 0,
        "seals_recorded": 0,
        "sar_self_approval_accepted": 0,
        "sar_dispositioner_approval_accepted": 0,
        "sar_unverified_approval_accepted": 0,
        "sar_anonymous_approval_accepted": 0,
        "sealed_case_mutations_accepted": 0,
        "tampered_export_verified": 0,
        "seal_incomplete_accepted": 0,
        "r7_positive_paths_failed": 0,
        # R8 regulatory clock counters
        "clock_cases_graded": 0,
        "clock_wrong_deadline": 0,
        "clock_state_wrong": 0,
        "clock_overdue_missing_from_queue": 0,
        "clock_terminal_still_escalated": 0,
        "clock_duplicate_escalation_events": 0,
        "clock_terminal_violation_undetected": 0,
        "clock_escalations_recorded": 0,
        "clock_continuing_clocks_started": 0,
        "clock_positive_paths_failed": 0,
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

    # -- Scenario 7 (R4): investigation records — citation discipline. ---
    # Every finding in a built record must cite elements that resolve;
    # every figure in a statement must trace to a cited record; the
    # hypothesis must name its support and carry its counter-search;
    # the structuring case must carry the source-of-funds open
    # question; a poisoned record must be refused at the gate; a
    # re-run over unchanged inputs must not duplicate the record,
    # and new evidence must produce the next version with a diff.
    investigations = InvestigationService(
        store, store, store, store, evidence, disposition_store=store
    )
    resolver = CitationResolver(store, evidence)

    def check_record(record, expected_label, *, sof_question: bool) -> None:
        counters["investigation_records_built"] += 1
        if record.hypothesis.label != expected_label:
            counters["investigation_hypothesis_wrong"] += 1
        by_id = {f.finding_id: f for f in record.findings}
        for finding in record.findings:
            if not finding.citations:
                counters["investigation_citation_failures"] += 1
                continue
            cited_tokens = set()
            for citation in finding.citations:
                try:
                    cited_tokens |= tokens_of(
                        resolver.resolve(citation, record.case_id)
                    )
                except Exception:
                    counters["investigation_citation_failures"] += 1
            allowed = cited_tokens | set().union(
                *(numeric_tokens(v) for v in finding.figures.values()), set()
            )
            if not numeric_tokens(finding.statement) <= allowed:
                counters["investigation_figure_provenance_failures"] += 1
            if finding.origin in (
                "typology", "screening", "alert", "profile", "prior_case",
            ):
                for value in finding.figures.values():
                    if not numeric_tokens(value) <= cited_tokens:
                        counters["investigation_figure_provenance_failures"] += 1
        hypothesis = record.hypothesis
        support_ok = all(
            fid in by_id and by_id[fid].direction == "supports"
            for fid in hypothesis.supporting_finding_ids
        ) and set(hypothesis.supporting_finding_ids) == {
            f.finding_id for f in record.findings if f.direction == "supports"
        } and (
            expected_label == "no_adverse_pattern"
            or bool(hypothesis.supporting_finding_ids)
        )
        counter_ok = record.counter_search.ran and bool(
            record.counter_search.checks
        ) and bool(record.counter_search.coverage)
        if not (support_ok and counter_ok):
            counters["investigation_hypothesis_incomplete"] += 1
        if sof_question and not any(
            q.evidence_needed == "source_of_funds_documentation"
            for q in record.open_questions
        ):
            counters["investigation_open_questions_missing"] += 1

    def to_investigating(case_id: str) -> None:
        workflow.transition(case_id, CaseStatus.ASSEMBLING, actor="eval")
        workflow.transition(case_id, CaseStatus.INVESTIGATING, actor="eval")

    inv_intake = IntakeService(
        store,
        ListAlertFeed([
            Alert(
                alert_id="EVAL-INV-1", rule_id="TM-STRUCTURING-01",
                customer_id="CUST-I1", account_id="ACCT-I1",
                severity="high", detected_on="2026-03-07",
                summary="Investigation eval: structuring case.",
                raw={
                    "customer_name": "Iris Iversen",
                    "customer_dob": "1980-04-12",
                    "customer_identifiers": ["PP-SE-1104"],
                    "counterparties": [],
                },
            ),
            Alert(
                alert_id="EVAL-INV-3", rule_id="TM-STRUCTURING-01",
                customer_id="CUST-I3", account_id="ACCT-I3",
                severity="low", detected_on="2026-03-27",
                summary="Investigation eval: cadence control.",
            ),
        ]),
        evidence,
    )

    # INV-1: a planted structuring case, screened (no hits), typed.
    inv1 = inv_intake.open_case("EVAL-INV-1").case_id
    workflow.transition(inv1, CaseStatus.ASSEMBLING, actor="eval")
    screening.screen_case(
        inv1, {ListKind.SANCTIONS: "2026.10.1"}, actor="eval"
    )
    inv1_profile = AccountProfile(
        account_id="ACCT-I1", customer_id="CUST-I1",
        opened_on=date(2026, 2, 1), account_type="business_checking",
        expected_monthly_amount=Decimal("30000"), expected_monthly_count=40,
    )
    inv1_stream = [
        etxn("I1-S1", "ACCT-I1", date(2026, 2, 10), "4200.00", channel="ach"),
        etxn("I1-1", "ACCT-I1", date(2026, 3, 2), "9500", cash=True, channel="branch"),
        etxn("I1-2", "ACCT-I1", date(2026, 3, 4), "9600", cash=True, channel="branch"),
        etxn("I1-3", "ACCT-I1", date(2026, 3, 6), "9700", cash=True, channel="branch"),
        etxn("I1-S2", "ACCT-I1", date(2026, 3, 10), "4200.00", channel="ach"),
    ]
    typologies.ingest_from_source(
        inv1, ListTransactionFeed([inv1_profile], {"ACCT-I1": inv1_stream}),
        actor="eval-feed",
    )
    typologies.run_typologies(inv1, "eval-pack", "1.0", actor="eval-runner")
    workflow.transition(inv1, CaseStatus.INVESTIGATING, actor="eval")
    record_v1 = investigations.run_investigation(inv1, actor="eval-analyst")
    check_record(record_v1, "structuring", sof_question=True)

    # The gate refuses poisoned records: a citation to a real item
    # naming an element that is not inside it, a citation to a
    # missing item, and an added finding with no citations.
    typo_finding = next(
        f for f in record_v1.findings if f.origin == "typology"
    )
    for poison in (
        typo_finding.model_copy(update={
            "citations": [typo_finding.citations[0].model_copy(
                update={"element": "finding:find-does-not-exist"})],
        }),
        typo_finding.model_copy(update={
            "citations": [typo_finding.citations[0].model_copy(
                update={"evidence_seq": 999})],
        }),
        typo_finding.model_copy(update={"citations": []}),
    ):
        poisoned = record_v1.model_copy(update={
            "findings": [
                poison if f.finding_id == typo_finding.finding_id else f
                for f in record_v1.findings
            ],
        })
        try:
            investigations.verify_record(poisoned)
            counters["investigation_unresolvable_accepted"] += 1
        except InvestigationRefusedError:
            pass

    # A re-run over unchanged inputs returns the same record.
    again = investigations.run_investigation(inv1, actor="eval-analyst")
    if again.record_id != record_v1.record_id or again.version != 1:
        counters["investigation_rerun_duplicated"] += 1

    # New evidence (a round-amount stream) + a fresh typology run
    # produce version 2, superseding v1, with the new pattern in the
    # diff and v1 still on the chain.
    extra = [
        etxn(f"I1-R{i}", "ACCT-I1", date(2026, 3, 12) + timedelta(days=i),
             "10000", channel="wire")
        for i in range(8)
    ]
    typologies.ingest_transactions(
        inv1, extra, source_ref="core-banking:ACCT-I1:delta", actor="eval-feed"
    )
    typologies.run_typologies(inv1, "eval-pack", "1.0", actor="eval-runner")
    record_v2 = investigations.run_investigation(inv1, actor="eval-analyst")
    if (
        record_v2.version != 2
        or record_v2.supersedes_record_id != record_v1.record_id
        or record_v2.diff is None
        or record_v2.diff.from_version != 1
        or not any(
            k.startswith("typology:round_amount")
            for k in record_v2.diff.added
        )
        or len(investigations.record_history(inv1)) != 2
    ):
        counters["investigation_rerun_duplicated"] += 1
    check_record(record_v2, "structuring", sof_question=True)
    try:
        evidence.verify_chain(inv1)
    except Exception:
        counters["chains_failed"] += 1

    # INV-3: the cadence control — no typology fires, the record's
    # hypothesis is the benign one, and its citations still resolve.
    inv3 = inv_intake.open_case("EVAL-INV-3").case_id
    inv3_stream = []
    day = date(2026, 1, 5)
    for i in range(9):
        inv3_stream.append(
            etxn(f"I3-{i}", "ACCT-I3", day, "9500", cash=True, channel="branch")
        )
        day += timedelta(days=10)
    inv3_profile = AccountProfile(
        account_id="ACCT-I3", customer_id="CUST-I3",
        opened_on=date(2025, 12, 1), account_type="business_checking",
    )
    typologies.ingest_from_source(
        inv3, ListTransactionFeed([inv3_profile], {"ACCT-I3": inv3_stream}),
        actor="eval-feed",
    )
    typologies.run_typologies(inv3, "eval-pack", "1.0", actor="eval-runner")
    to_investigating(inv3)
    record_inv3 = investigations.run_investigation(inv3, actor="eval-analyst")
    check_record(record_inv3, "no_adverse_pattern", sof_question=False)

    # The shipped seed structuring case, end to end over the repo's
    # own data files (screening + typologies + investigation). It
    # runs on its own stack: the shipped snapshots carry the same
    # version strings as the eval fixtures above with different
    # content, and snapshots are immutable once ingested.
    data_dir = Path(__file__).resolve().parents[1] / "data"
    s_store = InMemoryCaseStore()
    s_evidence = EvidenceService(
        s_store, LocalObjectStore(Path(tempfile.mkdtemp(prefix="aml-evals-seed-")))
    )
    s_workflow = CaseWorkflow(s_store, screening_store=s_store)
    s_screening = ScreeningService(s_store, s_store, s_evidence)
    s_typologies = TypologyService(s_store, s_store, s_evidence)
    s_investigations = InvestigationService(
        s_store, s_store, s_store, s_store, s_evidence
    )
    s_intake = IntakeService(
        s_store, ReferenceAlertFeed(data_dir / "seed_alerts.json"), s_evidence
    )
    s_screening.ingest_from_source(
        ReferenceScreeningFeed(data_dir / "screening_lists.json")
    )
    s_typologies.register_from_source(
        ReferenceRulePackFeed(data_dir / "typology_rules.json")
    )
    shipped = s_intake.open_case("ALRT-2026-1001").case_id
    s_workflow.transition(shipped, CaseStatus.ASSEMBLING, actor="eval")
    s_screening.screen_case(
        shipped,
        {
            ListKind.SANCTIONS: "2026.10.1",
            ListKind.PEP: "2026.10.1",
            ListKind.ADVERSE_MEDIA: "2026.10.1",
        },
        actor="eval",
    )
    s_typologies.ingest_from_source(
        shipped,
        ReferenceTransactionFeed(data_dir / "transaction_streams.json"),
        actor="eval-feed",
    )
    s_typologies.run_typologies(
        shipped, "harborline-typologies", "2026.10.1", actor="eval-runner"
    )
    s_workflow.transition(shipped, CaseStatus.INVESTIGATING, actor="eval")
    shipped_record = s_investigations.run_investigation(
        shipped, actor="eval-analyst"
    )
    # Citation/provenance checks for this record run against its own
    # stack's resolver.
    seed_resolver = CitationResolver(s_store, s_evidence)
    counters["investigation_records_built"] += 1
    if shipped_record.hypothesis.label != "structuring":
        counters["investigation_hypothesis_wrong"] += 1
    for finding in shipped_record.findings:
        cited_tokens = set()
        for citation in finding.citations:
            try:
                cited_tokens |= tokens_of(
                    seed_resolver.resolve(citation, shipped_record.case_id)
                )
            except Exception:
                counters["investigation_citation_failures"] += 1
        allowed = cited_tokens | set().union(
            *(numeric_tokens(v) for v in finding.figures.values()), set()
        )
        if not numeric_tokens(finding.statement) <= allowed:
            counters["investigation_figure_provenance_failures"] += 1
    if not any(
        q.evidence_needed == "source_of_funds_documentation"
        for q in shipped_record.open_questions
    ):
        counters["investigation_open_questions_missing"] += 1
    if not (
        shipped_record.counter_search.ran
        and shipped_record.counter_search.checks
    ):
        counters["investigation_hypothesis_incomplete"] += 1

    # -- Scenario 8 (R5): the disposition gate. -------------------------
    # Every refusal the gate exists to make is probed: anonymous and
    # system actors, a disposition with no investigation record to
    # rely on, free text offered instead of coded rationale, a
    # citation of a superseded record, closing outcomes over an
    # unresolved sanctions hit, and the dispositioning analyst
    # confirming their own closure. The positive paths must all land:
    # an adverse close parks for confirmation and closes only when a
    # second person confirms; a benign close lands at once; monitor,
    # escalate and send-back route where they should; and when a new
    # record version supersedes the one a disposition relied on, the
    # case is flagged DISPOSITION_STALE until a fresh disposition
    # answers it.
    dispositions = DispositionService(store, store, store, store, evidence, workflow)

    def attempt_disposition(case_id, counter=None, **kwargs):
        """A disposition attempt. With ``counter`` set (a refusal
        probe), a wrongly-accepted attempt increments it; positive
        paths pass no counter and are checked by their callers."""
        base = dict(
            analyst_id="e.okafor",
            analyst_role="analyst",
            outcome=DispositionOutcome.CLOSE_NO_ACTION,
            rationale_codes=["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"],
            record_id="",
            record_version=0,
        )
        base.update(kwargs)
        try:
            record = dispositions.record_disposition(case_id, **base)
        except DispositionRefusedError:
            return None
        if counter is not None:
            counters[counter] += 1
        return record

    def to_gate(case_id: str) -> None:
        workflow.transition(case_id, CaseStatus.AWAITING_ANALYST, actor="eval")

    # 8a: the structuring case (inv1, record v2, adverse hypothesis).
    to_gate(inv1)
    attempt_disposition(
        inv1, "disposition_anonymous_accepted",
        analyst_id="investigation-service",
        record_id=record_v2.record_id, record_version=record_v2.version,
    )
    attempt_disposition(
        inv1, "disposition_anonymous_accepted",
        analyst_id="",
        record_id=record_v2.record_id, record_version=record_v2.version,
    )
    attempt_disposition(
        inv1, "disposition_free_text_only_accepted",
        rationale_codes=[],
        record_id=record_v2.record_id, record_version=record_v2.version,
    )
    attempt_disposition(
        inv1, "disposition_stale_citation_accepted",
        record_id=record_v1.record_id, record_version=record_v1.version,
    )
    parked = attempt_disposition(
        inv1,
        rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"],
        record_id=record_v2.record_id, record_version=record_v2.version,
    )
    if parked is None or not parked.requires_confirmation:
        counters["disposition_positive_paths_failed"] += 1
    else:
        counters["dispositions_recorded"] += 1
        if store.get_case(inv1).status is not CaseStatus.PENDING_CONFIRMATION:
            counters["disposition_positive_paths_failed"] += 1
        try:
            dispositions.confirm_disposition(
                inv1,
                confirmer_id="e.okafor",
                confirmer_role="l2_reviewer",
                outcome=ConfirmationOutcome.CONFIRMED,
            )
            counters["disposition_self_confirmation_accepted"] += 1
        except DispositionRefusedError:
            pass
        dispositions.confirm_disposition(
            inv1,
            confirmer_id="m.osei",
            confirmer_role="l2_reviewer",
            outcome=ConfirmationOutcome.CONFIRMED,
        )
        if store.get_case(inv1).status is not CaseStatus.CLOSED:
            counters["disposition_positive_paths_failed"] += 1

    # 8b: a case with no investigation record cannot be dispositioned;
    # once investigated (benign), its close lands at once.
    bare = case_ids["EVAL-003"]
    for target in (
        CaseStatus.ASSEMBLING,
        CaseStatus.INVESTIGATING,
        CaseStatus.AWAITING_ANALYST,
    ):
        workflow.transition(bare, target, actor="eval")
    attempt_disposition(
        bare, "disposition_without_record_accepted",
        record_id="INV-none", record_version=1,
    )
    workflow.transition(bare, CaseStatus.INVESTIGATING, actor="eval")
    bare_record = investigations.run_investigation(bare, actor="eval-analyst")
    to_gate(bare)
    closed = attempt_disposition(
        bare,
        record_id=bare_record.record_id, record_version=bare_record.version,
    )
    if closed is None or store.get_case(bare).status is not CaseStatus.CLOSED:
        counters["disposition_positive_paths_failed"] += 1
    else:
        counters["dispositions_recorded"] += 1

    # 8c: staleness. inv3 is dispositioned to monitoring on record
    # v1; new evidence produces record v2; the case must be flagged
    # until a fresh disposition on v2 answers it.
    to_gate(inv3)
    monitored = dispositions.record_disposition(
        inv3,
        analyst_id="e.okafor",
        analyst_role="analyst",
        outcome=DispositionOutcome.CLOSE_MONITOR,
        rationale_codes=["PATTERN_EXPLAINED_MONITOR_ACTIVITY"],
        record_id=record_inv3.record_id,
        record_version=record_inv3.version,
        review_period_days=30,
    )
    counters["dispositions_recorded"] += 1
    if store.get_case(inv3).status is not CaseStatus.MONITORING:
        counters["disposition_positive_paths_failed"] += 1
    workflow.transition(inv3, CaseStatus.INVESTIGATING, actor="eval")
    extra3 = [
        etxn(f"I3-R{i}", "ACCT-I3", date(2026, 3, 12) + timedelta(days=i),
             "10000", channel="wire")
        for i in range(10)
    ]
    typologies.ingest_transactions(
        inv3, extra3, source_ref="core-banking:ACCT-I3:delta", actor="eval-feed"
    )
    typologies.run_typologies(inv3, "eval-pack", "1.0", actor="eval-runner")
    record_inv3_v2 = investigations.run_investigation(inv3, actor="eval-analyst")
    if record_inv3_v2.version != 2:
        counters["disposition_stale_unflagged"] += 1
    if FLAG_DISPOSITION_STALE not in store.get_case(inv3).flags:
        counters["disposition_stale_unflagged"] += 1
    to_gate(inv3)
    answered = dispositions.record_disposition(
        inv3,
        analyst_id="e.okafor",
        analyst_role="senior_analyst",
        outcome=DispositionOutcome.ESCALATE_L2,
        rationale_codes=["CONFLICTING_EVIDENCE"],
        record_id=record_inv3_v2.record_id,
        record_version=record_inv3_v2.version,
    )
    counters["dispositions_recorded"] += 1
    if FLAG_DISPOSITION_STALE in store.get_case(inv3).flags:
        counters["disposition_stale_unflagged"] += 1
    if dispositions.status_of(monitored) != "superseded":
        counters["disposition_stale_unflagged"] += 1

    # 8d: the sanctions case. The customer himself is on sanctions
    # v2 (the scenario-5 delta): closing outcomes are refused at the
    # gate; escalate_sar routes to the SAR queue; a send-back for
    # the missing source-of-funds evidence is honoured.
    disp_intake = IntakeService(
        store,
        ListAlertFeed([
            Alert(
                alert_id="EVAL-D1", rule_id="TM-SANCTIONS-02",
                customer_id="CUST-D1", account_id="ACCT-D1",
                severity="critical", detected_on="2026-10-25",
                summary="Disposition eval: listed customer.",
                raw={
                    "customer_name": "Daniel Okafor",
                    "customer_dob": "1985-03-04",
                    "customer_identifiers": ["PP-NG-2210"],
                    "counterparties": [],
                },
            ),
        ]),
        evidence,
    )
    d1 = disp_intake.open_case("EVAL-D1").case_id
    workflow.transition(d1, CaseStatus.ASSEMBLING, actor="eval")
    screening.screen_case(
        d1,
        {ListKind.SANCTIONS: "2026.10.2", ListKind.PEP: "2026.10.1"},
        actor="eval",
    )
    d1_profile = AccountProfile(
        account_id="ACCT-D1", customer_id="CUST-D1",
        opened_on=date(2025, 5, 1), account_type="personal_checking",
    )
    d1_stream = [
        etxn("D1-1", "ACCT-D1", date(2026, 10, 2), "2400.00", channel="ach"),
        etxn("D1-2", "ACCT-D1", date(2026, 10, 16), "2400.00", channel="ach"),
    ]
    typologies.ingest_from_source(
        d1, ListTransactionFeed([d1_profile], {"ACCT-D1": d1_stream}),
        actor="eval-feed",
    )
    typologies.run_typologies(d1, "eval-pack", "1.0", actor="eval-runner")
    workflow.transition(d1, CaseStatus.INVESTIGATING, actor="eval")
    d1_record = investigations.run_investigation(d1, actor="eval-analyst")
    if d1_record.hypothesis.label != "sanctions_match":
        counters["investigation_hypothesis_wrong"] += 1
    to_gate(d1)
    attempt_disposition(
        d1, "disposition_sanctions_blocked_accepted",
        record_id=d1_record.record_id, record_version=d1_record.version,
    )
    attempt_disposition(
        d1, "disposition_sanctions_blocked_accepted",
        outcome=DispositionOutcome.CLOSE_MONITOR,
        rationale_codes=["EMERGING_PATTERN_WATCH"],
        review_period_days=30,
        record_id=d1_record.record_id, record_version=d1_record.version,
    )
    routed = dispositions.record_disposition(
        d1,
        analyst_id="e.okafor",
        analyst_role="analyst",
        outcome=DispositionOutcome.ESCALATE_SAR,
        rationale_codes=["SANCTIONS_MATCH_SUSPECTED"],
        record_id=d1_record.record_id,
        record_version=d1_record.version,
    )
    counters["dispositions_recorded"] += 1
    if store.get_case(d1).status is not CaseStatus.SAR_PENDING:
        counters["disposition_positive_paths_failed"] += 1
    workflow.transition(d1, CaseStatus.INVESTIGATING, actor="eval")
    to_gate(d1)
    dispositions.record_disposition(
        d1,
        analyst_id="e.okafor",
        analyst_role="analyst",
        outcome=DispositionOutcome.REQUEST_MORE_EVIDENCE,
        rationale_codes=["SOURCE_OF_FUNDS_MISSING"],
        record_id=d1_record.record_id,
        record_version=d1_record.version,
        missing_evidence=["source_of_funds_documentation"],
    )
    counters["dispositions_recorded"] += 1
    if store.get_case(d1).status is not CaseStatus.INVESTIGATING:
        counters["disposition_positive_paths_failed"] += 1
    try:
        evidence.verify_chain(d1)
    except Exception:
        counters["chains_failed"] += 1

    # -- Scenario 9 (R6): SAR narrative drafting + the citation verifier.
    # The shipped seed structuring case, routed by the gate to
    # sar_pending, drafts a narrative that the citation verifier
    # passes statement by statement. The verifier's refusals are
    # probed with tampered drafts: a figure altered by a cent, a
    # statement stripped of its citations, a narrative that hides
    # the record's open questions — none may verify. And when new
    # evidence supersedes the record a verified narrative cites,
    # the narrative must drop back to stale, then be superseded by
    # the re-draft on the fresh routing. Nothing is filed: the
    # case stands in sar_pending throughout, at a verified draft.
    s_dispositions = DispositionService(
        s_store, s_store, s_store, s_store, s_evidence, s_workflow
    )
    s_sar = SarNarrativeService(
        s_store, s_store, s_store, s_store, s_evidence
    )

    # 9a: drafting before the gate routes the case is refused, on
    # the seed case (still investigating) and on an escalated case
    # of the main stack alike.
    try:
        s_sar.draft_narrative(shipped, actor="eval")
        counters["sar_draft_non_sar_pending_accepted"] += 1
    except SarNarrativeRefusedError:
        pass
    main_sar = SarNarrativeService(store, store, store, store, evidence)
    try:
        main_sar.draft_narrative(inv3, actor="eval")
        counters["sar_draft_non_sar_pending_accepted"] += 1
    except SarNarrativeRefusedError:
        pass

    # 9b: the gate routes the seed case; drafting + verification land.
    s_workflow.transition(shipped, CaseStatus.AWAITING_ANALYST, actor="eval")
    s_dispositions.record_disposition(
        shipped,
        analyst_id="e.okafor",
        analyst_role="analyst",
        outcome=DispositionOutcome.ESCALATE_SAR,
        rationale_codes=["STRUCTURING_SUSPECTED"],
        record_id=shipped_record.record_id,
        record_version=shipped_record.version,
    )
    if s_store.get_case(shipped).status is not CaseStatus.SAR_PENDING:
        counters["sar_positive_paths_failed"] += 1
    narrative, verification = s_sar.draft_narrative(shipped, actor="eval")
    counters["sar_narratives_drafted"] += 1
    if (
        not verification.all_verified
        or verification.narrative_problems
        or s_sar.status_of(narrative) != "verified"
    ):
        counters["sar_positive_paths_failed"] += 1
    else:
        counters["sar_narratives_verified"] += 1

    # 9c: tampered drafts cannot verify.
    amounts_section = next(
        s for s in narrative.sections if s.key == "amounts_and_instruments"
    )
    target = next(st for st in amounts_section.statements if st.figures)

    def tamper_sar(source, statement_id, **updates):
        sections = []
        for section in source.sections:
            statements = [
                st.model_copy(update=updates)
                if st.statement_id == statement_id
                else st
                for st in section.statements
            ]
            sections.append(
                section.model_copy(update={"statements": statements})
            )
        return source.model_copy(update={"sections": sections})

    total_value = next(iter(target.figures.values()))
    altered = str(Decimal(total_value) + Decimal("0.01"))
    figure_key = next(iter(target.figures.keys()))
    tampered_figure = tamper_sar(
        narrative,
        target.statement_id,
        text=target.text.replace(total_value, altered),
        figures={figure_key: altered},
    )
    if s_sar.check_narrative(tampered_figure).all_verified:
        counters["sar_figure_not_in_records_accepted"] += 1
    dropped_citations = tamper_sar(
        narrative, target.statement_id, citations=[]
    )
    if s_sar.check_narrative(dropped_citations).all_verified:
        counters["sar_unverifiable_marked_verified"] += 1
    hidden_questions = narrative.model_copy(
        update={
            "sections": [
                s
                for s in narrative.sections
                if s.key != "what_remains_unknown"
            ]
        }
    )
    if s_sar.check_narrative(hidden_questions).all_verified:
        counters["sar_open_questions_omitted"] += 1
    # The stored draft is untouched by the probes and still verifies.
    if s_sar.status_of(narrative) != "verified":
        counters["sar_positive_paths_failed"] += 1

    # 9d: staleness, then supersession by the re-draft.
    s_workflow.transition(shipped, CaseStatus.INVESTIGATING, actor="eval")
    extra_seed = [
        etxn(f"S-R{i}", "ACCT-5001", date(2026, 10, 26) + timedelta(days=i),
             "10000", channel="wire")
        for i in range(8)
    ]
    s_typologies.ingest_transactions(
        shipped, extra_seed,
        source_ref="core-banking:ACCT-5001:delta", actor="eval-feed",
    )
    s_typologies.run_typologies(
        shipped, "harborline-typologies", "2026.10.1", actor="eval-runner"
    )
    shipped_v2 = s_investigations.run_investigation(
        shipped, actor="eval-analyst"
    )
    if shipped_v2.version != 2 or s_sar.status_of(narrative) != "stale":
        counters["sar_stale_still_verified"] += 1
    s_workflow.transition(shipped, CaseStatus.AWAITING_ANALYST, actor="eval")
    s_dispositions.record_disposition(
        shipped,
        analyst_id="e.okafor",
        analyst_role="analyst",
        outcome=DispositionOutcome.ESCALATE_SAR,
        rationale_codes=["STRUCTURING_SUSPECTED"],
        record_id=shipped_v2.record_id,
        record_version=shipped_v2.version,
    )
    narrative_v2, verification_v2 = s_sar.draft_narrative(
        shipped, actor="eval"
    )
    counters["sar_narratives_drafted"] += 1
    if (
        not verification_v2.all_verified
        or s_sar.status_of(narrative_v2) != "verified"
        or s_sar.status_of(narrative) != "superseded"
        or s_store.get_case(shipped).status is not CaseStatus.SAR_PENDING
    ):
        counters["sar_positive_paths_failed"] += 1
    else:
        counters["sar_narratives_verified"] += 1
    try:
        s_evidence.verify_chain(shipped)
    except Exception:
        counters["chains_failed"] += 1

    # -- Scenario 10 (R7): dual-control approval + sealing/export. ----
    # The seed case stands in sar_pending at a verified narrative
    # (Scenario 9). A stale narrative must not be decidable; the
    # dispositioning analyst and the drafter must not approve; a
    # second person approves, completing the case file (nothing is
    # filed — the case reaches filed_sar and stops). A legal hold
    # blocks the archive seal; the custody seal certifies every
    # evidence item; the export verifies clean offline, a tampered
    # export fails naming the item, and every mutating path refuses
    # on the sealed case until an officer unseals it.
    s_evidence7 = EvidenceService(
        s_store, s_evidence._objects, seal_store=s_store
    )
    s_screening7 = ScreeningService(
        s_store, s_store, s_evidence7, seal_store=s_store
    )
    s_typologies7 = TypologyService(
        s_store, s_store, s_evidence7, seal_store=s_store
    )
    s_investigations7 = InvestigationService(
        s_store, s_store, s_store, s_store, s_evidence7,
        disposition_store=s_store, seal_store=s_store,
    )
    s_dispositions7 = DispositionService(
        s_store, s_store, s_store, s_store, s_evidence7, s_workflow,
        seal_store=s_store,
    )
    s_sar7 = SarNarrativeService(
        s_store, s_store, s_store, s_store, s_evidence7,
        approval_store=s_store, seal_store=s_store,
    )
    s_approvals = SarApprovalService(
        s_store, s_store, s_store, s_store, s_sar7, s_evidence7,
        s_workflow, seal_store=s_store,
    )
    s_sealing = CaseSealingService(
        s_store, s_store, s_store, s_store, s_store, s_evidence7, s_store
    )

    # 10a: a stale narrative cannot be decided. New evidence
    # supersedes the record narrative_v2 cites; the approval gate
    # refuses it as unverified-standing before any identity check
    # could pass it.
    s_workflow.transition(shipped, CaseStatus.INVESTIGATING, actor="eval")
    extra_seed7 = [
        etxn(f"S2-R{i}", "ACCT-5001", date(2026, 11, 3) + timedelta(days=i),
             "10000", channel="wire")
        for i in range(8)
    ]
    s_typologies7.ingest_transactions(
        shipped, extra_seed7,
        source_ref="core-banking:ACCT-5001:delta-2", actor="eval-feed",
    )
    s_typologies7.run_typologies(
        shipped, "harborline-typologies", "2026.10.1", actor="eval-runner"
    )
    shipped_v3 = s_investigations7.run_investigation(
        shipped, actor="eval-analyst"
    )
    if shipped_v3.version != 3 or s_sar7.status_of(narrative_v2) != "stale":
        counters["r7_positive_paths_failed"] += 1
    try:
        s_approvals.decide_narrative(
            shipped,
            approver_id="m.osei",
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
        counters["sar_unverified_approval_accepted"] += 1
    except ApprovalRefusedError:
        pass
    s_workflow.transition(shipped, CaseStatus.AWAITING_ANALYST, actor="eval")
    s_dispositions7.record_disposition(
        shipped,
        analyst_id="e.okafor",
        analyst_role="analyst",
        outcome=DispositionOutcome.ESCALATE_SAR,
        rationale_codes=["STRUCTURING_SUSPECTED"],
        record_id=shipped_v3.record_id,
        record_version=shipped_v3.version,
    )
    narrative_v3, verification_v3 = s_sar7.draft_narrative(
        shipped, actor="eval"
    )
    if (
        not verification_v3.all_verified
        or s_sar7.status_of(narrative_v3) != "verified"
        or s_store.get_case(shipped).status is not CaseStatus.SAR_PENDING
    ):
        counters["r7_positive_paths_failed"] += 1

    # 10b: dual control. The dispositioning analyst (e.okafor) and
    # the drafter (eval) are refused by name; an anonymous approver
    # is refused outright.
    try:
        s_approvals.decide_narrative(
            shipped,
            approver_id="e.okafor",
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
        counters["sar_dispositioner_approval_accepted"] += 1
    except ApprovalRefusedError as exc:
        if exc.reason != "approver_is_dispositioner":
            counters["r7_positive_paths_failed"] += 1
    try:
        s_approvals.decide_narrative(
            shipped,
            approver_id="eval",
            approver_role="analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
        counters["sar_self_approval_accepted"] += 1
    except ApprovalRefusedError as exc:
        if exc.reason != "approver_is_drafter":
            counters["r7_positive_paths_failed"] += 1
    try:
        s_approvals.decide_narrative(
            shipped,
            approver_id="",
            approver_role="senior_analyst",
            outcome=ApprovalOutcome.APPROVED,
        )
        counters["sar_anonymous_approval_accepted"] += 1
    except ApprovalRefusedError:
        pass

    # 10c: a second person approves; the case file is complete.
    s_approvals.decide_narrative(
        shipped,
        approver_id="m.osei",
        approver_role="senior_analyst",
        outcome=ApprovalOutcome.APPROVED,
    )
    counters["approvals_recorded"] += 1
    if (
        s_store.get_case(shipped).status is not CaseStatus.FILED_SAR
        or s_sar7.status_of(narrative_v3) != "approved"
    ):
        counters["r7_positive_paths_failed"] += 1

    # 10d: legal hold, then the seals. The hold blocks the archive
    # seal; the custody seal certifies every evidence item.
    s_sealing.place_hold(
        shipped,
        officer_id="o.reyes",
        officer_role="l2_reviewer",
        reason_code="LITIGATION_PENDING",
    )
    if not s_sealing.hold_in_force(shipped):
        counters["r7_positive_paths_failed"] += 1
    try:
        s_sealing.seal_case(
            shipped,
            officer_id="o.reyes",
            officer_role="l2_reviewer",
            purpose="archive",
        )
        counters["seal_incomplete_accepted"] += 1
    except SealingRefusedError:
        pass
    items_at_seal = len(s_store.list_evidence(shipped))
    seal = s_sealing.seal_case(
        shipped, officer_id="o.reyes", officer_role="l2_reviewer"
    )
    counters["seals_recorded"] += 1
    if (
        len(seal.manifest.items) != items_at_seal
        or seal.seal_hash != seal_hash_for(seal.manifest)
    ):
        counters["seal_incomplete_accepted"] += 1

    # 10e: the export verifies clean; a tampered export fails and
    # names the altered item.
    package = s_sealing.export_case_file(shipped)
    clean = verify_export_package(package)
    if not clean.ok or clean.items_checked != items_at_seal:
        counters["r7_positive_paths_failed"] += 1
    forged = dict(package)
    forged_items = [dict(i) for i in package["items"]]
    forged_items[1] = dict(
        forged_items[1],
        content_b64=base64.b64encode(b"forged content").decode("ascii"),
    )
    forged["items"] = forged_items
    tampered = verify_export_package(forged)
    if tampered.ok or not any(
        f"seq {forged_items[1]['seq']}" in p for p in tampered.problems
    ):
        counters["tampered_export_verified"] += 1

    # 10f: the sealed case refuses every mutating path.
    def sealed_probe(fn) -> None:
        try:
            fn()
            counters["sealed_case_mutations_accepted"] += 1
        except CaseSealedError:
            pass
        except Exception:
            counters["sealed_case_mutations_accepted"] += 1

    sealed_probe(lambda: s_evidence7.add_item(
        shipped, kind="analyst_note", content=b"late",
        source_ref="eval", captured_by="analyst:e.okafor",
    ))
    sealed_probe(lambda: s_screening7.screen_case(
        shipped, {ListKind.SANCTIONS: "2026.10.1"}, actor="eval",
    ))
    sealed_probe(lambda: s_typologies7.ingest_transactions(
        shipped,
        [etxn("S-LATE", "ACCT-5001", date(2026, 11, 20), "500",
              channel="ach")],
        source_ref="core-banking:late", actor="eval-feed",
    ))
    sealed_probe(lambda: s_typologies7.run_typologies(
        shipped, "harborline-typologies", "2026.10.1", actor="eval",
    ))
    sealed_probe(lambda: s_investigations7.run_investigation(
        shipped, actor="eval",
    ))
    sealed_probe(lambda: s_dispositions7.record_disposition(
        shipped,
        analyst_id="e.okafor",
        analyst_role="analyst",
        outcome=DispositionOutcome.CLOSE_NO_ACTION,
        rationale_codes=["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"],
        record_id="INV-x",
        record_version=1,
    ))
    sealed_probe(lambda: s_sar7.draft_narrative(shipped, actor="eval"))
    sealed_probe(lambda: s_approvals.decide_narrative(
        shipped,
        approver_id="m.osei",
        approver_role="senior_analyst",
        outcome=ApprovalOutcome.APPROVED,
    ))

    # 10g: release, unseal, reseal — the custody history keeps all
    # of it, in order, and the reseal is version 2.
    s_sealing.release_hold(
        shipped,
        officer_id="o.reyes",
        officer_role="l2_reviewer",
        reason_code="MATTER_RESOLVED",
    )
    s_sealing.unseal_case(
        shipped,
        officer_id="o.reyes",
        officer_role="l2_reviewer",
        reason_code="INVESTIGATION_REOPENED",
    )
    if s_sealing.is_sealed(shipped):
        counters["r7_positive_paths_failed"] += 1
    reseal = s_sealing.seal_case(
        shipped, officer_id="o.reyes", officer_role="l2_reviewer"
    )
    counters["seals_recorded"] += 1
    history = s_sealing.seal_history(shipped)
    if reseal.version != 2 or [h["record"] for h in history] != [
        "seal",
        "unseal",
        "seal",
    ]:
        counters["r7_positive_paths_failed"] += 1
    try:
        s_evidence7.verify_chain(shipped)
    except Exception:
        counters["chains_failed"] += 1

    # -- Scenario 11 (R8): regulatory clocks + escalation. ----------
    # Deadlines are graded against a literal table (day 30, day 60,
    # leap-year February, month-end detection) for identified and
    # unidentified subjects alike; boundary states land on the
    # exact days; the SAR and no-file lifecycles end their clocks
    # the documented way; a reopened case's clock is live again; a
    # new alert on a filed customer starts the continuing-activity
    # clock at intake; escalation crossings are recorded once; and
    # a terminal case with no disposition anywhere is reported as
    # a violation, not a silence.
    clocks = RegulatoryClockService(
        store, store, store, evidence, approvals=store
    )

    # 11a: the graded deadline table. Cases are written straight
    # to the store with their alert payload evidence — the facts
    # a filing clock reads — and graded for both subject states.
    deadline_table = [
        (date(2026, 10, 20), date(2026, 11, 19), date(2026, 12, 19)),
        (date(2026, 1, 31), date(2026, 3, 2), date(2026, 4, 1)),
        (date(2024, 2, 29), date(2024, 3, 30), date(2024, 4, 29)),
        (date(2023, 2, 28), date(2023, 3, 30), date(2023, 4, 29)),
        (date(2026, 12, 15), date(2027, 1, 14), date(2027, 2, 13)),
    ]
    boundary_case = None
    for i, (detected, initial, outer) in enumerate(deadline_table):
        for identified in (True, False):
            graded = Case(
                alert_id=f"EVAL-CLK-{i}-{identified}",
                customer_id="CUST-CLK",
                account_id="ACCT-CLK",
                rule_id="TM-CLOCK-01",
                detected_on=detected,
            )
            store.create_case(graded)
            if identified:
                payload = Alert(
                    alert_id=graded.alert_id,
                    rule_id=graded.rule_id,
                    customer_id=graded.customer_id,
                    account_id=graded.account_id,
                    detected_on=detected,
                    raw={
                        "customer_name": "Eval Subject",
                        "customer_dob": "1980-01-01",
                        "customer_identifiers": ["PP-EV-0001"],
                    },
                )
                evidence.add_item(
                    graded.case_id,
                    kind="alert_payload",
                    content=payload.model_dump_json(indent=2).encode("utf-8"),
                    source_ref=f"monitoring-feed:{graded.alert_id}",
                    captured_by="eval",
                )
            clock = clocks.filing_clock(
                store.get_case(graded.case_id), as_of=detected
            )
            counters["clock_cases_graded"] += 1
            if (
                clock.initial_deadline != initial
                or clock.outer_deadline != outer
                or clock.subject_identified is not identified
                or clock.operative_deadline
                != (initial if identified else outer)
            ):
                counters["clock_wrong_deadline"] += 1
            if i == 0 and identified:
                boundary_case = store.get_case(graded.case_id)

    # 11b: boundary states on the 2026-10-20 identified case
    # (initial deadline 2026-11-19).
    for as_of, expected in (
        (date(2026, 11, 11), ClockState.ON_TRACK),   # 8 days left
        (date(2026, 11, 12), ClockState.DUE_SOON),   # exactly 7
        (date(2026, 11, 19), ClockState.DUE),        # day 30
        (date(2026, 11, 20), ClockState.OVERDUE),    # day 31
    ):
        state = clocks.filing_clock(boundary_case, as_of=as_of).state
        if state is not expected:
            counters["clock_state_wrong"] += 1

    # 11c: lifecycles on the main stack. inv1 closed in 8a through
    # a confirmed close_no_action: its clock ends closed_no_file
    # naming that disposition and its coded rationale. The benign
    # EVAL-003 close (8b) ends the same way. inv3 was monitored
    # (8c) and then escalated — its latest disposition is not a
    # closure, so its clock is live again.
    inv1_clock = clocks.case_clocks(inv1, as_of=date(2026, 12, 1))
    if (
        inv1_clock.filing.state is not ClockState.CLOSED_NO_FILE
        or inv1_clock.filing.no_file_disposition_id
        != parked.disposition_id
        or inv1_clock.filing.no_file_rationale_codes
        != ["BENIGN_EXPLANATION_DOCUMENTED"]
        or inv1_clock.violations
    ):
        counters["clock_positive_paths_failed"] += 1
    bare_clock = clocks.case_clocks(bare, as_of=date(2026, 12, 1))
    if (
        bare_clock.filing.state is not ClockState.CLOSED_NO_FILE
        or bare_clock.filing.no_file_disposition_id
        != closed.disposition_id
    ):
        counters["clock_positive_paths_failed"] += 1
    inv3_clock = clocks.case_clocks(inv3, as_of=date(2026, 12, 1))
    if inv3_clock.filing.state is ClockState.CLOSED_NO_FILE:
        counters["clock_positive_paths_failed"] += 1

    # The seed case reached filed_sar in scenario 10: satisfied,
    # and documented — no violation on a sealed, filed file.
    s_clocks = RegulatoryClockService(
        s_store, s_store, s_store, s_evidence, approvals=s_store
    )
    shipped_clock = s_clocks.case_clocks(shipped, as_of=date(2027, 1, 1))
    if (
        shipped_clock.filing.state is not ClockState.SATISFIED
        or shipped_clock.violations
    ):
        counters["clock_positive_paths_failed"] += 1

    # 11d: the continuing-activity trigger, on its own stack. A
    # prior case filed with a determination on 2026-09-01; a new
    # alert for the same customer starts the 90/120-day clock at
    # intake; another customer's alert starts nothing.
    k_store = InMemoryCaseStore()
    k_evidence = EvidenceService(
        k_store,
        LocalObjectStore(Path(tempfile.mkdtemp(prefix="aml-evals-clocks-"))),
        seal_store=k_store,
    )
    k_clocks = RegulatoryClockService(
        k_store, k_store, k_store, k_evidence, approvals=k_store
    )
    k_intake = IntakeService(
        k_store,
        ListAlertFeed([
            Alert(
                alert_id="EVAL-K-NEW", rule_id="TM-VELOCITY-03",
                customer_id="CUST-K1", account_id="ACCT-K1",
                severity="medium", detected_on="2026-10-24",
                summary="New activity on a filed subject.",
            ),
            Alert(
                alert_id="EVAL-K-OTHER", rule_id="TM-VELOCITY-03",
                customer_id="CUST-K2", account_id="ACCT-K2",
                severity="low", detected_on="2026-10-24",
                summary="A customer with no filed history.",
            ),
        ]),
        k_evidence,
        clock_service=k_clocks,
    )
    prior = Case(
        alert_id="EVAL-K-PRIOR",
        customer_id="CUST-K1",
        account_id="ACCT-K1",
        rule_id="TM-STRUCTURING-01",
        detected_on=date(2026, 8, 2),
        status=CaseStatus.FILED_SAR,
        disposition=Disposition(
            analyst="e.okafor",
            decision="file_sar",
            reason_code="STRUCTURING_CONFIRMED",
            decided_at=datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc),
        ),
    )
    k_store.create_case(prior)
    new_case = k_intake.open_case("EVAL-K-NEW")
    link = k_clocks.continuing_link_for(new_case.case_id)
    if (
        link is None
        or link.prior_case_id != prior.case_id
        or link.determination_on != date(2026, 9, 1)
        or link.review_due_on != date(2026, 11, 30)
        or link.filing_due_on != date(2026, 12, 30)
    ):
        counters["clock_positive_paths_failed"] += 1
    else:
        counters["clock_continuing_clocks_started"] += 1
    at_review = k_clocks.case_clocks(new_case.case_id, as_of=date(2026, 11, 30))
    if (
        at_review.continuing_activity is None
        or at_review.continuing_activity.state is not ClockState.DUE
        or at_review.continuing_activity.operative_deadline_kind
        != "continuing_review"
    ):
        counters["clock_positive_paths_failed"] += 1
    past_filing = k_clocks.case_clocks(new_case.case_id, as_of=date(2026, 12, 31))
    if (
        past_filing.continuing_activity is None
        or past_filing.continuing_activity.state is not ClockState.OVERDUE
    ):
        counters["clock_positive_paths_failed"] += 1
    other = k_intake.open_case("EVAL-K-OTHER")
    if k_clocks.continuing_link_for(other.case_id) is not None:
        counters["clock_positive_paths_failed"] += 1

    # 11e: the escalation queue and the recorded crossings. An
    # overdue case and a due-soon case stand in the queue in that
    # order; the filed prior and a documented closed case do not
    # stand in it at all; refreshing the overdue case twice
    # records exactly one crossing.
    over_case = Case(
        alert_id="EVAL-K-OVER",
        customer_id="CUST-K3",
        account_id="ACCT-K3",
        rule_id="TM-CLOCK-01",
        detected_on=date(2026, 8, 1),  # outer deadline 2026-09-30
    )
    k_store.create_case(over_case)
    soon_case = Case(
        alert_id="EVAL-K-SOON",
        customer_id="CUST-K4",
        account_id="ACCT-K4",
        rule_id="TM-CLOCK-01",
        detected_on=date(2026, 10, 2),
    )
    k_store.create_case(soon_case)
    k_evidence.add_item(
        soon_case.case_id,
        kind="alert_payload",
        content=Alert(
            alert_id=soon_case.alert_id,
            rule_id=soon_case.rule_id,
            customer_id=soon_case.customer_id,
            account_id=soon_case.account_id,
            detected_on=date(2026, 10, 2),
            raw={
                "customer_name": "Soon Subject",
                "customer_dob": "1975-05-05",
            },
        ).model_dump_json(indent=2).encode("utf-8"),
        source_ref="monitoring-feed:EVAL-K-SOON",
        captured_by="eval",
    )  # identified: initial deadline 2026-11-01, 7 days out at as_of
    closed_case = Case(
        alert_id="EVAL-K-CLOSED",
        customer_id="CUST-K5",
        account_id="ACCT-K5",
        rule_id="TM-CLOCK-01",
        detected_on=date(2026, 8, 1),
        status=CaseStatus.CLOSED,
        disposition=Disposition(
            analyst="e.okafor",
            decision="close",
            reason_code="NO_SUSPICIOUS_ACTIVITY_IDENTIFIED",
            decided_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        ),
    )
    k_store.create_case(closed_case)
    k_store.add_disposition(
        DispositionRecord(
            case_id=closed_case.case_id,
            analyst_id="e.okafor",
            analyst_role="analyst",
            outcome=DispositionOutcome.CLOSE_NO_ACTION,
            rationale_codes=["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"],
            rationale_vocabulary_version="2026.10.1",
            record_id="inv-k",
            record_version=1,
            decided_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        )
    )
    queue = k_clocks.escalation_queue(as_of=date(2026, 10, 25))
    queue_ids = [e.case_id for e in queue]
    over_entries = [e for e in queue if e.case_id == over_case.case_id]
    if not over_entries or over_entries[0].state is not ClockState.OVERDUE:
        counters["clock_overdue_missing_from_queue"] += 1
    soon_entries = [e for e in queue if e.case_id == soon_case.case_id]
    if not soon_entries or soon_entries[0].state is not ClockState.DUE_SOON:
        counters["clock_positive_paths_failed"] += 1
    if (
        over_case.case_id in queue_ids
        and soon_case.case_id in queue_ids
        and queue_ids.index(over_case.case_id)
        > queue_ids.index(soon_case.case_id)
    ):
        counters["clock_positive_paths_failed"] += 1
    if prior.case_id in queue_ids or closed_case.case_id in queue_ids:
        counters["clock_terminal_still_escalated"] += 1
    first = k_clocks.refresh_escalations(
        over_case.case_id, as_of=date(2026, 10, 25)
    )
    second = k_clocks.refresh_escalations(
        over_case.case_id, as_of=date(2026, 10, 25)
    )
    recorded = k_clocks.recorded_escalations(over_case.case_id)
    counters["clock_escalations_recorded"] += len(recorded)
    if len(first) != 1 or second != [] or len(recorded) != 1:
        counters["clock_duplicate_escalation_events"] += 1
    try:
        k_evidence.verify_chain(over_case.case_id)
    except Exception:
        counters["chains_failed"] += 1

    # 11f: a terminal case with no disposition anywhere on its
    # record is a clock violation — detected, never silent.
    forged = Case(
        alert_id="EVAL-K-FORGED",
        customer_id="CUST-K6",
        account_id="ACCT-K6",
        rule_id="TM-CLOCK-01",
        detected_on=date(2026, 8, 1),
        status=CaseStatus.CLOSED,
    )
    k_store.create_case(forged)
    forged_view = k_clocks.case_clocks(forged.case_id, as_of=date(2026, 10, 25))
    if "terminal_without_disposition" not in forged_view.violations:
        counters["clock_terminal_violation_undetected"] += 1
    if forged_view.filing.state is ClockState.CLOSED_NO_FILE:
        counters["clock_positive_paths_failed"] += 1

    print("Blueprint #15 evals — R1+R2+R3+R4+R5+R6+R7+R8 counters")
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
        "investigation_citation_failures",
        "investigation_unresolvable_accepted",
        "investigation_hypothesis_incomplete",
        "investigation_hypothesis_wrong",
        "investigation_open_questions_missing",
        "investigation_figure_provenance_failures",
        "investigation_rerun_duplicated",
        "disposition_anonymous_accepted",
        "disposition_without_record_accepted",
        "disposition_sanctions_blocked_accepted",
        "disposition_self_confirmation_accepted",
        "disposition_free_text_only_accepted",
        "disposition_stale_unflagged",
        "disposition_stale_citation_accepted",
        "disposition_positive_paths_failed",
        "sar_draft_non_sar_pending_accepted",
        "sar_unverifiable_marked_verified",
        "sar_figure_not_in_records_accepted",
        "sar_open_questions_omitted",
        "sar_stale_still_verified",
        "sar_positive_paths_failed",
        "sar_self_approval_accepted",
        "sar_dispositioner_approval_accepted",
        "sar_unverified_approval_accepted",
        "sar_anonymous_approval_accepted",
        "sealed_case_mutations_accepted",
        "tampered_export_verified",
        "seal_incomplete_accepted",
        "r7_positive_paths_failed",
        "clock_wrong_deadline",
        "clock_state_wrong",
        "clock_overdue_missing_from_queue",
        "clock_terminal_still_escalated",
        "clock_duplicate_escalation_events",
        "clock_terminal_violation_undetected",
        "clock_positive_paths_failed",
    ]
    passed = all(counters[k] == 0 for k in zero_tolerance) and counters["cases_opened"] == len(ALERTS)
    print("GATE: PASS" if passed else "GATE: FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
