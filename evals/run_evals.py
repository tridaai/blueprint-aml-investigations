"""Eval gate for Blueprint #15 — AML Alert Investigation & Case File Agent.

Runs the scenarios against an in-memory stack (no disk, no network,
no keys) and reports the counters that exist so far. Later rounds
extend this gate: typology accuracy (R3), citation support (R4/R6),
clock compliance (R8), injection quarantine (R10), trap suites (R15).

Zero-tolerance counters:
  - cases closed without an analyst disposition ... must be 0
  - unlawful transitions accepted .................. must be 0
  - evidence chains failing verification ........... must be 0
  - duplicate cases per alert ...................... must be 0
  - screening runs accepted without a pin (R2) ..... must be 0
  - stale screenings left unflagged (R2) ........... must be 0
  - plain closes accepted over a sanctions hit (R2)  must be 0

Exit code 0 iff the gate passes.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aml_investigations.errors import (  # noqa: E402
    IllegalTransitionError,
    ScreeningPinRequiredError,
)
from aml_investigations.evidence import EvidenceService  # noqa: E402
from aml_investigations.intake import IntakeService, ListAlertFeed  # noqa: E402
from aml_investigations.models import (  # noqa: E402
    Alert,
    CaseStatus,
    Disposition,
    HitStatus,
    ListEntry,
    ListKind,
    ListSnapshot,
)
from aml_investigations.object_store import LocalObjectStore  # noqa: E402
from aml_investigations.screening import ScreeningService  # noqa: E402
from aml_investigations.stores import InMemoryCaseStore  # noqa: E402
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

    print("Blueprint #15 evals — R1+R2 counters")
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
    ]
    passed = all(counters[k] == 0 for k in zero_tolerance) and counters["cases_opened"] == len(ALERTS)
    print("GATE: PASS" if passed else "GATE: FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
