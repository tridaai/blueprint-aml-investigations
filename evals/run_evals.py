"""R1 eval gate for Blueprint #15 — AML Alert Investigation & Case File Agent.

Runs the R1 scenarios against an in-memory stack (no disk, no
network, no keys) and reports the counters that exist so far. Later
rounds extend this gate: screening/version-pin counters (R2),
typology accuracy (R3), citation support (R4/R6), clock compliance
(R8), injection quarantine (R10), trap suites (R15).

Zero-tolerance counters at R1:
  - cases closed without an analyst disposition ... must be 0
  - unlawful transitions accepted .................. must be 0
  - evidence chains failing verification ........... must be 0
  - duplicate cases per alert ...................... must be 0

Exit code 0 iff the gate passes.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aml_investigations.errors import IllegalTransitionError  # noqa: E402
from aml_investigations.evidence import EvidenceService  # noqa: E402
from aml_investigations.intake import IntakeService, ListAlertFeed  # noqa: E402
from aml_investigations.models import Alert, CaseStatus, Disposition  # noqa: E402
from aml_investigations.object_store import LocalObjectStore  # noqa: E402
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
]


def main() -> int:
    counters = {
        "cases_opened": 0,
        "closed_without_disposition": 0,
        "unlawful_transitions_accepted": 0,
        "chains_failed": 0,
        "duplicate_cases": 0,
        "audit_gaps": 0,
    }

    store = InMemoryCaseStore()
    objects = LocalObjectStore(Path(tempfile.mkdtemp(prefix="aml-evals-")))
    evidence = EvidenceService(store, objects)
    workflow = CaseWorkflow(store)
    intake = IntakeService(store, ListAlertFeed(list(ALERTS)), evidence)

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

    print("Blueprint #15 evals — R1 counters")
    for key, value in counters.items():
        print(f"  {key}: {value}")
    zero_tolerance = [
        "closed_without_disposition",
        "unlawful_transitions_accepted",
        "chains_failed",
        "duplicate_cases",
        "audit_gaps",
    ]
    passed = all(counters[k] == 0 for k in zero_tolerance) and counters["cases_opened"] == len(ALERTS)
    print("GATE: PASS" if passed else "GATE: FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
