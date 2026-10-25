"""Offline demo: one seeded alert walked end to end through R1's spine.

Opens a case from the reference feed, adds a transaction-window
evidence item, walks the case through its lawful states to the
analyst gate, records an analyst disposition closing the case, and
verifies the evidence hash chain. Runs entirely on in-memory
doubles — no disk, no network, no keys.
"""

from __future__ import annotations

import json

from .evidence import EvidenceService
from .intake import IntakeService, ListAlertFeed
from .models import Alert, CaseStatus, Disposition
from .object_store import LocalObjectStore
from .stores import InMemoryCaseStore
from .workflow import CaseWorkflow
import tempfile
from pathlib import Path


def run_demo() -> dict:
    store = InMemoryCaseStore()
    objects = LocalObjectStore(Path(tempfile.mkdtemp(prefix="aml-demo-")))
    evidence = EvidenceService(store, objects)
    workflow = CaseWorkflow(store)

    feed = ListAlertFeed(
        [
            Alert(
                alert_id="ALRT-DEMO-001",
                rule_id="TM-STRUCTURING-01",
                customer_id="CUST-1001",
                account_id="ACCT-5001",
                severity="high",
                detected_on="2026-10-20",
                summary="Cash deposits clustering just under the CTR threshold.",
                transaction_refs=["TXN-9001", "TXN-9002", "TXN-9003"],
            )
        ]
    )
    intake = IntakeService(store, feed, evidence)
    case = intake.open_case("ALRT-DEMO-001")

    evidence.add_item(
        case.case_id,
        kind="transaction_window",
        content=json.dumps(
            {"account_id": "ACCT-5001", "window_days": 30, "count": 3}
        ).encode(),
        source_ref="core-banking:ACCT-5001/30d",
        captured_by="evidence-service",
    )

    for target in (
        CaseStatus.ASSEMBLING,
        CaseStatus.INVESTIGATING,
        CaseStatus.AWAITING_ANALYST,
    ):
        case = workflow.transition(case.case_id, target=target, actor="investigation-service")
    case = workflow.transition(
        case.case_id,
        target=CaseStatus.CLOSED,
        actor="analyst:j.rivera",
        disposition=Disposition(
            analyst="j.rivera",
            decision="close",
            reason_code="BENIGN_EXPLANATION_DOCUMENTED",
            rationale="Deposits match the customer's documented cash-intensive business.",
        ),
    )
    intact = evidence.verify_chain(case.case_id)
    return {
        "case_id": case.case_id,
        "status": case.status.value,
        "disposition_analyst": case.disposition.analyst if case.disposition else None,
        "evidence_items": len(store.list_evidence(case.case_id)),
        "chain_intact": intact,
        "audit_events": len(store.list_audit(case.case_id)),
    }


def main() -> int:
    print(json.dumps(run_demo(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
