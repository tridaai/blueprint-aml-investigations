"""Offline demo: one seeded alert walked end to end through the spine.

Opens a case from the reference feed, adds a transaction-window
evidence item, screens the case against pinned list snapshots (R2 —
the counterparty is a namesake: same name as a listed person, a
different date of birth, recorded as a cleared hit), walks the case
through its lawful states to the analyst gate, records an analyst
disposition closing the case, and verifies the evidence hash chain.
Runs entirely on in-memory doubles — no disk, no network, no keys.
"""

from __future__ import annotations

import json

from .evidence import EvidenceService
from .intake import IntakeService, ListAlertFeed
from .models import Alert, CaseStatus, Disposition, ListEntry, ListKind, ListSnapshot
from .object_store import LocalObjectStore
from .screening import ScreeningService
from .stores import InMemoryCaseStore
from .workflow import CaseWorkflow
import tempfile
from pathlib import Path


def run_demo() -> dict:
    store = InMemoryCaseStore()
    objects = LocalObjectStore(Path(tempfile.mkdtemp(prefix="aml-demo-")))
    evidence = EvidenceService(store, objects)
    workflow = CaseWorkflow(store, screening_store=store)
    screening = ScreeningService(store, store, evidence)

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
                raw={
                    "customer_name": "Daniel Okafor",
                    "customer_dob": "1985-03-04",
                    "counterparties": [
                        {"name": "Viktor Petrov", "dob": "1979-06-02"}
                    ],
                },
            )
        ]
    )
    intake = IntakeService(store, feed, evidence)
    case = intake.open_case("ALRT-DEMO-001")

    screening.ingest_snapshot(
        ListSnapshot(
            list_kind=ListKind.SANCTIONS,
            version="2026.10.1",
            published_at="2026-10-01T00:00:00Z",
            source_note="Demo sanctions snapshot (stand-in).",
            entries=[
                ListEntry(
                    entry_id="SDN-1001",
                    name="Viktor Petrov",
                    dob="1962-04-11",
                    identifiers=["PP-XK-4471"],
                )
            ],
        )
    )
    run = screening.screen_case(
        case.case_id,
        {ListKind.SANCTIONS: "2026.10.1"},
        actor="screening-service",
    )
    screening_summary = {
        "run_id": run.run_id,
        "pins": {p.list_kind.value: p.version for p in run.pins},
        "open_hits": run.open_hits,
        "cleared_hits": run.cleared_hits,
    }

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
        "screening": screening_summary,
        "evidence_items": len(store.list_evidence(case.case_id)),
        "chain_intact": intact,
        "audit_events": len(store.list_audit(case.case_id)),
    }


def main() -> int:
    print(json.dumps(run_demo(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
