"""R11 profile + counterparty surface over HTTP."""

from __future__ import annotations

from fastapi.testclient import TestClient

from aml_investigations.api import create_app
from tests.test_profiles import (
    PROFILES,
    SANCTIONS,
    STREAMS,
    alert_a,
    alert_b,
    alert_c,
)
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.models import CaseStatus
from aml_investigations.transactions import ListTransactionFeed


def _client(services) -> TestClient:
    return TestClient(create_app(services), headers={"x-caller-id": "t.officer", "x-caller-role": "bsa_officer"})


def _seed(services):
    services.screening.ingest_snapshot(SANCTIONS)
    cases = {}
    for alert in (alert_a(), alert_b(), alert_c()):
        intake = IntakeService(
            services.store, ListAlertFeed([alert]), services.evidence
        )
        case = intake.open_case(alert.alert_id)
        services.workflow.transition(
            case.case_id, CaseStatus.ASSEMBLING, actor="test"
        )
        services.screening.screen_case(
            case.case_id, {SANCTIONS.list_kind: SANCTIONS.version},
            actor="test",
        )
        services.typologies.ingest_from_source(
            case.case_id,
            ListTransactionFeed(PROFILES, STREAMS),
            actor="test-feed",
        )
        cases[alert.customer_id] = case
    return cases


def test_profile_endpoints_end_to_end(services):
    cases = _seed(services)
    client = _client(services)

    missing = client.get("/customers/CUST-P1/profile")
    assert missing.status_code == 404

    created = client.post(
        "/customers/CUST-P1/profile",
        json={"as_of": "2026-03-20", "actor": "kyc-service"},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["customer_id"] == "CUST-P1"
    assert body["version"] == 1
    assert any(
        c["field"] == "dob" for c in body["identity_conflicts"]
    )

    latest = client.get("/customers/CUST-P1/profile")
    assert latest.status_code == 200
    assert latest.json()["profile_id"] == body["profile_id"]

    history = client.get("/customers/CUST-P1/profile/history")
    assert history.status_code == 200
    assert len(history.json()) == 1

    per_case = client.get(f"/cases/{cases['CUST-P1'].case_id}/profile")
    assert per_case.status_code == 200
    assert per_case.json()["profile_id"] == body["profile_id"]


def test_counterparty_endpoints(services):
    _seed(services)
    client = _client(services)

    listing = client.get("/customers/CUST-P1/counterparties")
    assert listing.status_code == 200
    by_name = {v["name_raw"]: v for v in listing.json()}
    assert by_name["Kestrel Trading LLC"]["total_in"] == "12000.00"
    assert by_name["Kestrel Trading LLC"]["total_out"] == "2200.25"
    assert by_name["Kestrel Trading LLC"]["customer_ids"] == [
        "CUST-P1",
        "CUST-P2",
    ]

    detail = client.get(
        "/customers/CUST-P1/counterparties/Kestrel Trading LLC"
    )
    assert detail.status_code == 200
    assert detail.json()["transaction_count"] == 5

    shared = client.get("/counterparties/shared")
    assert shared.status_code == 200
    assert [s["name_raw"] for s in shared.json()] == [
        "Kestrel Trading LLC"
    ]
    assert shared.json()[0]["total_in"] == "12900.00"


def test_profile_endpoints_404s(services):
    client = _client(services)
    assert (
        client.post(
            "/customers/CUST-NOPE/profile", json={"actor": "kyc"}
        ).status_code
        == 404
    )
    assert client.get("/customers/CUST-NOPE/profile").status_code == 404
    assert (
        client.get("/customers/CUST-NOPE/counterparties").status_code
        == 404
    )
    assert (
        client.get("/cases/case-nope/profile").status_code == 404
    )
