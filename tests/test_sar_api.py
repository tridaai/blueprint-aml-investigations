"""R6 SAR API: draft a narrative for a sar_pending case, fetch the
current draft and its history, re-run the citation verifier, read
the verification record — and the refusal mapping (drafting gates
are 422 with the reason named; a missing narrative is a 404).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aml_investigations.api import create_app
from aml_investigations.approval import SarApprovalService
from aml_investigations.clocks import RegulatoryClockService
from aml_investigations.config import Settings
from aml_investigations.dispositions import DispositionService
from aml_investigations.evidence import EvidenceService
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.investigation import InvestigationService
from aml_investigations.media import AdverseMediaService, ListMediaFeed
from aml_investigations.models import Alert, RulePack
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.profiles import ProfileService
from aml_investigations.quarantine import QuarantineService
from aml_investigations.reviews import ContinuingReviewService
from aml_investigations.sar import SarNarrativeService
from aml_investigations.screening import ListScreeningFeed, ScreeningService
from aml_investigations.sealing import CaseSealingService
from aml_investigations.stores import InMemoryCaseStore
from aml_investigations.transactions import (
    ListRulePackFeed,
    ListTransactionFeed,
)
from aml_investigations.typologies import TypologyService
from aml_investigations.wiring import Services
from aml_investigations.workflow import CaseWorkflow
from tests.test_sar import (
    ACCOUNT,
    CUSTOMER_SUBJECT,
    SANCTIONS,
    STRUCTURING_STREAM,
    profile,
)

ANALYST = "a.okafor"


def _alert() -> Alert:
    return Alert(
        alert_id="ALRT-A-1",
        rule_id="TM-STRUCTURING-01",
        customer_id="CUST-T-1",
        account_id=ACCOUNT,
        severity="high",
        detected_on="2026-03-07",
        summary="Cash deposits clustering under the CTR threshold.",
        raw={
            "customer_name": "Daniel Okafor",
            "customer_dob": "1985-03-04",
            "customer_identifiers": ["PP-NG-2210"],
            "counterparties": [],
        },
    )


@pytest.fixture()
def services(tmp_path: Path) -> Services:
    store = InMemoryCaseStore()
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects, seal_store=store)
    quarantine = QuarantineService(store, evidence, seal_store=store)
    evidence.quarantine = quarantine
    workflow = CaseWorkflow(store, screening_store=store)
    feed = ListAlertFeed([_alert()])
    clocks = RegulatoryClockService(
        store, store, store, evidence, approvals=store, review_store=store
    )
    intake = IntakeService(
        store, feed, evidence, clock_service=clocks, quarantine=quarantine
    )
    screening = ScreeningService(
        store, store, evidence, seal_store=store, quarantine=quarantine
    )
    typologies = TypologyService(
        store, store, evidence, seal_store=store, quarantine=quarantine
    )
    investigations = InvestigationService(
        store,
        store,
        store,
        store,
        evidence,
        disposition_store=store,
        seal_store=store,
        quarantine=quarantine,
        media_store=store,
    )
    dispositions = DispositionService(
        store, store, store, store, evidence, workflow, seal_store=store
    )
    sar = SarNarrativeService(
        store,
        store,
        store,
        store,
        evidence,
        approval_store=store,
        seal_store=store,
        review_store=store,
        quarantine=quarantine,
    )
    approvals = SarApprovalService(
        store, store, store, store, sar, evidence, workflow, seal_store=store
    )
    sealing = CaseSealingService(
        store, store, store, store, store, evidence, store
    )
    reviews = ContinuingReviewService(
        store,
        store,
        store,
        store,
        store,
        store,
        store,
        evidence,
        clocks,
        dispositions,
        seal_store=store,
        quarantine=quarantine,
    )
    profiles = ProfileService(
        store,
        store,
        store,
        store,
        evidence,
        dispositions=dispositions,
        approval_store=store,
        quarantine=quarantine,
    )
    media_feed = ListMediaFeed([])
    media = AdverseMediaService(
        store,
        store,
        evidence,
        media_feed,
        seal_store=store,
        quarantine=quarantine,
        profile_service=profiles,
        typology_store=store,
    )
    settings = Settings(
        database_url=None,
        sqlite_path=tmp_path / "aml.db",
        migrations_dir=tmp_path,
        object_store_dir=tmp_path / "objects",
        s3_endpoint_url=None,
        s3_bucket="aml-evidence",
        seed_alerts_path=tmp_path / "seed.json",
        screening_lists_path=tmp_path / "lists.json",
        transaction_streams_path=tmp_path / "streams.json",
        typology_rules_path=tmp_path / "rules.json",
        adverse_media_path=tmp_path / "media.json",
        log_level="INFO",
    )
    return Services(
        settings=settings,
        store=store,
        objects=objects,
        evidence=evidence,
        workflow=workflow,
        alerts=feed,
        intake=intake,
        screening=screening,
        screening_feed=ListScreeningFeed([SANCTIONS]),
        transactions=ListTransactionFeed(
            [profile()], {ACCOUNT: STRUCTURING_STREAM}
        ),
        typologies=typologies,
        rule_pack_feed=ListRulePackFeed(
            [RulePack(pack_id="test-pack", version="1.0")]
        ),
        investigations=investigations,
        dispositions=dispositions,
        sar=sar,
        approvals=approvals,
        sealing=sealing,
        clocks=clocks,
        reviews=reviews,
        quarantine=quarantine,
        profiles=profiles,
        media_feed=media_feed,
        media=media,
    )


@pytest.fixture()
def client(services) -> TestClient:
    return TestClient(create_app(services))


def _transition(client: TestClient, case_id: str, target: str) -> None:
    response = client.post(
        f"/cases/{case_id}/transitions",
        json={"target": target, "actor": "test"},
    )
    assert response.status_code == 200, response.text


def _sar_pending_case(client: TestClient) -> tuple[str, dict]:
    """Walk one case over HTTP to the sar_pending state."""
    response = client.post("/alerts/intake", json={"alert_id": "ALRT-A-1"})
    assert response.status_code == 201, response.text
    case_id = response.json()["case_id"]
    _transition(client, case_id, "assembling")
    response = client.post("/screening/snapshots/ingest-feed")
    assert response.status_code == 201, response.text
    response = client.post(
        f"/cases/{case_id}/screening",
        json={
            "pins": {"sanctions": "2026.10.1"},
            "actor": "test",
            "subjects": [CUSTOMER_SUBJECT.model_dump(mode="json")],
        },
    )
    assert response.status_code == 201, response.text
    response = client.post(f"/cases/{case_id}/transactions/ingest-feed")
    assert response.status_code == 201, response.text
    response = client.post("/typologies/rule-packs/register-feed")
    assert response.status_code == 201, response.text
    response = client.post(
        f"/cases/{case_id}/typologies/run",
        json={"pack_id": "test-pack", "version": "1.0", "actor": "test"},
    )
    assert response.status_code == 201, response.text
    _transition(client, case_id, "investigating")
    response = client.post(
        f"/cases/{case_id}/investigation/run", json={"actor": "analyst"}
    )
    assert response.status_code == 201, response.text
    record = response.json()
    _transition(client, case_id, "awaiting_analyst")
    response = client.post(
        f"/cases/{case_id}/disposition",
        json={
            "analyst_id": ANALYST,
            "analyst_role": "analyst",
            "outcome": "escalate_sar",
            "rationale_codes": ["STRUCTURING_SUSPECTED"],
            "record_id": record["record_id"],
            "record_version": record["version"],
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["case_status"] == "sar_pending"
    return case_id, record


def test_draft_fetch_verify_over_http(client):
    case_id, _record = _sar_pending_case(client)
    response = client.post(f"/cases/{case_id}/sar/draft", json={})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["case_status"] == "sar_pending"
    assert body["narrative"]["status"] == "verified"
    assert body["narrative"]["version"] == 1
    assert body["verification"]["all_verified"] is True

    response = client.get(f"/cases/{case_id}/sar")
    assert response.status_code == 200
    body = response.json()
    assert body["current"]["status"] == "verified"
    assert len(body["history"]) == 1
    assert body["current"]["verification"]["all_verified"] is True

    response = client.post(f"/cases/{case_id}/sar/verify")
    assert response.status_code == 201, response.text
    assert response.json()["narrative_status"] == "verified"
    assert response.json()["verification"]["all_verified"] is True

    response = client.get(f"/cases/{case_id}/sar/verification")
    assert response.status_code == 200
    body = response.json()
    assert body["narrative_status"] == "verified"
    assert body["verification"]["all_verified"] is True
    assert all(
        v["verified"] for v in body["verification"]["statement_verdicts"]
    )


def test_draft_on_a_case_not_routed_to_sar_is_422(client):
    response = client.post("/alerts/intake", json={"alert_id": "ALRT-A-1"})
    case_id = response.json()["case_id"]
    response = client.post(f"/cases/{case_id}/sar/draft", json={})
    assert response.status_code == 422
    assert "case_not_sar_pending" in response.json()["detail"]


def test_sar_reads_before_any_draft(client):
    response = client.post("/alerts/intake", json={"alert_id": "ALRT-A-1"})
    case_id = response.json()["case_id"]
    response = client.get(f"/cases/{case_id}/sar")
    assert response.status_code == 200
    assert response.json()["current"] is None
    assert response.json()["history"] == []
    response = client.get(f"/cases/{case_id}/sar/verification")
    assert response.status_code == 404
    response = client.post(f"/cases/{case_id}/sar/verify")
    assert response.status_code == 404


def test_draft_with_live_profile_is_422_until_configured(client):
    case_id, _record = _sar_pending_case(client)
    response = client.post(
        f"/cases/{case_id}/sar/draft", json={"profile": "hosted-frontier"}
    )
    assert response.status_code == 422
    assert "hosted-frontier" in response.json()["detail"]
