"""R9 continuing-activity reviews over HTTP: open a review, read
it (per case and per customer), record the cycle's decision —
and the refusal mapping (a refused review action is a 422 with
the reason named; a missing review is a 404).
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
from aml_investigations.gateway import ModelGateway, default_gateway_config
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.investigation import InvestigationService
from aml_investigations.media import AdverseMediaService, ListMediaFeed
from aml_investigations.models import Alert, RulePack
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.profiles import ProfileService
from aml_investigations.quarantine import QuarantineService
from aml_investigations.reporting import ReportingService
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
    ANALYST,
    CUSTOMER_SUBJECT,
    SANCTIONS,
    STRUCTURING_STREAM,
    identity_alert,
    profile,
)

REVIEWER = "b.osei"


@pytest.fixture()
def services(tmp_path: Path) -> Services:
    store = InMemoryCaseStore()
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects, seal_store=store)
    quarantine = QuarantineService(store, evidence, seal_store=store)
    evidence.quarantine = quarantine
    gateway = ModelGateway(
        default_gateway_config(), store, audit_store=store, evidence=evidence
    )
    workflow = CaseWorkflow(store, screening_store=store)
    feed = ListAlertFeed(
        [identity_alert("ALRT-S-1"), identity_alert("ALRT-R9-2")]
    )
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
        gateway=gateway,
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
        model_profiles_path=tmp_path / "profiles.json",
        model_prices_path=tmp_path / "prices.json",
        model_profile="offline",
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
        gateway=gateway,
        reports=ReportingService(
            store,
            clocks,
            screening_store=store,
            typology_store=store,
            investigation_store=store,
            disposition_store=store,
            narrative_store=store,
            approval_store=store,
            review_store=store,
            media_store=store,
            ledger_store=store,
            quarantine=quarantine,
        ),
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


def _investigated_case(client: TestClient, alert_id: str) -> tuple[str, dict]:
    response = client.post("/alerts/intake", json={"alert_id": alert_id})
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
    return case_id, record


def _filed_prior(client: TestClient) -> str:
    case_id, record = _investigated_case(client, "ALRT-S-1")
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
    response = client.post(f"/cases/{case_id}/sar/draft", json={})
    assert response.status_code == 201, response.text
    response = client.post(
        f"/cases/{case_id}/sar/approve",
        json={
            "approver_id": "m.rivera",
            "approver_role": "senior_analyst",
            "outcome": "approved",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["case_status"] == "filed_sar"
    return case_id


def test_review_endpoints_end_to_end(client):
    prior_id = _filed_prior(client)
    case_id, _record = _investigated_case(client, "ALRT-R9-2")

    response = client.post(
        f"/cases/{case_id}/continuing-reviews",
        json={"actor": REVIEWER},
    )
    assert response.status_code == 201, response.text
    review = response.json()["review"]
    assert review["cycle"] == 1
    assert review["prior_case_id"] == prior_id
    assert review["status"] == "open"
    review_id = review["review_id"]

    # One open review per cycle, over HTTP too.
    response = client.post(
        f"/cases/{case_id}/continuing-reviews",
        json={"actor": REVIEWER},
    )
    assert response.status_code == 422, response.text

    response = client.get(f"/cases/{case_id}/continuing-reviews")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["current"]["review_id"] == review_id
    assert [r["review_id"] for r in body["history"]] == [review_id]
    assert len(body["continuing_cycles"]) == 1
    assert body["continuing_cycles"][0]["answered_by_review_id"] is None

    response = client.get(
        f"/cases/{case_id}/continuing-reviews/{review_id}"
    )
    assert response.status_code == 200, response.text
    assert response.json()["review_id"] == review_id

    response = client.get(
        f"/cases/{case_id}/continuing-reviews/crev-missing"
    )
    assert response.status_code == 404, response.text

    # A decision without coded rationale is refused.
    response = client.post(
        f"/cases/{case_id}/continuing-reviews/{review_id}/disposition",
        json={
            "analyst_id": REVIEWER,
            "analyst_role": "senior_analyst",
            "outcome": "file_continuing",
            "rationale_codes": [],
        },
    )
    assert response.status_code == 422, response.text

    response = client.post(
        f"/cases/{case_id}/continuing-reviews/{review_id}/disposition",
        json={
            "analyst_id": REVIEWER,
            "analyst_role": "senior_analyst",
            "outcome": "file_continuing",
            "rationale_codes": ["STRUCTURING_SUSPECTED"],
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["case_status"] == "sar_pending"
    assert body["disposition"]["case_disposition_id"]
    assert body["review"]["status"] == "decided_file_continuing"

    response = client.get("/customers/CUST-T-1/continuing-reviews")
    assert response.status_code == 200, response.text
    history = response.json()
    assert [r["review_id"] for r in history["reviews"]] == [review_id]
    assert len(history["dispositions"]) == 1
    assert history["dispositions"][0]["outcome"] == "file_continuing"


def test_open_review_on_a_case_without_a_clock_is_422(client):
    prior_id = _filed_prior(client)
    response = client.post(
        f"/cases/{prior_id}/continuing-reviews",
        json={"actor": REVIEWER},
    )
    assert response.status_code == 422, response.text


def test_open_due_tick_endpoint(client):
    _filed_prior(client)
    _investigated_case(client, "ALRT-R9-2")
    response = client.post(
        "/continuing-reviews/open-due", json={"as_of": "2020-01-01"}
    )
    assert response.status_code == 201, response.text
    assert response.json()["opened"] == []
