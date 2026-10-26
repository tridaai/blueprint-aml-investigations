"""R12 adverse-media surface over HTTP."""

from __future__ import annotations

from fastapi.testclient import TestClient

from aml_investigations.api import create_app
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.media import AdverseMediaService, ListMediaFeed
from aml_investigations.models import CaseStatus
from tests.test_media import ARTICLES, alert_m1


def _client(services) -> TestClient:
    services.media = AdverseMediaService(
        services.store,
        services.store,
        services.evidence,
        ListMediaFeed(list(ARTICLES)),
        seal_store=services.store,
        quarantine=services.quarantine,
        profile_service=services.profiles,
        typology_store=services.store,
    )
    return TestClient(create_app(services), headers={"x-caller-id": "t.officer", "x-caller-role": "bsa_officer"})


def _seed(services) -> str:
    intake = IntakeService(
        services.store, ListAlertFeed([alert_m1()]), services.evidence
    )
    case = intake.open_case("ALRT-M-1")
    services.workflow.transition(
        case.case_id, CaseStatus.ASSEMBLING, actor="test"
    )
    return case.case_id


def test_media_endpoints_end_to_end(services):
    case_id = _seed(services)
    client = _client(services)

    empty = client.get(f"/cases/{case_id}/media/assessments")
    assert empty.status_code == 200
    assert empty.json()["assessments"] == []

    created = client.post(
        f"/cases/{case_id}/media/search",
        json={"as_of": "2026-10-20", "actor": "media-service"},
    )
    assert created.status_code == 201
    results = created.json()
    assert len(results) == len(ARTICLES)
    bands = {a["article_id"]: a["band"] for a in results}
    assert bands["ART-M1"] == "strong"
    assert bands["ART-M2"] == "namesake_cleared"
    assert bands["ART-M3"] == "possible"
    assert bands["ART-M4"] == "irrelevant"

    listed = client.get(f"/cases/{case_id}/media/assessments")
    assert listed.status_code == 200
    assert len(listed.json()["assessments"]) == len(ARTICLES)

    one = next(a for a in results if a["article_id"] == "ART-M1")
    detail = client.get(
        f"/cases/{case_id}/media/assessments/{one['assessment_id']}"
    )
    assert detail.status_code == 200
    body = detail.json()
    assert body["band"] == "strong"
    assert body["scorer_version"] == "2026.10.1"
    assert body["taxonomy_version"] == "2026.10.1"
    signals = {s["signal"]: s["outcome"] for s in body["signals"]}
    assert signals["dob"] == "supports"

    # The search moved no case state.
    case = client.get(f"/cases/{case_id}")
    assert case.json()["status"] == "assembling"


def test_media_endpoints_not_found(services):
    case_id = _seed(services)
    client = _client(services)

    missing_case = client.get("/cases/case-nope/media/assessments")
    assert missing_case.status_code == 404

    missing_search = client.post(
        "/cases/case-nope/media/search", json={"actor": "media-service"}
    )
    assert missing_search.status_code == 404

    missing_assessment = client.get(
        f"/cases/{case_id}/media/assessments/med-nope"
    )
    assert missing_assessment.status_code == 404
