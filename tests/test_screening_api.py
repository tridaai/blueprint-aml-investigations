"""R2 screening API: snapshot ingest, pinned runs, hit disposition."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aml_investigations.api import create_app
from tests.test_screening import adverse_v1, pep_v1, sanctions_v1, sanctions_v2


@pytest.fixture()
def client(services) -> TestClient:
    return TestClient(create_app(services), headers={"x-caller-id": "t.officer", "x-caller-role": "bsa_officer"})


def _ingest(client: TestClient, snapshot) -> dict:
    response = client.post(
        "/screening/snapshots", json=snapshot.model_dump(mode="json")
    )
    assert response.status_code == 201, response.text
    return response.json()


def _intake_okafor(client: TestClient, services) -> str:
    from aml_investigations.intake import IntakeService, ListAlertFeed
    from tests.test_screening import okafor_alert

    intake = IntakeService(
        services.store, ListAlertFeed([okafor_alert("ALRT-API-1")]), services.evidence
    )
    return intake.open_case("ALRT-API-1").case_id


def test_snapshot_ingest_and_list(client):
    body = _ingest(client, sanctions_v1())
    assert body["content_hash"]
    assert len(body["entries"]) == 2
    listed = client.get("/screening/snapshots", params={"kind": "sanctions"})
    assert listed.status_code == 200
    assert [s["version"] for s in listed.json()] == ["2026.10.1"]


def test_snapshot_conflict_is_409(client):
    _ingest(client, sanctions_v1())
    mutated = sanctions_v1().model_copy(
        update={"content_hash": "", "entries": sanctions_v1().entries[:1]}
    )
    response = client.post(
        "/screening/snapshots", json=mutated.model_dump(mode="json")
    )
    assert response.status_code == 409


def test_screen_without_pins_is_422(client, services):
    _ingest(client, sanctions_v1())
    case_id = _intake_okafor(client, services)
    response = client.post(
        f"/cases/{case_id}/screening",
        json={"pins": {}, "actor": "screening-service"},
    )
    assert response.status_code == 422


def test_screen_unknown_version_is_404(client, services):
    _ingest(client, sanctions_v1())
    case_id = _intake_okafor(client, services)
    response = client.post(
        f"/cases/{case_id}/screening",
        json={"pins": {"sanctions": "1999.01.1"}, "actor": "screening-service"},
    )
    assert response.status_code == 404


def test_full_screening_flow_over_api(client, services):
    _ingest(client, sanctions_v1())
    _ingest(client, pep_v1())
    _ingest(client, adverse_v1())
    case_id = _intake_okafor(client, services)

    response = client.post(
        f"/cases/{case_id}/screening",
        json={
            "pins": {
                "sanctions": "2026.10.1",
                "pep": "2026.10.1",
                "adverse_media": "2026.10.1",
            },
            "actor": "screening-service",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["run"]["open_hits"] == 0
    assert body["run"]["cleared_hits"] == 1  # the Viktor Petrov namesake

    view = client.get(f"/cases/{case_id}/screening")
    assert view.status_code == 200
    view = view.json()
    assert view["screening_stale"] is False
    assert len(view["runs"]) == 1

    # The delta lands: the case flags stale, then hits on re-screen.
    _ingest(client, sanctions_v2())
    view = client.get(f"/cases/{case_id}/screening").json()
    assert view["screening_stale"] is True
    assert "STALE_SCREENING" in view["flags"]

    response = client.post(
        f"/cases/{case_id}/screening",
        json={"pins": {"sanctions": "2026.10.2"}, "actor": "screening-service"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["run"]["open_hits"] == 1
    hit = next(h for h in body["hits"] if h["entry_id"] == "SDN-1004")
    assert hit["status"] == "open"

    # Plain close is refused over the API too (409), with the hit open.
    for target in ("assembling", "investigating", "awaiting_analyst"):
        r = client.post(
            f"/cases/{case_id}/transitions",
            json={"target": target, "actor": "investigation-service"},
        )
        assert r.status_code == 200, r.text
    r = client.post(
        f"/cases/{case_id}/transitions",
        json={
            "target": "closed",
            "actor": "analyst:j.rivera",
            "disposition": {
                "analyst": "j.rivera",
                "decision": "close",
                "reason_code": "BENIGN",
            },
        },
    )
    assert r.status_code == 409
    assert "sanctions" in r.json()["detail"]

    # Clearing the hit with a reason re-opens the close path.
    r = client.post(
        f"/screening/hits/{hit['hit_id']}/status",
        json={
            "status": "cleared",
            "actor": "analyst:j.rivera",
            "reason": "Passport on file predates the listing; different person.",
        },
    )
    assert r.status_code == 200
    assert r.json()["status"] == "cleared"
    r = client.post(
        f"/cases/{case_id}/transitions",
        json={
            "target": "closed",
            "actor": "analyst:j.rivera",
            "disposition": {
                "analyst": "j.rivera",
                "decision": "close",
                "reason_code": "HIT_CLEARED",
            },
        },
    )
    assert r.status_code == 200
    assert r.json()["status"] == "closed"


def test_hit_status_unknown_hit_is_404(client):
    response = client.post(
        "/screening/hits/hit-nope/status",
        json={"status": "cleared", "actor": "analyst:j.rivera", "reason": "x"},
    )
    assert response.status_code == 404
