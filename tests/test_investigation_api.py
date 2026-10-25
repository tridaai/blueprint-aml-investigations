"""R4 investigation API: run a case's investigation, read the
current record and its history, and the error mapping."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aml_investigations.api import create_app


@pytest.fixture()
def client(services) -> TestClient:
    return TestClient(create_app(services))


def _to_investigating(client: TestClient) -> str:
    response = client.post("/alerts/intake", json={"alert_id": "ALRT-T-001"})
    assert response.status_code == 201
    case_id = response.json()["case_id"]
    for target in ("assembling", "investigating"):
        response = client.post(
            f"/cases/{case_id}/transitions",
            json={"target": target, "actor": "test"},
        )
        assert response.status_code == 200
    return case_id


def test_run_and_read_back(client):
    case_id = _to_investigating(client)
    response = client.post(
        f"/cases/{case_id}/investigation/run", json={"actor": "analyst"}
    )
    assert response.status_code == 201
    record = response.json()
    assert record["version"] == 1
    assert record["model_profile"] == "offline"
    assert record["hypothesis"]["label"] == "no_adverse_pattern"
    assert record["counter_search"]["ran"] is True
    assert record["evidence_seq"] is not None
    assert record["findings"], "at minimum the alert finding is recorded"
    for finding in record["findings"]:
        assert finding["citations"], finding["finding_id"]

    response = client.get(f"/cases/{case_id}/investigation")
    assert response.status_code == 200
    body = response.json()
    assert body["current"]["record_id"] == record["record_id"]
    assert len(body["history"]) == 1


def test_run_requires_investigating_state(client):
    response = client.post("/alerts/intake", json={"alert_id": "ALRT-T-001"})
    case_id = response.json()["case_id"]
    response = client.post(
        f"/cases/{case_id}/investigation/run", json={"actor": "analyst"}
    )
    assert response.status_code == 409


def test_run_unknown_case_is_404(client):
    response = client.post(
        "/cases/case-nope/investigation/run", json={"actor": "analyst"}
    )
    assert response.status_code == 404
    response = client.get("/cases/case-nope/investigation")
    assert response.status_code == 404


def test_unconfigured_live_profile_is_422(client):
    case_id = _to_investigating(client)
    response = client.post(
        f"/cases/{case_id}/investigation/run",
        json={"actor": "analyst", "profile": "hosted-frontier"},
    )
    assert response.status_code == 422
    response = client.get(f"/cases/{case_id}/investigation")
    assert response.json()["current"] is None


def test_investigation_empty_before_first_run(client):
    case_id = _to_investigating(client)
    response = client.get(f"/cases/{case_id}/investigation")
    assert response.status_code == 200
    assert response.json()["current"] is None
    assert response.json()["history"] == []
