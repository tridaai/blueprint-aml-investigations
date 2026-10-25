"""API surface: health, readiness, intake, transitions, evidence."""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from aml_investigations.api import create_app


@pytest.fixture()
def client(services) -> TestClient:
    return TestClient(create_app(services))


def _intake(client: TestClient) -> str:
    response = client.post("/alerts/intake", json={"alert_id": "ALRT-T-001"})
    assert response.status_code == 201
    return response.json()["case_id"]


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness(client):
    response = client.get("/readiness")
    assert response.status_code == 200
    assert response.json()["ready"] is True


def test_request_id_header(client):
    response = client.get("/health")
    assert response.headers.get("x-request-id")


def test_intake_and_case_readback(client):
    case_id = _intake(client)
    response = client.get(f"/cases/{case_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "opened"
    assert body["detected_on"] == "2026-10-20"


def test_unknown_case_is_404(client):
    assert client.get("/cases/case-missing").status_code == 404


def test_close_without_disposition_is_422(client):
    case_id = _intake(client)
    for target in ("assembling", "investigating", "awaiting_analyst"):
        r = client.post(
            f"/cases/{case_id}/transitions",
            json={"target": target, "actor": "investigation-service"},
        )
        assert r.status_code == 200
    r = client.post(
        f"/cases/{case_id}/transitions",
        json={"target": "closed", "actor": "analyst:j.rivera"},
    )
    assert r.status_code == 422


def test_illegal_transition_is_409(client):
    case_id = _intake(client)
    r = client.post(
        f"/cases/{case_id}/transitions",
        json={"target": "closed", "actor": "analyst:j.rivera"},
    )
    assert r.status_code == 409


def test_full_close_over_api(client):
    case_id = _intake(client)
    for target in ("assembling", "investigating", "awaiting_analyst"):
        client.post(
            f"/cases/{case_id}/transitions",
            json={"target": target, "actor": "investigation-service"},
        )
    r = client.post(
        f"/cases/{case_id}/transitions",
        json={
            "target": "closed",
            "actor": "analyst:j.rivera",
            "disposition": {
                "analyst": "j.rivera",
                "decision": "close",
                "reason_code": "BENIGN_EXPLANATION_DOCUMENTED",
                "rationale": "Matches the documented business profile.",
            },
        },
    )
    assert r.status_code == 200
    assert r.json()["status"] == "closed"


def test_evidence_round_trip_and_verify(client):
    case_id = _intake(client)
    payload = base64.b64encode(b'{"window_days": 30}').decode()
    r = client.post(
        f"/cases/{case_id}/evidence",
        json={
            "kind": "transaction_window",
            "content_base64": payload,
            "source_ref": "core-banking:ACCT-5001/30d",
            "captured_by": "evidence-service",
        },
    )
    assert r.status_code == 201
    assert r.json()["seq"] == 2
    r = client.get(f"/cases/{case_id}/evidence")
    assert len(r.json()) == 2
    r = client.get(f"/cases/{case_id}/evidence/verify")
    assert r.json() == {"case_id": case_id, "chain_intact": True}
    r = client.get(f"/cases/{case_id}/audit")
    events = [e["event"] for e in r.json()]
    assert "case_opened" in events and "evidence_added" in events
