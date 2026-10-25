"""R7 API: the dual-control decision, sealing, legal hold, and
export over HTTP — status codes and refusal mapping (approval and
sealing refusals are 422 with the reason named; a mutation of a
sealed case is a 409 conflict)."""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from aml_investigations.api import create_app
from tests.test_sar_api import _sar_pending_case, services  # noqa: F401

ANALYST = "a.okafor"
APPROVER = "m.osei"
OFFICER = {"officer_id": "o.reyes", "officer_role": "l2_reviewer"}


@pytest.fixture()
def client(services) -> TestClient:  # noqa: F811
    return TestClient(create_app(services))


def _drafted_case(client: TestClient) -> str:
    case_id, _record = _sar_pending_case(client)
    response = client.post(f"/cases/{case_id}/sar/draft", json={})
    assert response.status_code == 201, response.text
    assert response.json()["narrative"]["status"] == "verified"
    return case_id


def _approve(client: TestClient, case_id: str, **overrides):
    payload = {
        "approver_id": APPROVER,
        "approver_role": "senior_analyst",
        "outcome": "approved",
    }
    payload.update(overrides)
    return client.post(f"/cases/{case_id}/sar/approve", json=payload)


def test_approve_seal_export_verify_over_http(client):
    case_id = _drafted_case(client)

    response = _approve(client, case_id)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["case_status"] == "filed_sar"
    assert body["approval"]["outcome"] == "approved"
    assert body["approval"]["approver_id"] == APPROVER

    response = client.get(f"/cases/{case_id}/sar/approval")
    assert response.status_code == 200
    assert response.json()["current"]["outcome"] == "approved"
    assert len(response.json()["history"]) == 1

    response = client.post(f"/cases/{case_id}/seal", json=OFFICER)
    assert response.status_code == 201, response.text
    seal = response.json()["seal"]
    assert seal["version"] == 1
    assert seal["operative"] is True
    assert seal["manifest"]["items"], "the manifest certifies items"

    response = client.get(f"/cases/{case_id}/seal")
    assert response.status_code == 200
    assert response.json()["sealed"] is True

    response = client.get(f"/cases/{case_id}/export")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    package = response.json()
    assert package["format"] == "harborline-case-file-export/1"

    response = client.post(
        "/cases/export/verify", json={"package": package}
    )
    assert response.status_code == 200
    assert response.json()["verification"]["ok"] is True

    forged = dict(package)
    items = [dict(i) for i in package["items"]]
    items[0] = dict(
        items[0],
        content_b64=base64.b64encode(b"forged").decode("ascii"),
    )
    forged["items"] = items
    response = client.post(
        "/cases/export/verify", json={"package": forged}
    )
    assert response.status_code == 200
    verification = response.json()["verification"]
    assert verification["ok"] is False
    assert any("seq 1" in p for p in verification["problems"])


def test_dual_control_refusals_over_http(client):
    case_id = _drafted_case(client)
    response = _approve(client, case_id, approver_id=ANALYST)
    assert response.status_code == 422
    assert "approver_is_dispositioner" in response.json()["detail"]

    response = _approve(
        client, case_id, outcome="rejected", reason_codes=[]
    )
    assert response.status_code == 422
    assert "rejection_codes_required" in response.json()["detail"]

    response = _approve(
        client,
        case_id,
        outcome="rejected",
        reason_codes=["CHRONOLOGY_WRONG"],
    )
    assert response.status_code == 201, response.text
    assert response.json()["case_status"] == "sar_pending"
    response = client.get(f"/cases/{case_id}/sar")
    assert response.json()["current"]["status"] == "rejected"


def test_sealed_case_mutation_is_a_409(client):
    case_id = _drafted_case(client)
    assert _approve(client, case_id).status_code == 201
    assert client.post(f"/cases/{case_id}/seal", json=OFFICER).status_code == 201
    response = client.post(
        f"/cases/{case_id}/evidence",
        json={
            "kind": "analyst_note",
            "content_base64": base64.b64encode(b"late").decode("ascii"),
            "source_ref": "test",
            "captured_by": "analyst:a.okafor",
        },
    )
    assert response.status_code == 409, response.text
    assert "case_sealed" in response.json()["detail"]


def test_hold_and_unseal_over_http(client):
    case_id = _drafted_case(client)
    assert _approve(client, case_id).status_code == 201

    response = client.post(
        f"/cases/{case_id}/legal-hold",
        json={**OFFICER, "reason_code": "REGULATORY_EXAMINATION"},
    )
    assert response.status_code == 201, response.text
    response = client.get(f"/cases/{case_id}/legal-hold")
    assert response.json()["on_hold"] is True

    response = client.post(
        f"/cases/{case_id}/seal", json={**OFFICER, "purpose": "archive"}
    )
    assert response.status_code == 422
    assert "legal_hold_blocks_archive" in response.json()["detail"]

    assert client.post(f"/cases/{case_id}/seal", json=OFFICER).status_code == 201
    response = client.post(
        f"/cases/{case_id}/legal-hold/release",
        json={**OFFICER, "reason_code": "EXAMINATION_CLOSED"},
    )
    assert response.status_code == 201, response.text
    response = client.get(f"/cases/{case_id}/legal-hold")
    assert response.json()["on_hold"] is False

    response = client.post(
        f"/cases/{case_id}/unseal",
        json={**OFFICER, "reason_code": "REGULATORY_REQUEST"},
    )
    assert response.status_code == 201, response.text
    response = client.get(f"/cases/{case_id}/seal")
    assert response.json()["sealed"] is False
    assert [h["record"] for h in response.json()["seal_history"]] == [
        "seal",
        "unseal",
    ]


def test_seal_of_an_open_case_and_missing_case(client):
    response = client.post("/alerts/intake", json={"alert_id": "ALRT-A-1"})
    case_id = response.json()["case_id"]
    response = client.post(f"/cases/{case_id}/seal", json=OFFICER)
    assert response.status_code == 422
    assert "case_not_terminal" in response.json()["detail"]
    response = client.post("/cases/nope/seal", json=OFFICER)
    assert response.status_code == 404
    response = client.get("/cases/nope/export")
    assert response.status_code == 404
