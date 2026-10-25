"""R5 disposition API: record a disposition at the gate, answer it
with a confirmation, read the history and the work queues — and the
refusal mapping (every gate refusal is a 422 with its reason named).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aml_investigations.api import create_app

ANALYST = "a.okafor"
L2 = "m.osei"


@pytest.fixture()
def client(services) -> TestClient:
    return TestClient(create_app(services))


def _transition(client: TestClient, case_id: str, target: str) -> None:
    response = client.post(
        f"/cases/{case_id}/transitions", json={"target": target, "actor": "test"}
    )
    assert response.status_code == 200, response.text


def _investigated_case(client: TestClient, alert_id: str = "ALRT-T-001") -> tuple[str, dict]:
    """A case with an investigation record, standing at the gate."""
    response = client.post("/alerts/intake", json={"alert_id": alert_id})
    assert response.status_code == 201
    case_id = response.json()["case_id"]
    _transition(client, case_id, "assembling")
    _transition(client, case_id, "investigating")
    response = client.post(
        f"/cases/{case_id}/investigation/run", json={"actor": "analyst"}
    )
    assert response.status_code == 201, response.text
    record = response.json()
    _transition(client, case_id, "awaiting_analyst")
    return case_id, record


def _disposition_body(record: dict, **overrides) -> dict:
    body = {
        "analyst_id": ANALYST,
        "analyst_role": "analyst",
        "outcome": "close_no_action",
        "rationale_codes": ["NO_SUSPICIOUS_ACTIVITY_IDENTIFIED"],
        "record_id": record["record_id"],
        "record_version": record["version"],
    }
    body.update(overrides)
    return body


def test_benign_disposition_closes_the_case(client):
    case_id, record = _investigated_case(client)
    assert record["hypothesis"]["label"] == "no_adverse_pattern"
    response = client.post(
        f"/cases/{case_id}/disposition", json=_disposition_body(record)
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["case_status"] == "closed"
    assert body["disposition"]["status"] == "effective"
    assert body["disposition"]["evidence_seq"] is not None

    response = client.get(f"/cases/{case_id}/dispositions")
    assert response.status_code == 200
    history = response.json()
    assert len(history["dispositions"]) == 1
    assert history["confirmations"] == []


def test_gate_refusals_are_422_with_named_reasons(client):
    case_id, record = _investigated_case(client)
    probes = [
        ({"analyst_id": "investigation-service"}, "anonymous_or_system_actor"),
        ({"analyst_id": ""}, "anonymous_or_system_actor"),
        ({"analyst_role": "manager"}, "unknown_role"),
        ({"rationale_codes": []}, "rationale_codes_required"),
        ({"rationale_codes": ["LOOKS_FINE"]}, "unknown_rationale_code"),
        ({"record_version": 99}, "record_citation_not_current"),
        ({"record_id": "INV-nope"}, "record_citation_not_current"),
    ]
    for overrides, reason in probes:
        response = client.post(
            f"/cases/{case_id}/disposition",
            json=_disposition_body(record, **overrides),
        )
        assert response.status_code == 422, (overrides, response.text)
        assert reason in response.json()["detail"], (overrides, response.text)
    # Nothing was recorded by any of the refused attempts.
    response = client.get(f"/cases/{case_id}/dispositions")
    assert response.json()["dispositions"] == []


def test_disposition_unknown_case_is_404(client):
    response = client.post(
        "/cases/case-nope/disposition",
        json=_disposition_body({"record_id": "INV-x", "version": 1}),
    )
    assert response.status_code == 404
    response = client.get("/cases/case-nope/dispositions")
    assert response.status_code == 404


def _adverse_case(client: TestClient) -> tuple[str, dict]:
    """A structuring case (adverse hypothesis) at the gate, built
    entirely over the API: pack, transactions, typologies, record."""
    response = client.post("/alerts/intake", json={"alert_id": "ALRT-T-002"})
    case_id = response.json()["case_id"]
    _transition(client, case_id, "assembling")
    response = client.post(
        "/typologies/rule-packs", json={"pack_id": "api-pack", "version": "1.0"}
    )
    assert response.status_code == 201, response.text
    stream = [
        {
            "transaction_id": f"A-{i}",
            "account_id": "ACCT-5002",
            "posted_at": f"2026-03-0{day}T10:00:00Z",
            "direction": "credit",
            "amount": amount,
            "channel": "branch",
            "cash": True,
        }
        for i, (day, amount) in enumerate(
            [(2, "9500"), (4, "9600"), (6, "9700")], start=1
        )
    ]
    response = client.post(
        f"/cases/{case_id}/transactions",
        json={
            "transactions": stream,
            "source_ref": "core-banking:ACCT-5002",
            "actor": "test-feed",
        },
    )
    assert response.status_code == 201, response.text
    response = client.post(
        f"/cases/{case_id}/typologies/run",
        json={"pack_id": "api-pack", "version": "1.0", "actor": "test"},
    )
    assert response.status_code == 201, response.text
    _transition(client, case_id, "investigating")
    response = client.post(
        f"/cases/{case_id}/investigation/run", json={"actor": "analyst"}
    )
    assert response.status_code == 201, response.text
    record = response.json()
    assert record["hypothesis"]["label"] == "structuring"
    _transition(client, case_id, "awaiting_analyst")
    return case_id, record


def test_adverse_close_waits_for_confirmation(client):
    case_id, record = _adverse_case(client)
    response = client.post(
        f"/cases/{case_id}/disposition",
        json=_disposition_body(
            record, rationale_codes=["BENIGN_EXPLANATION_DOCUMENTED"]
        ),
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["case_status"] == "pending_confirmation"
    assert body["disposition"]["status"] == "pending_confirmation"

    # The case is on the L2 worklist.
    response = client.get("/queues/pending-confirmation")
    assert response.status_code == 200
    queue = response.json()
    assert [entry["case"]["case_id"] for entry in queue] == [case_id]

    # The dispositioning analyst cannot confirm their own closure.
    response = client.post(
        f"/cases/{case_id}/disposition/confirmation",
        json={
            "confirmer_id": ANALYST,
            "confirmer_role": "l2_reviewer",
            "outcome": "confirmed",
        },
    )
    assert response.status_code == 422
    assert "self_confirmation" in response.json()["detail"]

    # A second person confirms; the closure lands.
    response = client.post(
        f"/cases/{case_id}/disposition/confirmation",
        json={
            "confirmer_id": L2,
            "confirmer_role": "l2_reviewer",
            "outcome": "confirmed",
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["case_status"] == "closed"
    assert client.get("/queues/pending-confirmation").json() == []

    response = client.get(f"/cases/{case_id}/dispositions")
    history = response.json()
    assert history["dispositions"][0]["status"] == "confirmed"
    assert len(history["confirmations"]) == 1
    assert history["confirmations"][0]["confirmer_id"] == L2


def test_escalation_queue_lists_sar_pending_cases(client):
    case_id, record = _adverse_case(client)
    response = client.post(
        f"/cases/{case_id}/disposition",
        json=_disposition_body(
            record,
            outcome="escalate_sar",
            rationale_codes=["STRUCTURING_SUSPECTED"],
        ),
    )
    assert response.status_code == 201, response.text
    assert response.json()["case_status"] == "sar_pending"
    response = client.get("/queues/escalations")
    assert response.status_code == 200
    queue = response.json()
    assert [entry["case"]["case_id"] for entry in queue] == [case_id]
    assert queue[0]["disposition"]["outcome"] == "escalate_sar"
