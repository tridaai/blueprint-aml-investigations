"""R3 typology API: rule packs, transaction ingestion, runs, findings."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aml_investigations.api import create_app
from aml_investigations.models import RulePack


@pytest.fixture()
def client(services) -> TestClient:
    return TestClient(create_app(services))


def _open_case(client: TestClient) -> str:
    response = client.post("/alerts/intake", json={"alert_id": "ALRT-T-001"})
    assert response.status_code == 201, response.text
    return response.json()["case_id"]


def _register_pack(client: TestClient, **overrides) -> dict:
    body = RulePack(pack_id="api-pack", version="1.0", **overrides).model_dump(mode="json")
    response = client.post("/typologies/rule-packs", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def _txn(tid: str, day: str, amount: str, *, cash: bool = True) -> dict:
    return {
        "transaction_id": tid,
        "account_id": "ACCT-5001",
        "posted_at": f"{day}T10:00:00Z",
        "direction": "credit",
        "amount": amount,
        "currency": "USD",
        "channel": "branch" if cash else "wire",
        "cash": cash,
    }


STRUCTURING_BATCH = {
    "transactions": [
        _txn("S1", "2026-03-02", "9500"),
        _txn("S2", "2026-03-04", "9600"),
        _txn("S3", "2026-03-06", "9700"),
    ],
    "source_ref": "core-banking:ACCT-5001",
    "actor": "feed-service",
}


def test_rule_pack_register_and_list(client):
    pack = _register_pack(client)
    assert pack["content_hash"]
    listed = client.get("/typologies/rule-packs")
    assert listed.status_code == 200
    assert [p["pack_id"] for p in listed.json()] == ["api-pack"]
    conflict = client.post(
        "/typologies/rule-packs",
        json=RulePack(
            pack_id="api-pack", version="1.0", structuring_min_count=4
        ).model_dump(mode="json"),
    )
    assert conflict.status_code == 409


def test_ingest_run_and_read_findings(client):
    case_id = _open_case(client)
    _register_pack(client)
    batch = client.post(f"/cases/{case_id}/transactions", json=STRUCTURING_BATCH)
    assert batch.status_code == 201, batch.text
    assert batch.json()["transaction_count"] == 3
    assert batch.json()["evidence_seq"] is not None

    run = client.post(
        f"/cases/{case_id}/typologies/run",
        json={"pack_id": "api-pack", "version": "1.0", "actor": "typology-service"},
    )
    assert run.status_code == 201, run.text
    body = run.json()
    assert body["run"]["finding_count"] == 1
    finding = body["findings"][0]
    assert finding["typology_id"] == "structuring"
    assert finding["figures"]["total_amount"] == "28800"
    assert finding["rule_pack_version"] == "1.0"

    view = client.get(f"/cases/{case_id}/typologies")
    assert view.status_code == 200
    assert len(view.json()["runs"]) == 1
    assert len(view.json()["findings"]) == 1

    txns = client.get(f"/cases/{case_id}/transactions")
    assert txns.status_code == 200
    assert len(txns.json()["transactions"]) == 3
    assert len(txns.json()["batches"]) == 1


def test_run_without_transactions_is_422(client):
    case_id = _open_case(client)
    _register_pack(client)
    run = client.post(
        f"/cases/{case_id}/typologies/run",
        json={"pack_id": "api-pack", "version": "1.0", "actor": "svc"},
    )
    assert run.status_code == 422


def test_run_with_unknown_pack_is_404(client):
    case_id = _open_case(client)
    client.post(f"/cases/{case_id}/transactions", json=STRUCTURING_BATCH)
    run = client.post(
        f"/cases/{case_id}/typologies/run",
        json={"pack_id": "ghost", "version": "0.0", "actor": "svc"},
    )
    assert run.status_code == 404


def test_ingest_wrong_account_is_422(client):
    case_id = _open_case(client)
    bad = {
        "transactions": [_txn("X1", "2026-03-02", "100") | {"account_id": "ACCT-9999"}],
        "source_ref": "core-banking:ACCT-9999",
        "actor": "feed-service",
    }
    response = client.post(f"/cases/{case_id}/transactions", json=bad)
    assert response.status_code == 422
