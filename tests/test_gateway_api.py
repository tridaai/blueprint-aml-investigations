"""R13 model-gateway API surface: profiles with prices and
configured state, a case's priced call ledger and cost rollup,
and the portfolio's per-day spend.

Uses the shared ``services`` fixture (tests/conftest.py), whose
stack wires the gateway into the investigation and SAR drafting
services — so an investigation run over HTTP leaves priced
ledger entries the cost endpoints then read back.
"""

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


def test_model_profiles_surface(client):
    response = client.get("/model/profiles")
    assert response.status_code == 200
    body = response.json()
    assert body["price_table"]["version"] == "2026.10.1"
    assert body["case_budget_usd"] == "2.50"
    profiles = {p["profile_id"]: p for p in body["profiles"]}
    assert profiles["offline"]["configured"] is True
    assert profiles["offline"]["model"] == "offline-template-composer-v1"
    # No key is set in the test deployment: the hosted profile
    # reports itself unconfigured, and no key value appears
    # anywhere in the payload.
    assert profiles["hosted-frontier"]["configured"] is False
    assert profiles["hosted-frontier"]["input_per_mtok_usd"] == "3.00"
    assert profiles["hosted-frontier"]["output_per_mtok_usd"] == "15.00"
    assert profiles["in-boundary"]["configured"] is False


def test_case_ledger_and_rollup_after_investigation(client):
    case_id = _to_investigating(client)
    response = client.post(
        f"/cases/{case_id}/investigation/run", json={"actor": "analyst"}
    )
    assert response.status_code == 201
    findings = response.json()["findings"]

    response = client.get(f"/cases/{case_id}/model-ledger")
    assert response.status_code == 200
    entries = response.json()["entries"]
    assert len(entries) == len(findings)
    assert all(e["purpose"] == "record_draft" for e in entries)
    assert all(e["cost_usd"] == "0" for e in entries)
    assert all(e["price_table_version"] == "2026.10.1" for e in entries)

    response = client.get(f"/cases/{case_id}/model-costs")
    assert response.status_code == 200
    rollup = response.json()
    assert rollup["calls"] == len(findings)
    assert rollup["cost_usd"] == "0"
    assert rollup["by_purpose"]["record_draft"]["calls"] == len(findings)
    assert rollup["by_profile"]["offline"]["calls"] == len(findings)
    assert rollup["budget_cap_usd"] == "2.50"
    assert rollup["budget_refusals"] == 0


def test_cost_endpoints_unknown_case_404(client):
    assert client.get("/cases/case-nope/model-ledger").status_code == 404
    assert client.get("/cases/case-nope/model-costs").status_code == 404


def test_portfolio_daily_rollup(client):
    case_id = _to_investigating(client)
    response = client.post(
        f"/cases/{case_id}/investigation/run", json={"actor": "analyst"}
    )
    assert response.status_code == 201
    findings = response.json()["findings"]

    response = client.get("/model-costs/daily")
    assert response.status_code == 200
    rows = response.json()["rows"]
    assert len(rows) == 1
    row = rows[0]
    assert row["profile_id"] == "offline"
    assert row["calls"] == len(findings)
    assert row["cost_usd"] == "0"
    assert row["tokens_in"] == 0 and row["tokens_out"] == 0
