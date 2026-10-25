"""R8 clock API: a case's clocks, the refresh tick, the clock
board, and the clock escalation queue over HTTP. Clock reads are
pure; the board and queue reads run the tick first, so a crossing
they reveal is on the case's chain before they answer.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aml_investigations.api import create_app


@pytest.fixture()
def client(services) -> TestClient:
    return TestClient(create_app(services))


def _open(client: TestClient, services) -> str:
    # ALRT-T-001: CUST-1001, detected 2026-10-20, no subject facts
    # in the payload — the clock runs on the 60-day outer deadline
    # (2026-12-19).
    return services.intake.open_case("ALRT-T-001").case_id


def test_case_clock_over_http(client, services):
    case_id = _open(client, services)
    response = client.get(f"/cases/{case_id}/clock", params={"as_of": "2026-12-25"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["case_id"] == case_id
    filing = body["filing"]
    assert filing["detected_on"] == "2026-10-20"
    assert filing["initial_deadline"] == "2026-11-19"
    assert filing["outer_deadline"] == "2026-12-19"
    assert filing["operative_deadline"] == "2026-12-19"
    assert filing["operative_deadline_kind"] == "outer"
    assert filing["subject_identified"] is False
    assert filing["state"] == "overdue"
    assert filing["days_remaining"] == -6
    assert body["continuing_activity"] is None
    assert body["violations"] == []
    # A pure read records nothing.
    assert body["escalations"] == []
    assert [
        i.kind for i in services.store.list_evidence(case_id)
    ] == ["alert_payload"]


def test_case_clock_unknown_case_is_404(client):
    response = client.get("/cases/case-nope/clock")
    assert response.status_code == 404


def test_refresh_records_crossing_once_over_http(client, services):
    case_id = _open(client, services)
    response = client.post(
        f"/cases/{case_id}/clock/refresh", json={"as_of": "2026-12-25"}
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert len(body["recorded"]) == 1
    event = body["recorded"][0]
    assert event["clock_kind"] == "filing"
    assert event["deadline_kind"] == "outer"
    assert event["state"] == "overdue"
    assert event["days_overdue"] == 6
    assert body["clocks"]["filing"]["state"] == "overdue"
    assert len(body["clocks"]["escalations"]) == 1

    response = client.post(
        f"/cases/{case_id}/clock/refresh", json={"as_of": "2026-12-25"}
    )
    assert response.status_code == 201
    assert response.json()["recorded"] == []
    kinds = [i.kind for i in services.store.list_evidence(case_id)]
    assert kinds.count("clock_escalation") == 1


def test_board_and_queue_over_http(client, services):
    case_id = _open(client, services)
    response = client.get(
        "/queues/clock-escalations", params={"as_of": "2026-12-25"}
    )
    assert response.status_code == 200, response.text
    queue = response.json()
    assert len(queue) == 1
    entry = queue[0]
    assert entry["case_id"] == case_id
    assert entry["state"] == "overdue"
    assert entry["deadline"] == "2026-12-19"
    assert "60-day outer deadline" in entry["reason"]
    # Reading the queue ran the tick: the crossing is on the chain.
    kinds = [i.kind for i in services.store.list_evidence(case_id)]
    assert kinds.count("clock_escalation") == 1

    response = client.get("/clocks/board", params={"as_of": "2026-12-25"})
    assert response.status_code == 200
    board = response.json()
    assert [v["case_id"] for v in board] == [case_id]
    assert board[0]["filing"]["state"] == "overdue"
    assert len(board[0]["escalations"]) == 1

    # Before any deadline pressure, the queue is empty.
    response = client.get(
        "/queues/clock-escalations", params={"as_of": "2026-10-25"}
    )
    assert response.json() == []
