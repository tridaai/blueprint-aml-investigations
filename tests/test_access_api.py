"""Access control over HTTP (R18): identity headers scope every
read and write; the 404 shape hides existence byte-for-byte;
the auditor reads and cannot write; exports and reports hold
their doors; denials are listed for the officer and auditor."""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from aml_investigations.api import create_app

OFFICER = {"x-caller-id": "o.reyes", "x-caller-role": "bsa_officer"}
REVIEWER = {"x-caller-id": "r.okafor", "x-caller-role": "l2_reviewer"}
AUDITOR = {"x-caller-id": "a.auditor", "x-caller-role": "auditor_readonly"}
RIVERA = {"x-caller-id": "a.rivera", "x-caller-role": "l1_analyst"}
CHEN = {"x-caller-id": "b.chen", "x-caller-role": "l1_analyst"}


@pytest.fixture()
def client(services) -> TestClient:
    # No default identity: every call names its caller, exactly
    # as the deployment's gateway would assert it.
    return TestClient(create_app(services))


def _intake(client: TestClient, alert_id: str = "ALRT-T-001") -> str:
    response = client.post(
        "/alerts/intake", json={"alert_id": alert_id}, headers=OFFICER
    )
    assert response.status_code == 201
    return response.json()["case_id"]


def _assign(client: TestClient, case_id: str, assignee: str) -> None:
    response = client.post(
        f"/cases/{case_id}/assignment",
        json={
            "assignee_id": assignee,
            "actor_id": "o.reyes",
            "actor_role": "bsa_officer",
        },
        headers=OFFICER,
    )
    assert response.status_code == 201, response.text
    assert response.json()["case"]["assigned_analyst"] == assignee
    assert response.json()["evidence_seq"] is not None


def test_cross_assignee_read_is_indistinguishable_from_missing(client):
    case_id = _intake(client)
    _assign(client, case_id, "a.rivera")
    hidden = client.get(f"/cases/{case_id}", headers=CHEN)
    missing = client.get("/cases/case-does-not-exist", headers=CHEN)
    assert hidden.status_code == 404
    assert hidden.content == missing.content
    # The assignee reads it fine.
    assert client.get(f"/cases/{case_id}", headers=RIVERA).status_code == 200


def test_anonymous_read_is_the_not_found_shape(client):
    case_id = _intake(client)
    anon = client.get(f"/cases/{case_id}")
    missing = client.get("/cases/case-does-not-exist")
    assert anon.status_code == 404
    assert anon.content == missing.content


def test_queue_shows_only_the_callers_book(client):
    mine = _intake(client, "ALRT-T-001")
    _assign(client, mine, "a.rivera")
    open_case = _intake(client, "ALRT-T-002")
    chen_ids = {
        c["case_id"] for c in client.get("/cases", headers=CHEN).json()
    }
    assert chen_ids == {open_case}
    rivera_ids = {
        c["case_id"] for c in client.get("/cases", headers=RIVERA).json()
    }
    assert rivera_ids == {mine, open_case}
    officer_ids = {
        c["case_id"] for c in client.get("/cases", headers=OFFICER).json()
    }
    assert officer_ids == {mine, open_case}


def test_auditor_reads_everything_and_writes_nothing(client):
    case_id = _intake(client)
    assert client.get(f"/cases/{case_id}", headers=AUDITOR).status_code == 200
    assert (
        client.get(f"/cases/{case_id}/evidence", headers=AUDITOR).status_code
        == 200
    )
    transition = client.post(
        f"/cases/{case_id}/transitions",
        json={"target": "assembling", "actor": "investigation-service"},
        headers=AUDITOR,
    )
    assert transition.status_code == 403
    assert transition.json()["code"] == "readonly_role"
    evidence = client.post(
        f"/cases/{case_id}/evidence",
        json={
            "kind": "transaction_window",
            "content_base64": base64.b64encode(b"{}").decode(),
            "source_ref": "core-banking:test",
            "captured_by": "evidence-service",
        },
        headers=AUDITOR,
    )
    assert evidence.status_code == 403
    assert evidence.json()["code"] == "readonly_role"
    disposition = client.post(
        f"/cases/{case_id}/disposition",
        json={
            "analyst_id": "a.auditor",
            "analyst_role": "auditor_readonly",
            "outcome": "close_no_action",
            "rationale_codes": ["no_suspicious_activity_identified"],
            "record_id": "rec-x",
            "record_version": 1,
        },
        headers=AUDITOR,
    )
    assert disposition.status_code == 403
    assert disposition.json()["code"] == "readonly_role"


def test_export_and_reports_hold_their_doors(client):
    case_id = _intake(client)
    _assign(client, case_id, "a.rivera")
    export = client.get(f"/cases/{case_id}/export", headers=REVIEWER)
    assert export.status_code == 403
    assert export.json()["code"] == "role_not_permitted"
    assert export.json()["family"] == "export"
    # The officer passes the access door (the sealing layer then
    # answers for itself: an unsealed case exports nothing).
    officer_export = client.get(f"/cases/{case_id}/export", headers=OFFICER)
    assert officer_export.status_code != 403
    report = client.get("/reports/pack", headers=RIVERA)
    assert report.status_code == 403
    assert report.json()["family"] == "reports"
    assert client.get("/reports/pack", headers=AUDITOR).status_code == 200
    assert client.get("/reports/pack").status_code == 403


def test_denials_are_recorded_and_listable(client):
    case_id = _intake(client)
    _assign(client, case_id, "a.rivera")
    client.get(f"/cases/{case_id}", headers=CHEN)
    client.get(f"/cases/{case_id}/export", headers=REVIEWER)
    denials = client.get("/access/denials", headers=OFFICER)
    assert denials.status_code == 200
    events = denials.json()
    codes = {e["detail"]["code"] for e in events}
    assert "not_assignee" in codes
    assert "role_not_permitted" in codes
    assert all(e["event"] == "access_denied" for e in events)
    # An analyst may not read the denial record.
    assert client.get("/access/denials", headers=RIVERA).status_code == 403
    assert client.get("/access/denials", headers=AUDITOR).status_code == 200


def test_assignment_over_http_claims_and_reassignment(client):
    case_id = _intake(client)
    # An L1 analyst claims the unassigned case for themselves.
    claim = client.post(
        f"/cases/{case_id}/assignment",
        json={
            "assignee_id": "b.chen",
            "actor_id": "b.chen",
            "actor_role": "l1_analyst",
        },
        headers=CHEN,
    )
    assert claim.status_code == 201
    assert client.get(f"/cases/{case_id}", headers=CHEN).status_code == 200
    # They cannot hand it to someone else.
    hand_off = client.post(
        f"/cases/{case_id}/assignment",
        json={
            "assignee_id": "a.rivera",
            "actor_id": "b.chen",
            "actor_role": "l1_analyst",
        },
        headers=CHEN,
    )
    assert hand_off.status_code == 403
    # The officer reassigns; the effect is immediate.
    _assign(client, case_id, "a.rivera")
    assert client.get(f"/cases/{case_id}", headers=CHEN).status_code == 404
    assert client.get(f"/cases/{case_id}", headers=RIVERA).status_code == 200


def test_work_queues_are_reviewer_doors(client):
    assert (
        client.get("/queues/pending-confirmation", headers=RIVERA).status_code
        == 403
    )
    assert (
        client.get("/queues/pending-confirmation", headers=REVIEWER).status_code
        == 200
    )
    assert (
        client.get("/counterparties/shared", headers=RIVERA).status_code
        == 403
    )


def test_customer_reads_hide_unknown_customers(client):
    case_id = _intake(client)
    _assign(client, case_id, "a.rivera")
    customer = client.get(
        f"/cases/{case_id}", headers=OFFICER
    ).json()["customer_id"]
    hidden = client.get(f"/customers/{customer}/profile", headers=CHEN)
    missing = client.get("/customers/CUST-NOPE/profile", headers=CHEN)
    assert hidden.status_code == 404
    assert hidden.content == missing.content
    assert (
        client.get(f"/customers/{customer}/counterparties", headers=RIVERA)
        .status_code
        == 200
    )


def test_vocabulary_carries_the_access_policy(client):
    body = client.get("/vocabulary").json()
    assert body["access"]["version"] == "2026.10.1"
    assert "auditor_readonly" in body["access"]["roles"]
    assert body["access"]["identity_headers"] == [
        "x-caller-id",
        "x-caller-role",
    ]


def test_console_sends_identity_on_reads(client):
    page = client.get("/console")
    assert page.status_code == 200
    assert 'opts.headers["x-caller-id"]' in page.text
    assert 'opts.headers["x-caller-role"]' in page.text
