"""Alert intake: case opening, detection-date stamping, idempotency."""

from __future__ import annotations

from datetime import date

import pytest

from aml_investigations.errors import AlertNotFoundError
from aml_investigations.models import CaseStatus


def test_intake_opens_case_in_opened_state(services):
    case = services.intake.open_case("ALRT-T-001")
    assert case.status is CaseStatus.OPENED
    assert case.alert_id == "ALRT-T-001"
    assert case.customer_id == "CUST-1001"
    assert case.account_id == "ACCT-5001"
    assert case.rule_id == "TM-STRUCTURING-01"


def test_detection_date_is_stamped_from_the_alert(services):
    case = services.intake.open_case("ALRT-T-001")
    assert case.detected_on == date(2026, 10, 20)


def test_retention_floor_is_five_years(services):
    case = services.intake.open_case("ALRT-T-001")
    assert case.retention_until == date(2031, 10, 20)


def test_intake_is_idempotent_per_alert(services):
    first = services.intake.open_case("ALRT-T-001")
    second = services.intake.open_case("ALRT-T-001")
    assert first.case_id == second.case_id
    assert len(services.store.list_cases()) == 1


def test_alert_payload_is_first_evidence_item(services):
    case = services.intake.open_case("ALRT-T-001")
    items = services.evidence.list_items(case.case_id)
    assert len(items) == 1
    assert items[0].kind == "alert_payload"
    assert items[0].seq == 1
    content = services.evidence.read_item_content(case.case_id, 1)
    assert b"ALRT-T-001" in content


def test_unknown_alert_is_refused(services):
    with pytest.raises(AlertNotFoundError):
        services.intake.open_case("ALRT-MISSING")


def test_case_opened_is_audited(services):
    case = services.intake.open_case("ALRT-T-002")
    events = services.store.list_audit(case.case_id)
    assert events[0].event == "case_opened"
    assert events[0].detail["detected_on"] == "2026-10-21"
