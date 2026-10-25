"""Alert intake: the monitoring-system port and the case-opening service.

A real deployment wires this port to the bank's transaction-monitoring
platform. The blueprint ships a reference feed (a JSON file of alerts
in the port's shape) so the whole flow runs offline.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

from .clocks import RegulatoryClockService
from .errors import AlertNotFoundError
from .evidence import EvidenceService
from .logging_config import get_logger
from .models import Alert, AuditEvent, Case
from .ports import AlertSource, CaseStore

logger = get_logger(__name__)

#: BSA retention posture: case material is retained five years past
#: closure/filing (Law 5's retention field, stamped at intake as a
#: floor and recomputed when a case reaches a terminal state).
RETENTION_YEARS = 5


class ReferenceAlertFeed:
    """AlertSource over a JSON file of alert payloads (the reference feed)."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._alerts: dict[str, Alert] = {}
        if self._path.exists():
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            for entry in payload.get("alerts", []):
                alert = Alert.model_validate(entry)
                self._alerts[alert.alert_id] = alert

    def get_alert(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    def list_alerts(self) -> list[Alert]:
        return list(self._alerts.values())


class ListAlertFeed:
    """AlertSource over an in-memory list (tests, embedding)."""

    def __init__(self, alerts: list[Alert]) -> None:
        self._alerts = {a.alert_id: a for a in alerts}

    def get_alert(self, alert_id: str) -> Alert | None:
        return self._alerts.get(alert_id)

    def list_alerts(self) -> list[Alert]:
        return list(self._alerts.values())


def _retention_floor(detected_on: date) -> date:
    try:
        return detected_on.replace(year=detected_on.year + RETENTION_YEARS)
    except ValueError:  # Feb 29 -> Feb 28 five years on
        return detected_on.replace(
            year=detected_on.year + RETENTION_YEARS, day=28
        ) + timedelta(days=0)


class IntakeService:
    """Opens cases from alerts. Intake is idempotent per alert: a
    re-delivered alert returns the existing case instead of opening a
    duplicate (monitoring systems re-send; case files must not fork).

    When a clock service is wired (R8), opening a case also fires
    the continuing-activity trigger: a new case for a customer with
    a prior ``filed_sar`` case gets its continuing-activity clock
    started on its evidence chain (see ``clocks.py``). The hook is
    optional so bare test stacks wire intake exactly as before.
    """

    def __init__(
        self,
        store: CaseStore,
        source: AlertSource,
        evidence: EvidenceService,
        clock_service: RegulatoryClockService | None = None,
    ) -> None:
        self._store = store
        self._source = source
        self._evidence = evidence
        self._clocks = clock_service

    def open_case(self, alert_id: str, *, actor: str = "intake-service") -> Case:
        existing = self._store.get_case_by_alert(alert_id)
        if existing is not None:
            return existing
        alert = self._source.get_alert(alert_id)
        if alert is None:
            raise AlertNotFoundError(alert_id)
        return self.open_case_from_alert(alert, actor=actor)

    def open_case_from_alert(self, alert: Alert, *, actor: str = "intake-service") -> Case:
        existing = self._store.get_case_by_alert(alert.alert_id)
        if existing is not None:
            return existing
        case = Case(
            alert_id=alert.alert_id,
            customer_id=alert.customer_id,
            account_id=alert.account_id,
            rule_id=alert.rule_id,
            severity=alert.severity,
            detected_on=alert.detected_on,
            retention_until=_retention_floor(alert.detected_on),
        )
        self._store.create_case(case)
        self._store.append_audit(
            AuditEvent(
                case_id=case.case_id,
                actor=actor,
                event="case_opened",
                detail={
                    "alert_id": alert.alert_id,
                    "rule_id": alert.rule_id,
                    "detected_on": alert.detected_on.isoformat(),
                },
            )
        )
        # The verbatim alert payload is the case file's first evidence
        # item — everything later cites back to evidence, starting here.
        self._evidence.add_item(
            case.case_id,
            kind="alert_payload",
            content=alert.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"monitoring-feed:{alert.alert_id}",
            captured_by=actor,
        )
        # R8: the continuing-activity trigger. A new case for a
        # customer whose prior case reached filed_sar starts a
        # 90/120-day continuing-activity clock, linked on this
        # case's chain.
        if self._clocks is not None:
            opened = self._store.get_case(case.case_id) or case
            self._clocks.record_continuing_link(opened, actor=actor)
        logger.info(
            "case opened",
            extra={"case_id": case.case_id, "event": "case_opened", "alert_id": alert.alert_id},
        )
        return self._store.get_case(case.case_id) or case
