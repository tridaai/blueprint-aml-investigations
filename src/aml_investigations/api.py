"""FastAPI surface for the AML investigations blueprint (R1).

Endpoints cover the intake -> case -> evidence spine. Investigation
work (screening, typologies, findings, SAR drafting) arrives in later
rounds behind the same case/evidence model.
"""

from __future__ import annotations

import base64
import binascii
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .errors import (
    AlertNotFoundError,
    AmlError,
    CaseNotFoundError,
    DispositionRequiredError,
    EvidenceChainError,
    EvidenceNotFoundError,
    IllegalTransitionError,
)
from .logging_config import (
    case_id_var,
    configure_logging,
    get_logger,
    request_id_var,
)
from .models import CaseStatus, Disposition
from .wiring import Services, build_services

logger = get_logger(__name__)


class IntakeRequest(BaseModel):
    alert_id: str
    actor: str = "intake-service"


class TransitionRequest(BaseModel):
    target: CaseStatus
    actor: str = Field(min_length=1)
    disposition: Disposition | None = None


class EvidenceRequest(BaseModel):
    kind: str = Field(min_length=1)
    content_base64: str
    source_ref: str = Field(min_length=1)
    captured_by: str = Field(min_length=1)
    media_type: str = "application/octet-stream"
    legal_hold: bool = False


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": message})


def create_app(services: Services | None = None) -> FastAPI:
    services = services or build_services()
    configure_logging(services.settings.log_level)
    app = FastAPI(
        title="AML Alert Investigation & Case File Agent",
        version="0.1.0",
    )
    app.state.services = services

    @app.middleware("http")
    async def correlation(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        token = request_id_var.set(request_id)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["x-request-id"] = request_id
        return response

    @app.exception_handler(CaseNotFoundError)
    async def _case_not_found(_request: Request, exc: CaseNotFoundError):
        return _error(404, f"case not found: {exc}")

    @app.exception_handler(AlertNotFoundError)
    async def _alert_not_found(_request: Request, exc: AlertNotFoundError):
        return _error(404, f"alert not found: {exc}")

    @app.exception_handler(EvidenceNotFoundError)
    async def _evidence_not_found(_request: Request, exc: EvidenceNotFoundError):
        return _error(404, f"evidence item not found: {exc}")

    @app.exception_handler(DispositionRequiredError)
    async def _disposition_required(_request: Request, exc: DispositionRequiredError):
        return _error(422, str(exc))

    @app.exception_handler(IllegalTransitionError)
    async def _illegal_transition(_request: Request, exc: IllegalTransitionError):
        return _error(409, str(exc))

    @app.exception_handler(EvidenceChainError)
    async def _chain_error(_request: Request, exc: EvidenceChainError):
        return _error(500, f"evidence chain verification failed: {exc}")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/readiness")
    async def readiness():
        store_ok = services.store.ping()
        objects_ok = services.objects.ping()
        ready = store_ok and objects_ok
        return JSONResponse(
            status_code=200 if ready else 503,
            content={
                "ready": ready,
                "case_store": store_ok,
                "object_store": objects_ok,
            },
        )

    @app.get("/alerts")
    async def list_alerts():
        return [a.model_dump(mode="json") for a in services.alerts.list_alerts()]

    @app.post("/alerts/intake", status_code=201)
    async def intake(payload: IntakeRequest):
        case = services.intake.open_case(payload.alert_id, actor=payload.actor)
        return case.model_dump(mode="json")

    @app.get("/cases")
    async def list_cases(status: str | None = None):
        return [
            c.model_dump(mode="json") for c in services.store.list_cases(status)
        ]

    @app.get("/cases/{case_id}")
    async def get_case(case_id: str):
        case_id_var.set(case_id)
        case = services.store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        return case.model_dump(mode="json")

    @app.post("/cases/{case_id}/transitions")
    async def transition(case_id: str, payload: TransitionRequest):
        case_id_var.set(case_id)
        case = services.workflow.transition(
            case_id,
            payload.target,
            actor=payload.actor,
            disposition=payload.disposition,
        )
        return case.model_dump(mode="json")

    @app.post("/cases/{case_id}/evidence", status_code=201)
    async def add_evidence(case_id: str, payload: EvidenceRequest):
        case_id_var.set(case_id)
        try:
            content = base64.b64decode(payload.content_base64, validate=True)
        except binascii.Error:
            return _error(422, "content_base64 is not valid base64")
        item = services.evidence.add_item(
            case_id,
            kind=payload.kind,
            content=content,
            source_ref=payload.source_ref,
            captured_by=payload.captured_by,
            media_type=payload.media_type,
            legal_hold=payload.legal_hold,
        )
        return item.model_dump(mode="json")

    @app.get("/cases/{case_id}/evidence")
    async def list_evidence(case_id: str):
        items = services.evidence.list_items(case_id)
        return [i.model_dump(mode="json") for i in items]

    @app.get("/cases/{case_id}/evidence/verify")
    async def verify_evidence(case_id: str):
        intact = services.evidence.verify_chain(case_id)
        return {"case_id": case_id, "chain_intact": intact}

    @app.get("/cases/{case_id}/audit")
    async def list_audit(case_id: str):
        if services.store.get_case(case_id) is None:
            raise CaseNotFoundError(case_id)
        return [
            e.model_dump(mode="json") for e in services.store.list_audit(case_id)
        ]

    return app


app = create_app()
