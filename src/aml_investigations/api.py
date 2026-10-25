"""FastAPI surface for the AML investigations blueprint.

Endpoints cover the intake -> case -> evidence spine (R1) and the
screening surface (R2): snapshot ingest, pinned screening runs, hit
disposition. Investigation work (typologies, findings, SAR drafting)
arrives in later rounds behind the same case/evidence model.
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
    HitNotFoundError,
    IllegalTransitionError,
    ScreeningError,
    ScreeningPinRequiredError,
    SnapshotImmutableError,
    SnapshotNotFoundError,
)
from .logging_config import (
    case_id_var,
    configure_logging,
    get_logger,
    request_id_var,
)
from .models import (
    CaseStatus,
    Disposition,
    HitStatus,
    ListKind,
    ListSnapshot,
    ScreeningSubject,
)
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


class ScreenRequest(BaseModel):
    pins: dict[str, str] = Field(
        description="Pinned snapshot set: list kind -> snapshot version. "
        "Required — screening without a pin is refused (Law 3)."
    )
    actor: str = Field(min_length=1)
    subjects: list[ScreeningSubject] | None = Field(
        default=None,
        description="Explicit subjects; default derives them from the "
        "case's alert payload evidence.",
    )


class HitStatusRequest(BaseModel):
    status: HitStatus
    actor: str = Field(min_length=1)
    reason: str = Field(min_length=1)


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

    @app.exception_handler(SnapshotImmutableError)
    async def _snapshot_immutable(_request: Request, exc: SnapshotImmutableError):
        return _error(409, str(exc))

    @app.exception_handler(SnapshotNotFoundError)
    async def _snapshot_not_found(_request: Request, exc: SnapshotNotFoundError):
        return _error(404, str(exc))

    @app.exception_handler(HitNotFoundError)
    async def _hit_not_found(_request: Request, exc: HitNotFoundError):
        return _error(404, f"screening hit not found: {exc}")

    @app.exception_handler(ScreeningPinRequiredError)
    async def _pin_required(_request: Request, exc: ScreeningPinRequiredError):
        return _error(422, str(exc))

    @app.exception_handler(ScreeningError)
    async def _screening_error(_request: Request, exc: ScreeningError):
        return _error(422, str(exc))

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

    # --- screening (R2, Law 3) --------------------------------------
    @app.post("/screening/snapshots", status_code=201)
    async def ingest_snapshot(payload: ListSnapshot):
        snapshot = services.screening.ingest_snapshot(payload)
        return snapshot.model_dump(mode="json")

    @app.post("/screening/snapshots/ingest-feed", status_code=201)
    async def ingest_feed():
        snapshots = services.screening.ingest_from_source(services.screening_feed)
        return [s.model_dump(mode="json") for s in snapshots]

    @app.get("/screening/snapshots")
    async def list_snapshots(kind: ListKind | None = None):
        return [
            s.model_dump(mode="json")
            for s in services.store.list_snapshots(kind)
        ]

    @app.post("/cases/{case_id}/screening", status_code=201)
    async def screen_case(case_id: str, payload: ScreenRequest):
        case_id_var.set(case_id)
        run = services.screening.screen_case(
            case_id,
            payload.pins,
            actor=payload.actor,
            subjects=payload.subjects,
        )
        hits = [
            h
            for h in services.store.list_hits(case_id)
            if h.run_id == run.run_id
        ]
        return {
            "run": run.model_dump(mode="json"),
            "hits": [h.model_dump(mode="json") for h in hits],
        }

    @app.get("/cases/{case_id}/screening")
    async def get_screening(case_id: str):
        case = services.store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        return {
            "case_id": case_id,
            "screened_against": [
                s.model_dump(mode="json") for s in case.screened_against
            ],
            "screening_stale": case.screening_stale,
            "flags": case.flags,
            "runs": [
                r.model_dump(mode="json")
                for r in services.store.list_screening_runs(case_id)
            ],
            "hits": [
                h.model_dump(mode="json") for h in services.store.list_hits(case_id)
            ],
        }

    @app.post("/screening/hits/{hit_id}/status")
    async def set_hit_status(hit_id: str, payload: HitStatusRequest):
        hit = services.screening.set_hit_status(
            hit_id,
            payload.status,
            actor=payload.actor,
            reason=payload.reason,
        )
        return hit.model_dump(mode="json")

    return app


app = create_app()
