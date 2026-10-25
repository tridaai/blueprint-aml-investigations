"""FastAPI surface for the AML investigations blueprint.

Endpoints cover the intake -> case -> evidence spine (R1), the
screening surface (R2): snapshot ingest, pinned screening runs, hit
disposition, the typology surface (R3): rule-pack registration,
evidence-backed transaction ingestion, engine runs, findings, and
the investigation surface (R4): run the investigation graph for a
case, fetch the current investigation record and its version
history, and the disposition surface (R5): record a disposition at
the analyst gate, confirm a pending one, read a case's disposition
history, and read the confirmation / escalation work queues. SAR
drafting arrives in later rounds behind the same case/evidence
model.
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
    DispositionRefusedError,
    DispositionRequiredError,
    EvidenceChainError,
    EvidenceNotFoundError,
    HitNotFoundError,
    IllegalTransitionError,
    InvestigationError,
    InvestigationStateError,
    NoTransactionsError,
    RulePackImmutableError,
    RulePackNotFoundError,
    ScreeningError,
    ScreeningPinRequiredError,
    SnapshotImmutableError,
    SnapshotNotFoundError,
    TransactionMismatchError,
    TypologyError,
)
from .logging_config import (
    case_id_var,
    configure_logging,
    get_logger,
    request_id_var,
)
from .models import (
    CaseStatus,
    ConfirmationOutcome,
    Disposition,
    DispositionOutcome,
    HitStatus,
    ListKind,
    ListSnapshot,
    RulePack,
    ScreeningSubject,
    Transaction,
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


class TransactionBatchRequest(BaseModel):
    transactions: list[Transaction]
    source_ref: str = Field(min_length=1)
    actor: str = Field(min_length=1)


class TypologyRunRequest(BaseModel):
    pack_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    actor: str = Field(min_length=1)


class InvestigationRunRequest(BaseModel):
    actor: str = Field(min_length=1)
    profile: str = Field(
        default="offline",
        description="Model profile for narrative composition. "
        "'offline' is the deterministic default; a live profile "
        "must be configured in the deployment.",
    )


class DispositionRequest(BaseModel):
    """One analyst disposition at the gate (R5). Field validation is
    deliberately permissive here: the disposition service owns every
    refusal and names its reason (anonymous actor, uncoded rationale,
    stale record citation, sanctions block)."""

    analyst_id: str
    analyst_role: str
    outcome: DispositionOutcome
    rationale_codes: list[str] = Field(default_factory=list)
    record_id: str
    record_version: int
    note: str = ""
    review_period_days: int | None = None
    missing_evidence: list[str] = Field(default_factory=list)


class ConfirmationRequest(BaseModel):
    """A second person's answer to a pending-confirmation disposition."""

    confirmer_id: str
    confirmer_role: str
    outcome: ConfirmationOutcome
    note: str = ""


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

    @app.exception_handler(RulePackImmutableError)
    async def _pack_immutable(_request: Request, exc: RulePackImmutableError):
        return _error(409, str(exc))

    @app.exception_handler(RulePackNotFoundError)
    async def _pack_not_found(_request: Request, exc: RulePackNotFoundError):
        return _error(404, str(exc))

    @app.exception_handler(NoTransactionsError)
    async def _no_transactions(_request: Request, exc: NoTransactionsError):
        return _error(422, str(exc))

    @app.exception_handler(TransactionMismatchError)
    async def _txn_mismatch(_request: Request, exc: TransactionMismatchError):
        return _error(422, str(exc))

    @app.exception_handler(TypologyError)
    async def _typology_error(_request: Request, exc: TypologyError):
        return _error(422, str(exc))

    @app.exception_handler(InvestigationStateError)
    async def _investigation_state(_request: Request, exc: InvestigationStateError):
        return _error(409, str(exc))

    @app.exception_handler(InvestigationError)
    async def _investigation_error(_request: Request, exc: InvestigationError):
        return _error(422, str(exc))

    @app.exception_handler(DispositionRefusedError)
    async def _disposition_refused(_request: Request, exc: DispositionRefusedError):
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

    # --- typologies (R3, Law 4) -------------------------------------
    @app.post("/typologies/rule-packs", status_code=201)
    async def register_rule_pack(payload: RulePack):
        pack = services.typologies.register_rule_pack(payload)
        return pack.model_dump(mode="json")

    @app.post("/typologies/rule-packs/register-feed", status_code=201)
    async def register_rule_pack_feed():
        packs = services.typologies.register_from_source(services.rule_pack_feed)
        return [p.model_dump(mode="json") for p in packs]

    @app.get("/typologies/rule-packs")
    async def list_rule_packs():
        return [
            p.model_dump(mode="json") for p in services.store.list_rule_packs()
        ]

    @app.post("/cases/{case_id}/transactions/ingest-feed", status_code=201)
    async def ingest_transactions_feed(case_id: str, actor: str = "core-banking-feed"):
        case_id_var.set(case_id)
        batch = services.typologies.ingest_from_source(
            case_id, services.transactions, actor=actor
        )
        return batch.model_dump(mode="json")

    @app.post("/cases/{case_id}/transactions", status_code=201)
    async def ingest_transactions(case_id: str, payload: TransactionBatchRequest):
        case_id_var.set(case_id)
        batch = services.typologies.ingest_transactions(
            case_id,
            payload.transactions,
            source_ref=payload.source_ref,
            actor=payload.actor,
        )
        return batch.model_dump(mode="json")

    @app.get("/cases/{case_id}/transactions")
    async def list_transactions(case_id: str):
        if services.store.get_case(case_id) is None:
            raise CaseNotFoundError(case_id)
        return {
            "case_id": case_id,
            "batches": [
                b.model_dump(mode="json")
                for b in services.store.list_transaction_batches(case_id)
            ],
            "transactions": [
                t.model_dump(mode="json")
                for t in services.store.list_transactions(case_id)
            ],
        }

    @app.post("/cases/{case_id}/typologies/run", status_code=201)
    async def run_typologies(case_id: str, payload: TypologyRunRequest):
        case_id_var.set(case_id)
        run = services.typologies.run_typologies(
            case_id, payload.pack_id, payload.version, actor=payload.actor
        )
        findings = services.typologies.list_findings(case_id, run_id=run.run_id)
        return {
            "run": run.model_dump(mode="json"),
            "findings": [f.model_dump(mode="json") for f in findings],
        }

    @app.get("/cases/{case_id}/typologies")
    async def get_typologies(case_id: str):
        if services.store.get_case(case_id) is None:
            raise CaseNotFoundError(case_id)
        return {
            "case_id": case_id,
            "runs": [
                r.model_dump(mode="json")
                for r in services.store.list_typology_runs(case_id)
            ],
            "findings": [
                f.model_dump(mode="json")
                for f in services.typologies.list_findings(case_id)
            ],
        }

    # --- investigations (R4) -----------------------------------------
    @app.post("/cases/{case_id}/investigation/run", status_code=201)
    async def run_investigation(case_id: str, payload: InvestigationRunRequest):
        case_id_var.set(case_id)
        record = services.investigations.run_investigation(
            case_id, actor=payload.actor, profile=payload.profile
        )
        return record.model_dump(mode="json")

    @app.get("/cases/{case_id}/investigation")
    async def get_investigation(case_id: str):
        if services.store.get_case(case_id) is None:
            raise CaseNotFoundError(case_id)
        current = services.investigations.current_record(case_id)
        return {
            "case_id": case_id,
            "current": (
                current.model_dump(mode="json") if current is not None else None
            ),
            "history": [
                r.model_dump(mode="json")
                for r in services.investigations.record_history(case_id)
            ],
        }

    # --- dispositions (R5): the analyst gate -------------------------
    @app.post("/cases/{case_id}/disposition", status_code=201)
    async def record_disposition(case_id: str, payload: DispositionRequest):
        case_id_var.set(case_id)
        record = services.dispositions.record_disposition(
            case_id,
            analyst_id=payload.analyst_id,
            analyst_role=payload.analyst_role,
            outcome=payload.outcome,
            rationale_codes=payload.rationale_codes,
            record_id=payload.record_id,
            record_version=payload.record_version,
            note=payload.note,
            review_period_days=payload.review_period_days,
            missing_evidence=payload.missing_evidence,
        )
        return {
            "disposition": services.dispositions.view(record),
            "case_status": services.store.get_case(case_id).status.value,
        }

    @app.post("/cases/{case_id}/disposition/confirmation", status_code=201)
    async def confirm_disposition(case_id: str, payload: ConfirmationRequest):
        case_id_var.set(case_id)
        confirmation = services.dispositions.confirm_disposition(
            case_id,
            confirmer_id=payload.confirmer_id,
            confirmer_role=payload.confirmer_role,
            outcome=payload.outcome,
            note=payload.note,
        )
        return {
            "confirmation": confirmation.model_dump(mode="json"),
            "case_status": services.store.get_case(case_id).status.value,
        }

    @app.get("/cases/{case_id}/dispositions")
    async def get_dispositions(case_id: str):
        if services.store.get_case(case_id) is None:
            raise CaseNotFoundError(case_id)
        return {
            "case_id": case_id,
            "dispositions": [
                services.dispositions.view(r)
                for r in services.dispositions.history(case_id)
            ],
            "confirmations": [
                c.model_dump(mode="json")
                for c in services.dispositions.confirmations(case_id)
            ],
        }

    @app.get("/queues/pending-confirmation")
    async def pending_confirmation_queue():
        return services.dispositions.confirmation_queue()

    @app.get("/queues/escalations")
    async def escalation_queue():
        return services.dispositions.escalation_queue()

    return app


app = create_app()
