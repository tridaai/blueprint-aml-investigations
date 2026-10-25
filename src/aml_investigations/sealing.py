"""Case sealing, legal hold, and export (R7): Law 5, completed.

Everything before this round *wrote* the case file: evidence on a
hash chain, findings cited to it, decisions recorded on it. This
round is where the file becomes a custody object:

- **Sealing.** A named officer seals a case that has reached a
  terminal state — ``closed`` (a confirmed or effective closure),
  or ``filed_sar`` (its narrative approved under dual control).
  The seal computes a manifest over *every* evidence item on the
  case (seq, kind, content hash, chain hash), the chain head, and
  the operative artefacts by id and version (investigation
  record, dispositions, narrative, verification, approval), and
  certifies it with a hash. Before certifying anything, sealing
  re-verifies the whole evidence chain: a case whose chain does
  not verify cannot be sealed — the seal would be certifying a
  completeness the file does not have.
- **A sealed case is read-only.** Its state is derived from the
  append-only seal history (the operative seal is the latest one
  no unseal lifts), and every mutating service path — evidence
  intake, screening, typologies, investigation, disposition,
  drafting, approval — refuses on it with the one named reason
  (``case_sealed``, see ``evidence.ensure_case_mutable``). The
  only writes a sealed case accepts are this service's own
  custody records: seals, unseals, legal-hold events.
- **Unsealing** is a named officer's act with a coded reason,
  recorded the same way. The seal it lifts is never edited or
  removed; a reseal is the next seal version, and the history
  keeps all of it.
- **Legal hold** is placed and released by a named officer with
  coded reasons, recorded on the chain. A hold in force blocks
  an archive seal, is stated on every seal's retention metadata,
  and suspends any retention consequence. There is **no purge
  path anywhere in this system** — retention dates are recorded
  so the file's custody is governed, never so anything can be
  destroyed; a hold would bar a purge if one were ever built,
  and it is recorded here so that remains a fact, not a hope.
- **Export** produces the sealed file as one package (manifest +
  every certified item's content + the seal and custody
  history), and :func:`verify_export_package` re-checks a
  package end to end — offline, with no store — naming any item
  that was altered, dropped, or added after sealing.

And the boundary this whole blueprint keeps: sealing a SAR case
file does not file anything. **No SAR is ever filed by this
system** — approval and sealing end at an approved, sealed case
file.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import date, datetime, timezone

from .errors import (
    CaseNotFoundError,
    EvidenceChainError,
    SealingRefusedError,
)
from .evidence import (
    EvidenceService,
    chain_hash,
    content_hash,
    operative_seal,
)
from .intake import RETENTION_YEARS
from .logging_config import get_logger
from .models import (
    ArtefactPin,
    AuditEvent,
    Case,
    CaseSeal,
    CaseSealManifest,
    CaseUnseal,
    ExportVerification,
    LegalHoldEvent,
    SealManifestItem,
    TERMINAL_STATUSES,
)
from .ports import (
    ApprovalStore,
    CaseStore,
    DispositionStore,
    InvestigationStore,
    SarNarrativeStore,
    SealStore,
)

logger = get_logger(__name__)

#: The export package format identifier. A package that does not
#: carry it is not verified against this round's rules at all.
EXPORT_FORMAT = "harborline-case-file-export/1"

#: Retention basis stated on every seal, in words.
RETENTION_BASIS = (
    "BSA five-year retention posture: the sealed case file is "
    "retained for five years from the seal date. Retention "
    "authorises no destruction — no purge path exists in this "
    "system — and a legal hold suspends any retention consequence."
)

#: The coded officer roles for custody acts (seal, unseal, hold).
#: Custody is senior work: the analyst role that works cases does
#: not seal them.
OFFICER_ROLES = frozenset({"senior_analyst", "l2_reviewer"})

#: Actors that are the system, not a person — the same vocabulary
#: the disposition gate refuses (dispositions.SYSTEM_ACTORS); kept
#: in step with it deliberately, since custody is a human act for
#: the same reason disposition is.
SYSTEM_ACTORS = frozenset(
    {
        "system",
        "agent",
        "anonymous",
        "unknown",
        "none",
        "aml-agent",
        "intake-service",
        "screening-service",
        "typology-service",
        "investigation-service",
    }
)

#: What a seal may be for. "custody" is the ordinary seal of a
#: completed file; "archive" moves the file to long-term archive
#: custody — the move a legal hold blocks.
SEAL_PURPOSES = frozenset({"custody", "archive"})

#: Coded reasons an officer may unseal a case file.
UNSEAL_REASON_CODES = frozenset(
    {
        "SEAL_ERROR_CORRECTION",
        "INVESTIGATION_REOPENED",
        "REGULATORY_REQUEST",
        "COURT_ORDER",
        "CONTINUING_ACTIVITY_REVIEW",
    }
)

#: Coded reasons a legal hold may be placed.
HOLD_REASON_CODES = frozenset(
    {
        "LITIGATION_PENDING",
        "REGULATORY_EXAMINATION",
        "COURT_ORDER",
        "INVESTIGATION_ONGOING",
    }
)

#: Coded reasons a legal hold may be released.
HOLD_RELEASE_REASON_CODES = frozenset(
    {
        "MATTER_RESOLVED",
        "HOLD_LAPSED",
        "ORDER_LIFTED",
        "EXAMINATION_CLOSED",
    }
)


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def seal_hash_for(manifest: CaseSealManifest) -> str:
    """The seal's certificate: SHA-256 over the manifest's
    canonical JSON. Any change to any listed item, hash, or
    artefact pin changes it."""
    return hashlib.sha256(
        _canonical(manifest.model_dump(mode="json"))
    ).hexdigest()


def _plus_years(day: date, years: int) -> date:
    try:
        return day.replace(year=day.year + years)
    except ValueError:  # Feb 29 -> Feb 28 in the target year
        return day.replace(year=day.year + years, day=28)


class CaseSealingService:
    """Seals, unseals, holds, and exports case files (R7)."""

    def __init__(
        self,
        store: CaseStore,
        records: InvestigationStore,
        dispositions: DispositionStore,
        narratives: SarNarrativeStore,
        approvals: ApprovalStore,
        evidence: EvidenceService,
        seals: SealStore,
    ) -> None:
        self._store = store
        self._records = records
        self._dispositions = dispositions
        self._narratives = narratives
        self._approvals = approvals
        self._evidence = evidence
        self._seals = seals

    # -- refusals + identity -------------------------------------------

    def _refuse(
        self, case_id: str, actor: str, reason: str, message: str
    ) -> SealingRefusedError:
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="sealing_refused",
                detail={"reason": reason, "message": message},
            )
        )
        return SealingRefusedError(reason, message)

    def _require_case(self, case_id: str) -> Case:
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        return case

    def _validate_officer(
        self, case_id: str, officer_id: str, officer_role: str
    ) -> str:
        officer = officer_id or ""
        if not officer.strip() or officer.strip().lower() in SYSTEM_ACTORS:
            raise self._refuse(
                case_id,
                officer or "anonymous",
                "anonymous_or_system_actor",
                f"a custody act must name the officer performing "
                f"it; {officer_id!r} is anonymous or a system actor",
            )
        if officer_role not in OFFICER_ROLES:
            raise self._refuse(
                case_id,
                f"officer:{officer}",
                "officer_role_required",
                f"custody acts are officer work: the role must be "
                f"one of ({', '.join(sorted(OFFICER_ROLES))}), "
                f"not {officer_role!r}",
            )
        return f"officer:{officer}"

    # -- derived state ---------------------------------------------------

    def current_seal(self, case_id: str) -> CaseSeal | None:
        self._require_case(case_id)
        return operative_seal(self._seals, case_id)

    def is_sealed(self, case_id: str) -> bool:
        return operative_seal(self._seals, case_id) is not None

    def hold_in_force(self, case_id: str) -> bool:
        events = self._seals.list_hold_events(case_id)
        return bool(events) and events[-1].action == "placed"

    def hold_events(self, case_id: str) -> list[LegalHoldEvent]:
        self._require_case(case_id)
        return self._seals.list_hold_events(case_id)

    # -- sealing -----------------------------------------------------------

    def seal_case(
        self,
        case_id: str,
        *,
        officer_id: str,
        officer_role: str,
        purpose: str = "custody",
    ) -> CaseSeal:
        """Seal a terminal case file: verify its chain, certify a
        manifest over every evidence item and the case's operative
        artefacts, and make the file read-only."""
        case = self._require_case(case_id)
        actor = self._validate_officer(case_id, officer_id, officer_role)
        if purpose not in SEAL_PURPOSES:
            raise self._refuse(
                case_id,
                actor,
                "unknown_seal_purpose",
                f"seal purpose {purpose!r} is not one of "
                f"({', '.join(sorted(SEAL_PURPOSES))})",
            )
        existing = operative_seal(self._seals, case_id)
        if existing is not None:
            raise self._refuse(
                case_id,
                actor,
                "already_sealed",
                f"case is already sealed (seal {existing.seal_id}, "
                f"version {existing.version}); unseal it before "
                "resealing — the history keeps both",
            )
        on_hold = self.hold_in_force(case_id)
        if purpose == "archive" and on_hold:
            raise self._refuse(
                case_id,
                actor,
                "legal_hold_blocks_archive",
                "a legal hold stands on this case; an archive seal "
                "is refused while the hold is in force — seal for "
                "custody, or have the hold released first",
            )
        if case.status not in TERMINAL_STATUSES:
            raise self._refuse(
                case_id,
                actor,
                "case_not_terminal",
                f"case is {case.status.value}; only a case in a "
                "terminal state (closed, or filed_sar with its "
                "narrative approved) may be sealed — a file still "
                "being worked is not certified",
            )
        try:
            self._evidence.verify_chain(case_id)
        except EvidenceChainError as exc:
            raise self._refuse(
                case_id,
                actor,
                "evidence_chain_broken",
                f"the evidence chain does not verify ({exc}); a "
                "seal certifies the manifest complete, and this "
                "file's completeness cannot be certified",
            )

        items = self._store.list_evidence(case_id)
        manifest = CaseSealManifest(
            case_id=case_id,
            chain_head_hash=case.evidence_head_hash or "",
            items=[
                SealManifestItem(
                    seq=item.seq,
                    kind=item.kind,
                    content_sha256=item.content_sha256,
                    chain_hash=item.chain_hash,
                )
                for item in items
            ],
            artefacts=self._artefact_pins(case_id),
        )
        if items and manifest.chain_head_hash != items[-1].chain_hash:
            raise self._refuse(
                case_id,
                actor,
                "evidence_chain_broken",
                "the case's recorded chain head does not match its "
                "latest evidence item; the manifest cannot be "
                "certified complete",
            )
        sealed_at = datetime.now(timezone.utc)
        retention_until = _plus_years(sealed_at.date(), RETENTION_YEARS)
        seal = CaseSeal(
            case_id=case_id,
            version=len(self._seals.list_seals(case_id)) + 1,
            sealed_by=officer_id,
            sealed_role=officer_role,
            sealed_at=sealed_at,
            purpose=purpose,
            manifest=manifest,
            seal_hash=seal_hash_for(manifest),
            retention_basis=RETENTION_BASIS,
            retention_until=retention_until,
            legal_hold=on_hold,
        )
        item = self._evidence.add_item(
            case_id=case_id,
            kind="case_seal",
            content=seal.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"case-seal:{seal.seal_id}",
            captured_by=actor,
            custody_record=True,
        )
        final = seal.model_copy(update={"evidence_seq": item.seq})
        self._seals.add_seal(final)
        refreshed = self._store.get_case(case_id)
        if refreshed is not None:
            refreshed.retention_until = retention_until
            self._store.update_case(refreshed)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="case_sealed",
                detail={
                    "seal_id": final.seal_id,
                    "version": str(final.version),
                    "seal_hash": final.seal_hash,
                    "items_certified": str(len(manifest.items)),
                    "purpose": purpose,
                    "legal_hold": str(on_hold),
                    "retention_until": retention_until.isoformat(),
                },
            )
        )
        logger.info(
            "case %s sealed: %s (version %d, %d items)",
            case_id,
            final.seal_id,
            final.version,
            len(manifest.items),
        )
        return final

    def unseal_case(
        self,
        case_id: str,
        *,
        officer_id: str,
        officer_role: str,
        reason_code: str,
        note: str = "",
    ) -> CaseUnseal:
        """Lift the operative seal: a named officer, a coded
        reason, its own custody record. The seal stays in history."""
        self._require_case(case_id)
        actor = self._validate_officer(case_id, officer_id, officer_role)
        seal = operative_seal(self._seals, case_id)
        if seal is None:
            raise self._refuse(
                case_id,
                actor,
                "case_not_sealed",
                "the case is not sealed; there is no seal to lift",
            )
        if reason_code not in UNSEAL_REASON_CODES:
            raise self._refuse(
                case_id,
                actor,
                "unknown_unseal_reason",
                f"unseal reason {reason_code!r} is not in the "
                f"vocabulary ({', '.join(sorted(UNSEAL_REASON_CODES))})",
            )
        unseal = CaseUnseal(
            case_id=case_id,
            seal_id=seal.seal_id,
            unsealed_by=officer_id,
            unsealed_role=officer_role,
            reason_code=reason_code,
            note=note,
        )
        item = self._evidence.add_item(
            case_id=case_id,
            kind="case_unseal",
            content=unseal.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"case-unseal:{unseal.unseal_id}",
            captured_by=actor,
            custody_record=True,
        )
        final = unseal.model_copy(update={"evidence_seq": item.seq})
        self._seals.add_unseal(final)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="case_unsealed",
                detail={
                    "unseal_id": final.unseal_id,
                    "seal_id": seal.seal_id,
                    "reason_code": reason_code,
                },
            )
        )
        logger.info(
            "case %s unsealed: seal %s lifted (%s)",
            case_id,
            seal.seal_id,
            reason_code,
        )
        return final

    # -- legal hold ---------------------------------------------------------

    def place_hold(
        self,
        case_id: str,
        *,
        officer_id: str,
        officer_role: str,
        reason_code: str,
        note: str = "",
    ) -> LegalHoldEvent:
        self._require_case(case_id)
        actor = self._validate_officer(case_id, officer_id, officer_role)
        if reason_code not in HOLD_REASON_CODES:
            raise self._refuse(
                case_id,
                actor,
                "unknown_hold_reason",
                f"legal-hold reason {reason_code!r} is not in the "
                f"vocabulary ({', '.join(sorted(HOLD_REASON_CODES))})",
            )
        if self.hold_in_force(case_id):
            raise self._refuse(
                case_id,
                actor,
                "already_on_hold",
                "a legal hold already stands on this case; a second "
                "placing adds nothing to the record",
            )
        return self._record_hold(
            case_id,
            actor=actor,
            action="placed",
            officer_id=officer_id,
            officer_role=officer_role,
            reason_code=reason_code,
            note=note,
        )

    def release_hold(
        self,
        case_id: str,
        *,
        officer_id: str,
        officer_role: str,
        reason_code: str,
        note: str = "",
    ) -> LegalHoldEvent:
        self._require_case(case_id)
        actor = self._validate_officer(case_id, officer_id, officer_role)
        if reason_code not in HOLD_RELEASE_REASON_CODES:
            raise self._refuse(
                case_id,
                actor,
                "unknown_hold_release_reason",
                f"hold-release reason {reason_code!r} is not in "
                f"the vocabulary "
                f"({', '.join(sorted(HOLD_RELEASE_REASON_CODES))})",
            )
        if not self.hold_in_force(case_id):
            raise self._refuse(
                case_id,
                actor,
                "not_on_hold",
                "no legal hold stands on this case; there is "
                "nothing to release",
            )
        return self._record_hold(
            case_id,
            actor=actor,
            action="released",
            officer_id=officer_id,
            officer_role=officer_role,
            reason_code=reason_code,
            note=note,
        )

    def _record_hold(
        self,
        case_id: str,
        *,
        actor: str,
        action: str,
        officer_id: str,
        officer_role: str,
        reason_code: str,
        note: str,
    ) -> LegalHoldEvent:
        event = LegalHoldEvent(
            case_id=case_id,
            action=action,
            officer_id=officer_id,
            officer_role=officer_role,
            reason_code=reason_code,
            note=note,
        )
        item = self._evidence.add_item(
            case_id=case_id,
            kind="legal_hold",
            content=event.model_dump_json(indent=2).encode("utf-8"),
            source_ref=f"legal-hold:{event.hold_event_id}",
            captured_by=actor,
            custody_record=True,
        )
        final = event.model_copy(update={"evidence_seq": item.seq})
        self._seals.add_hold_event(final)
        case = self._store.get_case(case_id)
        if case is not None:
            case.legal_hold = action == "placed"
            self._store.update_case(case)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event=f"legal_hold_{action}",
                detail={
                    "hold_event_id": final.hold_event_id,
                    "reason_code": reason_code,
                },
            )
        )
        logger.info("case %s: legal hold %s (%s)", case_id, action, reason_code)
        return final

    # -- export ---------------------------------------------------------------

    def export_case_file(self, case_id: str) -> dict:
        """The sealed case file as one package: the operative
        seal, its manifest, the full content of every certified
        evidence item, and the custody + audit history. Refused
        for an unsealed case — an export certifies a sealed file,
        not a work in progress."""
        case = self._require_case(case_id)
        seal = operative_seal(self._seals, case_id)
        if seal is None:
            raise self._refuse(
                case_id,
                "export-service",
                "case_not_sealed",
                "only a sealed case file is exported; seal the "
                "case first — an export is the sealed file, "
                "certified, not a snapshot of work in progress",
            )
        items = []
        for entry in seal.manifest.items:
            item = self._store.get_evidence_item(case_id, entry.seq)
            content = self._evidence.read_item_content(case_id, entry.seq)
            items.append(
                {
                    "seq": entry.seq,
                    "kind": entry.kind,
                    "media_type": item.media_type if item else None,
                    "source_ref": item.source_ref if item else None,
                    "captured_by": item.captured_by if item else None,
                    "content_sha256": entry.content_sha256,
                    "prev_hash": item.prev_hash if item else None,
                    "chain_hash": entry.chain_hash,
                    "content_b64": base64.b64encode(content).decode("ascii"),
                }
            )
        return {
            "format": EXPORT_FORMAT,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "case_id": case_id,
            "case": case.model_dump(mode="json"),
            "seal": seal.model_dump(mode="json"),
            "manifest": seal.manifest.model_dump(mode="json"),
            "seal_history": self.seal_history(case_id),
            "legal_holds": [
                e.model_dump(mode="json")
                for e in self._seals.list_hold_events(case_id)
            ],
            "items": items,
            "audit": [
                e.model_dump(mode="json")
                for e in self._store.list_audit(case_id)
            ],
        }

    # -- views ------------------------------------------------------------------

    def _artefact_pins(self, case_id: str) -> list[ArtefactPin]:
        pins: list[ArtefactPin] = []
        records = self._records.list_investigation_records(case_id)
        if records:
            current = records[-1]
            pins.append(
                ArtefactPin(
                    kind="investigation_record",
                    artefact_id=current.record_id,
                    version=current.version,
                )
            )
        for disposition in self._dispositions.list_dispositions(case_id):
            pins.append(
                ArtefactPin(
                    kind="disposition",
                    artefact_id=disposition.disposition_id,
                    detail=disposition.outcome.value,
                )
            )
        narratives = self._narratives.list_narratives(case_id)
        if narratives:
            current = narratives[-1]
            pins.append(
                ArtefactPin(
                    kind="sar_narrative",
                    artefact_id=current.narrative_id,
                    version=current.version,
                )
            )
            verification = self._narratives.get_verification_for(
                current.narrative_id
            )
            if verification is not None:
                pins.append(
                    ArtefactPin(
                        kind="sar_narrative_verification",
                        artefact_id=verification.verification_id,
                        detail=f"all_verified={verification.all_verified}",
                    )
                )
            approval = self._approvals.get_approval_for(current.narrative_id)
            if approval is not None:
                pins.append(
                    ArtefactPin(
                        kind="sar_approval",
                        artefact_id=approval.approval_id,
                        detail=approval.outcome.value,
                    )
                )
        return pins

    def seal_history(self, case_id: str) -> list[dict]:
        """Seals and unseals in chain order, with the operative
        seal marked — the file's custody history."""
        entries: list[tuple[int, dict]] = []
        for seal in self._seals.list_seals(case_id):
            body = seal.model_dump(mode="json")
            body["record"] = "seal"
            entries.append((seal.evidence_seq or 0, body))
        for unseal in self._seals.list_unseals(case_id):
            body = unseal.model_dump(mode="json")
            body["record"] = "unseal"
            entries.append((unseal.evidence_seq or 0, body))
        entries.sort(key=lambda pair: pair[0])
        return [body for _, body in entries]

    def view(self, seal: CaseSeal) -> dict:
        body = seal.model_dump(mode="json")
        operative = operative_seal(self._seals, seal.case_id)
        body["operative"] = (
            operative is not None and operative.seal_id == seal.seal_id
        )
        body["legal_hold_in_force"] = self.hold_in_force(seal.case_id)
        return body

    def case_file_view(self, case_id: str) -> dict:
        """The case's custody state: operative seal, seal history,
        legal-hold state — the R7 read model."""
        self._require_case(case_id)
        seal = operative_seal(self._seals, case_id)
        return {
            "case_id": case_id,
            "sealed": seal is not None,
            "current_seal": (
                self.view(seal) if seal is not None else None
            ),
            "seal_history": self.seal_history(case_id),
            "legal_hold_in_force": self.hold_in_force(case_id),
            "legal_holds": [
                e.model_dump(mode="json")
                for e in self._seals.list_hold_events(case_id)
            ],
        }


def verify_export_package(package: dict) -> ExportVerification:
    """Re-check an exported case-file package end to end — offline.

    No store, no network: everything the check needs is in the
    package. It verifies that the seal hash reproduces over the
    manifest the package carries; that every item the manifest
    certifies is present, unaltered (its content hashes to the
    certified value), and chained (each link recomputes, and the
    chain lands on the manifest's head); and that the package
    carries nothing the manifest does not certify. Every failure
    is named — an altered item by its seq — and ``ok`` is true
    only when there are no failures.
    """
    problems: list[str] = []
    case_id = str(package.get("case_id") or "")
    seal = package.get("seal") or {}
    seal_id = str(seal.get("seal_id") or "")
    if package.get("format") != EXPORT_FORMAT:
        problems.append(
            f"package format {package.get('format')!r} is not "
            f"{EXPORT_FORMAT!r}; this package is not verified "
            "against the export rules"
        )
        return ExportVerification(
            case_id=case_id, seal_id=seal_id, ok=False, problems=problems
        )
    manifest = package.get("manifest") or seal.get("manifest") or {}
    if not manifest:
        problems.append("the package carries no seal manifest")
        return ExportVerification(
            case_id=case_id, seal_id=seal_id, ok=False, problems=problems
        )
    if manifest.get("case_id") != case_id:
        problems.append(
            f"manifest is for case {manifest.get('case_id')!r}, "
            f"package is for case {case_id!r}"
        )
    expected_hash = hashlib.sha256(_canonical(manifest)).hexdigest()
    if seal.get("seal_hash") != expected_hash:
        problems.append(
            "seal hash mismatch: the manifest in this package does "
            "not hash to the value the seal certifies — the "
            "manifest has been altered since sealing"
        )
    entries = sorted(
        manifest.get("items") or [], key=lambda e: e.get("seq", 0)
    )
    package_items = package.get("items") or []
    by_seq = {item.get("seq"): item for item in package_items}
    certified = {entry.get("seq") for entry in entries}
    for seq in sorted(s for s in by_seq if s not in certified):
        problems.append(
            f"package carries item seq {seq}, which the seal's "
            "manifest does not certify — content added after sealing"
        )
    prev_hash: str | None = None
    checked = 0
    for entry in entries:
        seq = entry.get("seq")
        kind = entry.get("kind")
        item = by_seq.get(seq)
        if item is None:
            problems.append(
                f"manifest item seq {seq} ({kind}) is missing from "
                "the package — the export is incomplete"
            )
            continue
        checked += 1
        if item.get("kind") != kind:
            problems.append(
                f"item seq {seq}: kind {item.get('kind')!r} does "
                f"not match the manifest's {kind!r}"
            )
        if item.get("content_sha256") != entry.get("content_sha256"):
            problems.append(
                f"item seq {seq}: the package's recorded content "
                "hash does not match the manifest's certified hash"
            )
        try:
            content = base64.b64decode(
                item.get("content_b64") or "", validate=True
            )
        except (ValueError, TypeError):
            problems.append(
                f"item seq {seq}: content is not valid base64"
            )
            content = b""
        if content_hash(content) != entry.get("content_sha256"):
            problems.append(
                f"item seq {seq} ({kind}): content does not hash to "
                "the certified value — the item has been altered "
                "since sealing"
            )
        link = chain_hash(
            prev_hash,
            str(entry.get("content_sha256")),
            case_id,
            int(seq),
            str(kind),
        )
        if link != entry.get("chain_hash"):
            problems.append(
                f"item seq {seq} ({kind}): chain link does not "
                "recompute — the item's position or content in the "
                "chain has been altered"
            )
        if item.get("chain_hash") != entry.get("chain_hash"):
            problems.append(
                f"item seq {seq}: the package's recorded chain hash "
                "does not match the manifest's certified hash"
            )
        prev_hash = str(entry.get("chain_hash"))
    if entries and prev_hash != manifest.get("chain_head_hash"):
        problems.append(
            "the item chain does not recompute to the manifest's "
            "chain head hash"
        )
    return ExportVerification(
        case_id=case_id,
        seal_id=seal_id,
        ok=not problems,
        items_checked=checked,
        problems=problems,
    )
