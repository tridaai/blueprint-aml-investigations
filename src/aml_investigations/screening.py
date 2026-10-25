"""Screening: version-pinned list snapshots and delta re-screening.

Law 3 lives here. Sanctions, PEP, and adverse-media lists are
ingested as immutable, versioned snapshots. Every screening run is
pinned to an explicit snapshot set — the case record names the exact
versions it was screened against, forever. When a newer snapshot of
a list arrives, open cases screened on the older version are flagged
``STALE_SCREENING``; a re-screen on the new version clears the flag
and its results sit alongside the earlier run's, never replacing
them.

Name matching is deterministic — no model, no embeddings. The rules
(see ``match_name``) are documented, ordered, and identical on every
run, because a screening result a bank cannot reproduce is a
screening result it cannot defend to an examiner.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from .errors import (
    CaseNotFoundError,
    HitNotFoundError,
    ScreeningError,
    ScreeningPinRequiredError,
    SnapshotImmutableError,
    SnapshotNotFoundError,
)
from .evidence import EvidenceService, ensure_case_mutable
from .logging_config import get_logger
from .models import (
    AuditEvent,
    Case,
    HitStatus,
    ListEntry,
    ListKind,
    ListSnapshot,
    ScreenedAgainst,
    ScreeningHit,
    ScreeningRun,
    ScreeningSubject,
    TERMINAL_STATUSES,
)
from .ports import CaseStore, ScreeningStore, SealStore

logger = get_logger(__name__)

FLAG_STALE_SCREENING = "STALE_SCREENING"
FLAG_SANCTIONS_HIT = "SANCTIONS_HIT"

#: Minimum token-overlap (Jaccard) for a name pair to count as a match
#: at all. Below this, two names are simply different names.
_MIN_OVERLAP = 0.5


# ---------------------------------------------------------------------------
# Deterministic name matching
# ---------------------------------------------------------------------------


def normalise_name(name: str) -> list[str]:
    """Normalise a name to a token list.

    Steps, in order: Unicode NFKD decomposition; drop combining marks
    (diacritics); lowercase; every non-alphanumeric character becomes
    a space; split on whitespace. "José  O'Brien-Smith" and
    "jose obrien smith" normalise identically.
    """
    decomposed = unicodedata.normalize("NFKD", name)
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    cleaned = re.sub(r"[^a-z0-9]+", " ", stripped.lower())
    return cleaned.split()


def normalise_identifier(identifier: str) -> str:
    """Identifiers compare stripped of case, spaces, and punctuation."""
    return re.sub(r"[^A-Z0-9]+", "", identifier.upper())


def match_name(
    subject_tokens: list[str], entry_tokens: list[str]
) -> tuple[float, str] | None:
    """Score one name pair. Returns (score, rule) or None for no match.

    Rules, first that fires wins:
      exact_name        identical token sequences            -> 1.00
      name_token_set    same tokens, different order         -> 0.95
      name_token_subset one side's tokens all in the other
                        (both sides >= 2 tokens)             -> 0.85
      name_token_overlap Jaccard >= 0.5 with >= 2 shared     -> Jaccard
    """
    if not subject_tokens or not entry_tokens:
        return None
    if subject_tokens == entry_tokens:
        return 1.0, "exact_name"
    subject_set, entry_set = set(subject_tokens), set(entry_tokens)
    if subject_set == entry_set:
        return 0.95, "name_token_set"
    if len(subject_set) >= 2 and len(entry_set) >= 2:
        if subject_set <= entry_set or entry_set <= subject_set:
            return 0.85, "name_token_subset"
    shared = subject_set & entry_set
    if len(shared) >= 2:
        jaccard = len(shared) / len(subject_set | entry_set)
        if jaccard >= _MIN_OVERLAP:
            return round(jaccard, 4), "name_token_overlap"
    return None


def _best_name_match(
    subject: ScreeningSubject, entry: ListEntry
) -> tuple[float, str] | None:
    """Best score over every (subject name/alias) x (entry name/alias)
    pair, with the surfaces named in the basis."""
    subject_surfaces = [("name", subject.name)] + [
        ("alias", alias) for alias in subject.aliases
    ]
    entry_surfaces = [("name", entry.name)] + [
        ("alias", alias) for alias in entry.aliases
    ]
    best: tuple[float, str] | None = None
    for s_label, s_name in subject_surfaces:
        s_tokens = normalise_name(s_name)
        for e_label, e_name in entry_surfaces:
            result = match_name(s_tokens, normalise_name(e_name))
            if result is None:
                continue
            score, rule = result
            basis = f"{rule} (subject {s_label} vs entry {e_label})"
            if best is None or score > best[0]:
                best = (score, basis)
    return best


def snapshot_content_hash(snapshot: ListSnapshot) -> str:
    """SHA-256 over the snapshot's canonical content.

    The canonical form covers the list kind, the version, and every
    entry's fields (aliases sorted, identifiers sorted) — so the hash
    changes iff the screening-relevant content changes.
    """
    canonical = {
        "list_kind": snapshot.list_kind.value,
        "version": snapshot.version,
        "entries": [
            {
                "entry_id": e.entry_id,
                "name": e.name,
                "aliases": sorted(e.aliases),
                "dob": e.dob.isoformat() if e.dob else None,
                "identifiers": sorted(normalise_identifier(i) for i in e.identifiers),
                "note": e.note,
            }
            for e in sorted(snapshot.entries, key=lambda e: e.entry_id)
        ],
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# List sources (the feed side of the port)
# ---------------------------------------------------------------------------


class ListScreeningFeed:
    """ScreeningListSource over an in-memory list (tests, embedding)."""

    def __init__(self, snapshots: list[ListSnapshot]) -> None:
        self._snapshots = list(snapshots)

    def list_snapshots(self) -> list[ListSnapshot]:
        return list(self._snapshots)


class ReferenceScreeningFeed:
    """ScreeningListSource over a JSON file of snapshot definitions."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._snapshots: list[ListSnapshot] = []
        if self._path.exists():
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            for entry in payload.get("snapshots", []):
                self._snapshots.append(ListSnapshot.model_validate(entry))

    def list_snapshots(self) -> list[ListSnapshot]:
        return list(self._snapshots)


# ---------------------------------------------------------------------------
# The screening service
# ---------------------------------------------------------------------------


class ScreeningService:
    """Ingests snapshots, runs pinned screenings, tracks staleness.

    One service owns every write path that touches snapshots, runs,
    and hits, which is what keeps the case record's screening fields
    (``screened_against``, ``screening_stale``, ``flags``) in sync
    with the hit records the state machine guard reads.
    """

    def __init__(
        self,
        store: CaseStore,
        screening_store: ScreeningStore,
        evidence: EvidenceService,
        seal_store: SealStore | None = None,
        quarantine=None,
    ) -> None:
        self._store = store
        self._screening = screening_store
        self._evidence = evidence
        self._seals = seal_store
        # R10 (Law 7): when wired, the names a run produces —
        # subject names from the alert payload and entry names from
        # the list vendor — are scanned as the result lands and
        # matches quarantined, so a name carrying an instruction
        # reaches the investigation record only fenced.
        self._quarantine = quarantine

    # -- snapshot ingest ------------------------------------------------

    def ingest_snapshot(
        self, snapshot: ListSnapshot, *, actor: str = "list-feed"
    ) -> ListSnapshot:
        """Ingest one snapshot. Idempotent for identical content;
        refused (SnapshotImmutableError) when the same kind + version
        arrives with different content — that is a corrected list,
        and a corrected list is a new version, never an edit."""
        digest = snapshot_content_hash(snapshot)
        if snapshot.content_hash and snapshot.content_hash != digest:
            raise ScreeningError(
                f"snapshot {snapshot.list_kind.value} {snapshot.version}: "
                "declared content_hash does not match its content"
            )
        snapshot = snapshot.model_copy(update={"content_hash": digest})
        existing = self._screening.get_snapshot(snapshot.list_kind, snapshot.version)
        if existing is not None:
            if existing.content_hash == digest:
                return existing
            raise SnapshotImmutableError(
                f"{snapshot.list_kind.value} version {snapshot.version} is "
                f"already ingested with different content (hash "
                f"{existing.content_hash[:12]}…); ingest the corrected "
                "list as a new version"
            )
        self._screening.save_snapshot(snapshot)
        self._store.append_audit(
            AuditEvent(
                case_id=None,
                actor=actor,
                event="snapshot_ingested",
                detail={
                    "list_kind": snapshot.list_kind.value,
                    "version": snapshot.version,
                    "snapshot_id": snapshot.snapshot_id,
                    "content_hash": digest,
                    "entries": snapshot.entry_count,
                },
            )
        )
        flagged = self._flag_stale_cases(snapshot, actor=actor)
        logger.info(
            "snapshot ingested",
            extra={
                "event": "snapshot_ingested",
                "list_kind": snapshot.list_kind.value,
                "version": snapshot.version,
                "stale_flagged": len(flagged),
            },
        )
        return snapshot

    def ingest_from_source(self, source, *, actor: str = "list-feed") -> list[ListSnapshot]:
        return [self.ingest_snapshot(s, actor=actor) for s in source.list_snapshots()]

    def _flag_stale_cases(
        self, new_snapshot: ListSnapshot, *, actor: str
    ) -> list[str]:
        """Flag open cases screened on an older version of this list.

        'Older' is by ``published_at`` — version labels are the
        publisher's, the clock is ours. Terminal cases are sealed
        history and are never flagged.
        """
        flagged: list[str] = []
        for case in self._store.list_cases():
            if case.status in TERMINAL_STATUSES:
                continue
            for screened in case.screened_against:
                if screened.list_kind != new_snapshot.list_kind:
                    continue
                if screened.snapshot_id == new_snapshot.snapshot_id:
                    continue
                previous = self._screening.get_snapshot(
                    screened.list_kind, screened.version
                )
                if previous is not None and previous.published_at >= new_snapshot.published_at:
                    continue
                if not case.screening_stale:
                    case.screening_stale = True
                    self._refresh_flags(case)
                    self._store.update_case(case)
                    self._store.append_audit(
                        AuditEvent(
                            case_id=case.case_id,
                            actor=actor,
                            event="screening_stale_flagged",
                            detail={
                                "list_kind": new_snapshot.list_kind.value,
                                "screened_version": screened.version,
                                "new_version": new_snapshot.version,
                            },
                        )
                    )
                flagged.append(case.case_id)
                break
        return flagged

    # -- subjects ---------------------------------------------------------

    def derive_subjects(self, case: Case) -> list[ScreeningSubject]:
        """Default subject set from the case's alert payload evidence:
        the customer (name + aliases + identifiers carried in the
        alert's raw payload) plus any counterparties named there.

        Fuller subject assembly from the KYC profile is the KYC
        round's job; callers with better subjects pass them to
        ``screen_case`` explicitly.
        """
        payload_item = None
        for item in self._store.list_evidence(case.case_id):
            if item.kind == "alert_payload":
                payload_item = item
                break
        if payload_item is None:
            return []
        from .models import Alert

        raw_bytes = self._evidence.read_item_content(case.case_id, payload_item.seq)
        alert = Alert.model_validate_json(raw_bytes.decode("utf-8"))
        raw = alert.raw or {}
        subjects: list[ScreeningSubject] = []
        customer_name = raw.get("customer_name")
        if customer_name:
            subjects.append(
                ScreeningSubject(
                    subject_ref=case.customer_id,
                    name=customer_name,
                    role="customer",
                    aliases=list(raw.get("customer_aliases", [])),
                    dob=raw.get("customer_dob"),
                    identifiers=list(raw.get("customer_identifiers", [])),
                )
            )
            for alias in raw.get("customer_aliases", []):
                subjects.append(
                    ScreeningSubject(
                        subject_ref=f"{case.customer_id}:alias",
                        name=alias,
                        role="alias",
                        dob=raw.get("customer_dob"),
                        identifiers=list(raw.get("customer_identifiers", [])),
                    )
                )
        for idx, counterparty in enumerate(raw.get("counterparties", [])):
            if not isinstance(counterparty, dict) or not counterparty.get("name"):
                continue
            subjects.append(
                ScreeningSubject(
                    subject_ref=f"counterparty:{idx}",
                    name=counterparty["name"],
                    role="counterparty",
                    aliases=list(counterparty.get("aliases", [])),
                    dob=counterparty.get("dob"),
                    identifiers=list(counterparty.get("identifiers", [])),
                )
            )
        return subjects

    # -- screening runs ---------------------------------------------------

    def screen_case(
        self,
        case_id: str,
        pins: dict[ListKind, str] | dict[str, str],
        *,
        actor: str,
        subjects: list[ScreeningSubject] | None = None,
    ) -> ScreeningRun:
        """Screen one case against an explicitly pinned snapshot set.

        Refused, by construction, when: no pin set is given
        (ScreeningPinRequiredError), a pin names a kind + version
        that was never ingested (SnapshotNotFoundError), or no
        subjects can be determined (ScreeningError). A run always
        records its results as an evidence item on the case.
        """
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        ensure_case_mutable(self._seals, case_id)
        if not pins:
            raise ScreeningPinRequiredError(
                "screening requires an explicit pinned snapshot set "
                "(list kind -> version); screening against 'current' "
                "lists is not reproducible and is refused"
            )
        snapshots: list[ListSnapshot] = []
        for kind_key, version in pins.items():
            kind = kind_key if isinstance(kind_key, ListKind) else ListKind(kind_key)
            snapshot = self._screening.get_snapshot(kind, version)
            if snapshot is None:
                raise SnapshotNotFoundError(
                    f"no ingested snapshot for {kind.value} version {version!r}"
                )
            snapshots.append(snapshot)

        subject_list = subjects if subjects is not None else self.derive_subjects(case)
        if not subject_list:
            raise ScreeningError(
                f"case {case_id}: no screening subjects — none supplied "
                "and none derivable from the alert payload"
            )

        is_rescreen = bool(case.screened_against)
        run = ScreeningRun(case_id=case_id, actor=actor, is_rescreen=is_rescreen)
        pin_lines = [
            ScreenedAgainst(
                list_kind=s.list_kind,
                snapshot_id=s.snapshot_id,
                version=s.version,
                run_id=run.run_id,
                screened_at=run.run_at,
            )
            for s in snapshots
        ]
        run = run.model_copy(
            update={"pins": pin_lines, "subject_count": len(subject_list)}
        )

        hits: list[ScreeningHit] = []
        for subject in subject_list:
            for snapshot in snapshots:
                for entry in snapshot.entries:
                    hit = self._match_subject_entry(run, subject, snapshot, entry)
                    if hit is not None:
                        hits.append(hit)

        for hit in hits:
            self._screening.add_hit(hit)
        open_hits = [h for h in hits if h.status is HitStatus.OPEN]
        cleared_hits = [h for h in hits if h.status is HitStatus.CLEARED]
        run = run.model_copy(
            update={"open_hits": len(open_hits), "cleared_hits": len(cleared_hits)}
        )

        # The run is recorded as evidence: results are part of the
        # case file, hash-chained like everything else (Law 5).
        content = json.dumps(
            {
                "run": run.model_dump(mode="json"),
                "hits": [h.model_dump(mode="json") for h in hits],
            },
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        item = self._evidence.add_item(
            case_id,
            kind="screening_result",
            content=content,
            source_ref=f"screening:{run.run_id}",
            captured_by=actor,
        )
        run = run.model_copy(update={"evidence_seq": item.seq})
        # R10 (Law 7): the run's names are untrusted text from two
        # directions — the subject's side (alert payload) and the
        # list vendor's side (entry names). Matches quarantine here;
        # matching itself is deterministic code over the raw names
        # and is unaffected either way.
        if self._quarantine is not None and hits:
            name_fields: dict[str, str] = {}
            for hit in hits:
                name_fields[f"hit:{hit.hit_id}.subject_name"] = hit.subject_name
                name_fields[f"hit:{hit.hit_id}.entry_name"] = hit.entry_name
            self._quarantine.record_scan(
                case_id,
                source_kind="screening_result",
                evidence_seq=item.seq,
                fields=name_fields,
                actor=actor,
            )
        self._screening.add_screening_run(run)

        # Refresh the case's screening record.
        case = self._store.get_case(case_id) or case
        by_kind = {s.list_kind: s for s in case.screened_against}
        for pin in pin_lines:
            by_kind[pin.list_kind] = pin
        case.screened_against = [by_kind[k] for k in sorted(by_kind, key=lambda k: k.value)]
        case.screening_stale = self._compute_stale(case)
        self._refresh_flags(case)
        case.updated_at = datetime.now(timezone.utc)
        self._store.update_case(case)

        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor,
                event="screening_run",
                detail={
                    "run_id": run.run_id,
                    "pins": {
                        p.list_kind.value: p.version for p in pin_lines
                    },
                    "subjects": len(subject_list),
                    "open_hits": len(open_hits),
                    "cleared_hits": len(cleared_hits),
                    "is_rescreen": is_rescreen,
                    "evidence_seq": item.seq,
                },
            )
        )
        for hit in open_hits:
            if hit.list_kind is ListKind.SANCTIONS:
                self._store.append_audit(
                    AuditEvent(
                        case_id=case_id,
                        actor=actor,
                        event="sanctions_hit",
                        detail={
                            "hit_id": hit.hit_id,
                            "run_id": run.run_id,
                            "entry_id": hit.entry_id,
                            "entry_name": hit.entry_name,
                            "snapshot_version": hit.snapshot_version,
                            "strength": hit.strength,
                        },
                    )
                )
        logger.info(
            "screening run",
            extra={
                "case_id": case_id,
                "event": "screening_run",
                "run_id": run.run_id,
                "open_hits": len(open_hits),
            },
        )
        return run

    def _match_subject_entry(
        self,
        run: ScreeningRun,
        subject: ScreeningSubject,
        snapshot: ListSnapshot,
        entry: ListEntry,
    ) -> ScreeningHit | None:
        matched = _best_name_match(subject, entry)
        if matched is None:
            return None
        score, basis = matched
        subject_ids = {normalise_identifier(i) for i in subject.identifiers}
        entry_ids = {normalise_identifier(i) for i in entry.identifiers}
        identifier_match = bool(subject_ids & entry_ids)
        dob_match = (
            subject.dob is not None and entry.dob is not None and subject.dob == entry.dob
        )
        dob_mismatch = (
            subject.dob is not None and entry.dob is not None and subject.dob != entry.dob
        )
        status = HitStatus.OPEN
        cleared_reason: str | None = None
        if identifier_match:
            basis += "; identifier_match"
            strength = "strong"
            if dob_mismatch:
                basis += "; dob_conflict (identifier prevails, analyst to review)"
        elif dob_mismatch:
            # The namesake trap: same name, different person. Recorded
            # as a cleared hit with the reason — never silently dropped,
            # never allowed to block the case.
            status = HitStatus.CLEARED
            cleared_reason = "date_of_birth_mismatch"
            basis += "; dob_mismatch_auto_cleared"
            strength = "potential"
        elif dob_match:
            basis += "; dob_match"
            strength = "strong"
        else:
            strength = "potential"
        return ScreeningHit(
            case_id=run.case_id,
            run_id=run.run_id,
            subject_ref=subject.subject_ref,
            subject_name=subject.name,
            subject_role=subject.role,
            list_kind=snapshot.list_kind,
            snapshot_id=snapshot.snapshot_id,
            snapshot_version=snapshot.version,
            entry_id=entry.entry_id,
            entry_name=entry.name,
            score=score,
            basis=basis,
            strength=strength,
            status=status,
            cleared_reason=cleared_reason,
        )

    # -- hit disposition ----------------------------------------------------

    def set_hit_status(
        self,
        hit_id: str,
        status: HitStatus,
        *,
        actor: str,
        reason: str,
    ) -> ScreeningHit:
        """An analyst clears or confirms a hit, with a reason.

        Clearing is the only way an open sanctions hit stops blocking
        a plain close; the reason stays on the hit and in the audit
        log. A hit already in the requested status is returned as-is.
        """
        if status is HitStatus.OPEN:
            raise ScreeningError("a hit cannot be moved back to open")
        if not reason or not reason.strip():
            raise ScreeningError("clearing or confirming a hit requires a reason")
        hit = self._screening.get_hit(hit_id)
        if hit is None:
            raise HitNotFoundError(hit_id)
        ensure_case_mutable(self._seals, hit.case_id)
        if hit.status is status:
            return hit
        hit = hit.model_copy(
            update={
                "status": status,
                "status_actor": actor,
                "status_reason": reason,
                "cleared_reason": reason if status is HitStatus.CLEARED else hit.cleared_reason,
            }
        )
        self._screening.update_hit(hit)
        case = self._store.get_case(hit.case_id)
        if case is not None:
            self._refresh_flags(case)
            case.updated_at = datetime.now(timezone.utc)
            self._store.update_case(case)
        self._store.append_audit(
            AuditEvent(
                case_id=hit.case_id,
                actor=actor,
                event=(
                    "screening_hit_cleared"
                    if status is HitStatus.CLEARED
                    else "screening_hit_confirmed"
                ),
                detail={
                    "hit_id": hit.hit_id,
                    "list_kind": hit.list_kind.value,
                    "entry_id": hit.entry_id,
                    "snapshot_version": hit.snapshot_version,
                    "reason": reason,
                },
            )
        )
        return hit

    # -- case flag bookkeeping ----------------------------------------------

    def _compute_stale(self, case: Case) -> bool:
        """Stale iff some list this case was screened against now has
        a newer-published snapshot ingested than the pinned one."""
        for screened in case.screened_against:
            snapshots = self._screening.list_snapshots(screened.list_kind)
            for snapshot in snapshots:
                if snapshot.snapshot_id == screened.snapshot_id:
                    continue
                pinned = self._screening.get_snapshot(
                    screened.list_kind, screened.version
                )
                if pinned is not None and snapshot.published_at > pinned.published_at:
                    return True
        return False

    def _refresh_flags(self, case: Case) -> None:
        """Rebuild the screening-owned flags on the case record from
        the authoritative hit/staleness state."""
        flags = [f for f in case.flags if f not in (FLAG_STALE_SCREENING, FLAG_SANCTIONS_HIT)]
        if case.screening_stale:
            flags.append(FLAG_STALE_SCREENING)
        unresolved_sanctions = any(
            h.list_kind is ListKind.SANCTIONS and h.status is not HitStatus.CLEARED
            for h in self._screening.list_hits(case.case_id)
        )
        if unresolved_sanctions:
            flags.append(FLAG_SANCTIONS_HIT)
        case.flags = flags

    def unresolved_sanctions_hits(self, case_id: str) -> list[ScreeningHit]:
        return [
            h
            for h in self._screening.list_hits(case_id)
            if h.list_kind is ListKind.SANCTIONS and h.status is not HitStatus.CLEARED
        ]
