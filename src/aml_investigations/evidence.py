"""The evidence store service: immutable items, hash-chained per case.

Law 5: once an item enters the evidence store it cannot be edited;
corrections are new items. Each item's ``chain_hash`` binds it to the
case's previous item, so a missing, reordered, or altered item breaks
verification:

    content_sha256 = sha256(content)
    chain_hash     = sha256(prev_chain_hash | content_sha256 |
                            case_id | seq | kind)

with the literal string ``GENESIS`` as the first item's prev hash.
``verify_chain`` recomputes every link from the stored blobs, so it
detects both metadata tampering and blob tampering.
"""

from __future__ import annotations

import hashlib

from .errors import CaseNotFoundError, EvidenceChainError
from .logging_config import get_logger
from .models import AuditEvent, EvidenceItem
from .ports import CaseStore, ObjectStore

logger = get_logger(__name__)

GENESIS = "GENESIS"


def content_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def chain_hash(
    prev_hash: str | None,
    item_content_hash: str,
    case_id: str,
    seq: int,
    kind: str,
) -> str:
    material = "|".join(
        [prev_hash or GENESIS, item_content_hash, case_id, str(seq), kind]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def object_key_for(case_id: str, seq: int, item_content_hash: str) -> str:
    return f"cases/{case_id}/evidence/{seq:04d}-{item_content_hash[:16]}.bin"


class EvidenceService:
    def __init__(self, store: CaseStore, objects: ObjectStore) -> None:
        self._store = store
        self._objects = objects

    def add_item(
        self,
        case_id: str,
        *,
        kind: str,
        content: bytes,
        source_ref: str,
        captured_by: str,
        media_type: str = "application/json",
        legal_hold: bool = False,
    ) -> EvidenceItem:
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        existing = self._store.list_evidence(case_id)
        seq = len(existing) + 1
        prev_hash = existing[-1].chain_hash if existing else None
        digest = content_hash(content)
        link = chain_hash(prev_hash, digest, case_id, seq, kind)
        key = object_key_for(case_id, seq, digest)
        self._objects.put(key, content, media_type)
        item = EvidenceItem(
            case_id=case_id,
            seq=seq,
            kind=kind,
            media_type=media_type,
            source_ref=source_ref,
            captured_by=captured_by,
            object_key=key,
            content_sha256=digest,
            prev_hash=prev_hash,
            chain_hash=link,
            legal_hold=legal_hold,
        )
        self._store.add_evidence_item(item)
        case.evidence_head_hash = link
        from datetime import datetime, timezone

        case.updated_at = datetime.now(timezone.utc)
        self._store.update_case(case)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=captured_by,
                event="evidence_added",
                detail={
                    "seq": seq,
                    "kind": kind,
                    "content_sha256": digest,
                    "chain_hash": link,
                    "source_ref": source_ref,
                },
            )
        )
        logger.info(
            "evidence added",
            extra={"case_id": case_id, "event": "evidence_added"},
        )
        return item

    def list_items(self, case_id: str) -> list[EvidenceItem]:
        if self._store.get_case(case_id) is None:
            raise CaseNotFoundError(case_id)
        return self._store.list_evidence(case_id)

    def read_item_content(self, case_id: str, seq: int) -> bytes:
        item = self._store.get_evidence_item(case_id, seq)
        if item is None:
            from .errors import EvidenceNotFoundError

            raise EvidenceNotFoundError(f"{case_id}#{seq}")
        return self._objects.get(item.object_key)

    def verify_chain(self, case_id: str) -> bool:
        """Recompute every link from the stored blobs. True iff intact."""
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        items = self._store.list_evidence(case_id)
        prev_hash: str | None = None
        for position, item in enumerate(items, start=1):
            if item.seq != position:
                raise EvidenceChainError(
                    f"sequence gap at position {position}: found seq {item.seq}"
                )
            if item.prev_hash != prev_hash:
                raise EvidenceChainError(f"prev_hash mismatch at seq {item.seq}")
            try:
                blob = self._objects.get(item.object_key)
            except Exception as exc:  # missing blob = broken chain of custody
                raise EvidenceChainError(
                    f"blob missing at seq {item.seq}: {item.object_key}"
                ) from exc
            digest = content_hash(blob)
            if digest != item.content_sha256:
                raise EvidenceChainError(f"content hash mismatch at seq {item.seq}")
            link = chain_hash(prev_hash, digest, case_id, item.seq, item.kind)
            if link != item.chain_hash:
                raise EvidenceChainError(f"chain hash mismatch at seq {item.seq}")
            prev_hash = item.chain_hash
        if case.evidence_head_hash != prev_hash:
            raise EvidenceChainError("case head hash does not match the chain")
        return True
