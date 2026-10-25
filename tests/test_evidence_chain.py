"""Law 5: evidence immutability and the per-case hash chain."""

from __future__ import annotations

import pytest

from aml_investigations.errors import CaseNotFoundError, EvidenceChainError


def _open_with_items(services, count: int = 3) -> str:
    case_id = services.intake.open_case("ALRT-T-001").case_id
    for i in range(count):
        services.evidence.add_item(
            case_id,
            kind=f"item-{i}",
            content=f"content-{i}".encode(),
            source_ref=f"test:{i}",
            captured_by="evidence-service",
        )
    return case_id


def test_chain_links_and_head(services):
    case_id = _open_with_items(services, 3)
    items = services.evidence.list_items(case_id)
    # seq 1 is the alert payload captured at intake.
    assert [i.seq for i in items] == [1, 2, 3, 4]
    assert items[0].prev_hash is None
    for prev, cur in zip(items, items[1:]):
        assert cur.prev_hash == prev.chain_hash
    case = services.store.get_case(case_id)
    assert case.evidence_head_hash == items[-1].chain_hash
    assert services.evidence.verify_chain(case_id) is True


def test_verify_detects_blob_tampering(services, tmp_path):
    case_id = _open_with_items(services, 2)
    item = services.evidence.list_items(case_id)[-1]
    blob_path = tmp_path / "objects" / item.object_key
    blob_path.write_bytes(b"forged content")
    with pytest.raises(EvidenceChainError):
        services.evidence.verify_chain(case_id)


def test_verify_detects_metadata_tampering(services):
    case_id = _open_with_items(services, 2)
    items = services.store.list_evidence(case_id)
    forged = items[1].model_copy(update={"content_sha256": "0" * 64})
    # Rewrite the stored record directly, as an attacker with DB
    # access might; verification must still fail.
    stored = services.store._evidence[case_id]  # in-memory double internals
    stored[1] = forged
    with pytest.raises(EvidenceChainError):
        services.evidence.verify_chain(case_id)


def test_verify_detects_missing_blob(services, tmp_path):
    case_id = _open_with_items(services, 1)
    item = services.evidence.list_items(case_id)[0]
    (tmp_path / "objects" / item.object_key).unlink()
    with pytest.raises(EvidenceChainError):
        services.evidence.verify_chain(case_id)


def test_chains_are_per_case(services):
    first = services.intake.open_case("ALRT-T-001").case_id
    second = services.intake.open_case("ALRT-T-002").case_id
    services.evidence.add_item(
        first, kind="k", content=b"a", source_ref="t:1", captured_by="svc"
    )
    assert services.evidence.verify_chain(first) is True
    assert services.evidence.verify_chain(second) is True
    assert (
        services.store.get_case(first).evidence_head_hash
        != services.store.get_case(second).evidence_head_hash
    )


def test_evidence_port_has_no_mutation_verbs(services):
    """Immutability by construction: the services expose no edit/delete."""
    assert not hasattr(services.evidence, "update_item")
    assert not hasattr(services.evidence, "delete_item")
    assert not hasattr(services.objects, "delete")
    assert not hasattr(services.objects, "update")


def test_add_item_to_unknown_case_is_refused(services):
    with pytest.raises(CaseNotFoundError):
        services.evidence.add_item(
            "case-missing",
            kind="k",
            content=b"x",
            source_ref="t:0",
            captured_by="svc",
        )


def test_evidence_add_is_audited(services):
    case_id = _open_with_items(services, 1)
    events = [e.event for e in services.store.list_audit(case_id)]
    assert events.count("evidence_added") == 2  # alert payload + one item
