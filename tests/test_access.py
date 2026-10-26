"""Access control (R18): the role policy as data, assignment
scoping, existence-hiding refusals, the read-only auditor, and
the denial record — graded at the access module, the one check
point the API and the CLI both enforce through."""

from __future__ import annotations

import pytest

from aml_investigations.access import (
    ACCESS_POLICY_VERSION,
    AccessService,
    CallerIdentity,
    access_policy_document,
    identity_for_actor,
)
from aml_investigations.errors import (
    AccessDeniedError,
    CaseNotFoundError,
    CustomerNotFoundError,
)

OFFICER = CallerIdentity(person_id="o.reyes", role="bsa_officer")
REVIEWER = CallerIdentity(person_id="r.okafor", role="l2_reviewer")
AUDITOR = CallerIdentity(person_id="a.auditor", role="auditor_readonly")
RIVERA = CallerIdentity(person_id="a.rivera", role="l1_analyst")
CHEN = CallerIdentity(person_id="b.chen", role="l1_analyst")
SYSTEM = CallerIdentity(person_id="system", role="system")


def _case(services, alert_id="ALRT-T-001"):
    return services.intake.open_case(alert_id, actor="intake-service")


class _Seal:
    evidence_seq = 1


class _SealedStub:
    """A seal store that reports the case sealed — the policy's
    sealed-custody rule is graded here; the sealing machinery
    itself is graded by the R7 tests."""

    def list_seals(self, case_id):
        return [_Seal()]

    def list_unseals(self, case_id):
        return []


# -- identity resolution -------------------------------------------------


def test_identity_resolution():
    assert identity_for_actor(None, None) is None
    assert identity_for_actor("", None) is None
    assert identity_for_actor("screening-service").role == "system"
    assert identity_for_actor("system").role == "system"
    assert identity_for_actor("j.rivera").role == "l1_analyst"
    assert identity_for_actor("j.rivera", "analyst").role == "l1_analyst"
    assert (
        identity_for_actor("j.rivera", "senior_analyst").role
        == "l1_analyst"
    )
    assert (
        identity_for_actor("j.rivera", "l2_reviewer").role
        == "l2_reviewer"
    )
    assert (
        identity_for_actor("o.reyes", "bsa_officer").role == "bsa_officer"
    )
    assert (
        identity_for_actor("a.aud", "auditor_readonly").role
        == "auditor_readonly"
    )
    # The gates' refused decider names are nobody, not the system.
    assert identity_for_actor("anonymous").role == "l1_analyst"
    assert identity_for_actor("unknown").role == "l1_analyst"


def test_policy_document_is_the_shipped_policy():
    doc = access_policy_document()
    assert doc["version"] == ACCESS_POLICY_VERSION
    assert doc["roles"]["auditor_readonly"]["writes"] is False
    assert "export" not in doc["roles"]["l2_reviewer"]["case_families"]
    assert "export" in doc["roles"]["bsa_officer"]["case_families"]
    assert "reports" in doc["roles"]["bsa_officer"]["portfolio_families"]
    assert "reports" not in doc["roles"]["l1_analyst"]["portfolio_families"]


# -- assignment ----------------------------------------------------------


def test_assignment_is_a_recorded_act(services):
    case = _case(services)
    updated, seq = services.access.assign_case(
        case.case_id, assignee_id="a.rivera", actor=OFFICER
    )
    assert updated.assigned_analyst == "a.rivera"
    assert seq is not None
    items = services.evidence.list_items(case.case_id)
    assignment_items = [
        i for i in items if i.kind == "case_assignment"
    ]
    assert len(assignment_items) == 1
    audit = services.store.list_audit(case.case_id)
    assert any(e.event == "case_assigned" for e in audit)
    # And it takes effect immediately.
    assert services.access.in_scope(RIVERA, updated)
    assert not services.access.in_scope(CHEN, updated)


def test_l1_claims_unassigned_for_self_only(services):
    case = _case(services)
    updated, _ = services.access.assign_case(
        case.case_id, assignee_id="a.rivera", actor=RIVERA
    )
    assert updated.assigned_analyst == "a.rivera"

    other = _case(services, "ALRT-T-002")
    with pytest.raises(AccessDeniedError) as refused:
        services.access.assign_case(
            other.case_id, assignee_id="b.chen", actor=RIVERA
        )
    assert refused.value.code == "role_not_permitted"
    with pytest.raises(AccessDeniedError) as refused:
        services.access.assign_case(
            case.case_id, assignee_id="b.chen", actor=CHEN
        )
    assert refused.value.code == "not_assignee"


def test_reassignment_takes_effect_immediately(services):
    case = _case(services)
    services.access.assign_case(
        case.case_id, assignee_id="a.rivera", actor=OFFICER
    )
    services.access.assign_case(
        case.case_id, assignee_id="b.chen", actor=OFFICER
    )
    current = services.store.get_case(case.case_id)
    assert services.access.in_scope(CHEN, current)
    assert not services.access.in_scope(RIVERA, current)
    items = [
        i
        for i in services.evidence.list_items(case.case_id)
        if i.kind == "case_assignment"
    ]
    assert len(items) == 2


def test_auditor_assigns_nothing(services):
    case = _case(services)
    with pytest.raises(AccessDeniedError) as refused:
        services.access.assign_case(
            case.case_id, assignee_id="a.rivera", actor=AUDITOR
        )
    assert refused.value.code == "readonly_role"


# -- reads: scope and existence ------------------------------------------


def test_out_of_scope_read_is_the_not_found_shape_and_recorded(services):
    case = _case(services)
    services.access.assign_case(
        case.case_id, assignee_id="a.rivera", actor=OFFICER
    )
    with pytest.raises(CaseNotFoundError):
        services.access.check_read(CHEN, case.case_id, "evidence")
    with pytest.raises(CaseNotFoundError):
        services.access.check_read(None, case.case_id, "case")
    denials = services.access.denials()
    assert len(denials) == 2
    by_family = {d.detail["family"]: d.detail["code"] for d in denials}
    # Another analyst's case: not_assignee. No identity at all:
    # role_not_permitted. Both recorded, both hidden the same way.
    assert by_family == {
        "evidence": "not_assignee",
        "case": "role_not_permitted",
    }
    assert denials[0].detail["policy_version"] == ACCESS_POLICY_VERSION


def test_book_roles_read_across_and_unassigned_is_open(services):
    case = _case(services)
    # Unassigned: any analyst may read (the pick-up queue).
    services.access.check_read(CHEN, case.case_id, "evidence")
    services.access.assign_case(
        case.case_id, assignee_id="a.rivera", actor=OFFICER
    )
    for reader in (REVIEWER, OFFICER, AUDITOR, SYSTEM, RIVERA):
        services.access.check_read(reader, case.case_id, "evidence")
    listed = services.access.filter_cases(
        CHEN, services.store.list_cases()
    )
    assert listed == []


def test_export_family_is_officer_only(services):
    case = _case(services)
    services.access.check_read(OFFICER, case.case_id, "export")
    for reader in (REVIEWER, RIVERA, AUDITOR):
        with pytest.raises(AccessDeniedError) as refused:
            services.access.check_read(reader, case.case_id, "export")
        assert refused.value.code == "role_not_permitted"
        assert refused.value.family == "export"


def test_sealed_custody_families_close_to_analysts(services):
    case = _case(services)
    sealed_access = AccessService(
        services.store,
        evidence=services.evidence,
        seal_store=_SealedStub(),
    )
    for family in ("evidence", "narratives", "records"):
        with pytest.raises(AccessDeniedError) as refused:
            sealed_access.check_read(RIVERA, case.case_id, family)
        assert refused.value.code == "role_not_permitted"
    # The seal view itself stays readable; officer/auditor keep
    # the custody families.
    sealed_access.check_read(RIVERA, case.case_id, "custody")
    sealed_access.check_read(OFFICER, case.case_id, "evidence")
    sealed_access.check_read(AUDITOR, case.case_id, "narratives")


# -- writes: the read-only role and decision scoping ----------------------


def test_auditor_writes_nothing_anywhere(services):
    case = _case(services)
    for family in ("case", "evidence", "dispositions", "custody"):
        with pytest.raises(AccessDeniedError) as refused:
            services.access.check_write(AUDITOR, case.case_id, family)
        assert refused.value.code == "readonly_role"
    with pytest.raises(AccessDeniedError) as refused:
        services.access.check_door_write(AUDITOR, "intake")
    assert refused.value.code == "readonly_role"


def test_decision_writes_are_assignment_scoped(services):
    case = _case(services)
    services.access.assign_case(
        case.case_id, assignee_id="a.rivera", actor=OFFICER
    )
    with pytest.raises(AccessDeniedError) as refused:
        services.access.check_write(CHEN, case.case_id, "dispositions")
    assert refused.value.code == "not_assignee"
    # Operational writes are not assignment-scoped.
    services.access.check_write(CHEN, case.case_id, "transactions")
    # The assignee and the book roles decide.
    services.access.check_write(RIVERA, case.case_id, "dispositions")
    services.access.check_write(REVIEWER, case.case_id, "dispositions")


def test_derivations_run_as_system_not_as_an_analyst(services):
    case = _case(services)
    services.access.assign_case(
        case.case_id, assignee_id="a.rivera", actor=OFFICER
    )
    # A header-less derivation trigger resolves to nobody — and
    # passes: the derivation runs under system scope, stated.
    services.access.check_write(
        None, case.case_id, "clocks", derivation=True
    )
    # The same non-identity cannot perform an analyst act.
    with pytest.raises(AccessDeniedError):
        services.access.check_write(None, case.case_id, "dispositions")


# -- portfolio + customers -------------------------------------------------


def test_portfolio_doors(services):
    services.access.check_portfolio(OFFICER, "reports")
    services.access.check_portfolio(AUDITOR, "reports")
    services.access.check_portfolio(REVIEWER, "confirmation_queue")
    for identity, family in (
        (RIVERA, "reports"),
        (RIVERA, "confirmation_queue"),
        (REVIEWER, "reports"),
        (None, "reports"),
    ):
        with pytest.raises(AccessDeniedError) as refused:
            services.access.check_portfolio(identity, family)
        assert refused.value.code == "role_not_permitted"


def test_customer_reads_follow_case_access(services):
    case = _case(services)
    services.access.assign_case(
        case.case_id, assignee_id="a.rivera", actor=OFFICER
    )
    visible = services.access.check_customer_read(RIVERA, case.customer_id)
    assert [c.case_id for c in visible] == [case.case_id]
    with pytest.raises(CustomerNotFoundError):
        services.access.check_customer_read(CHEN, case.customer_id)
    with pytest.raises(CustomerNotFoundError):
        services.access.check_customer_read(OFFICER, "CUST-NOPE")
    denials = services.access.denials()
    assert any(
        d.detail.get("customer_id") == case.customer_id for d in denials
    )
