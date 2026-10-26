"""Access control (R18): role-scoped case access + retrieval ACLs.

Until R17, identity bound only the *writes*: the gates require a
named analyst with a coded role before a disposition, a
confirmation, an approval, or a seal can be recorded. Reads were
open to whoever could reach the API. This round extends the same
identity discipline to reads, behind ONE access-check module that
the API layer and the CLI both call — there is no second door.

The caller asserts an identity (the deployment's gateway asserts
it in production; the console sends it from its identity fields;
the CLI takes it as ``--caller``/``--role``). A caller identity is
a person id plus a role from the access vocabulary:

- ``l1_analyst`` — the first line. Sees the work they can lawfully
  touch: cases assigned to them, plus unassigned cases (the pickup
  queue). Never another analyst's case.
- ``l2_reviewer`` — the second line. Reads across the book and
  holds the confirmation / escalation queues; confirms and
  approves under the gates' own rules.
- ``bsa_officer`` — reads across the book and additionally holds
  the portfolio doors: management reports, the model-spend
  rollup, case-file export, the denials list.
- ``auditor_readonly`` — reads everything, including the sealed
  book and the denials list, and writes NOTHING. Read-only is a
  hard property of the role: the access check refuses an
  auditor's write before any gate logic runs.
- ``system`` — the deployment's own services (intake, screening,
  the clock scheduler, internal derivations). System scope is how
  service-to-service work is authorised; it is never a way for a
  person to widen their own access, and the reporting/clock
  derivations inside the service layer run under it by
  construction.

The policy itself is data (below): per role, a scope
(``assigned`` or ``book``), the artefact families they may read,
and the state rule. Artefact families are the units a case file
is read in — evidence, records, narratives, profiles, media,
ledger, and the rest. One state rule has teeth: once a case is
SEALED, its evidence / narratives / records families move into
custody — the first and second line no longer read them; the
officer, the auditor, and the system do. The seal view itself
stays readable, so an analyst can still see that the file is
sealed, by whom, and when.

Refusal discipline:

- A case read by a caller with no right on that case raises
  :class:`CaseNotFoundError` — byte-identical in shape to the
  read of a case that does not exist. Existence is not leaked.
- A refusal the caller is entitled to see (a family their role
  excludes on a case in their scope, a portfolio door their role
  does not hold, a write they may not make) raises
  :class:`AccessDeniedError`, HTTP 403, carrying a coded reason:
  ``role_not_permitted`` / ``not_assignee`` / ``readonly_role``.
- EVERY refusal of an existing resource is recorded first, as an
  ``access_denied`` audit event naming the caller, the case or
  door, the family, and the code. An officer or an auditor can
  list the denials.

Writes keep every gate check they already had — access control
is additive, never a replacement. The access layer adds two
things to writes: the read-only role's hard refusal, and
assignment scoping on the *decision* families (dispositions,
approvals, custody, review decisions, assignment itself): an
L1 analyst's decision on a case assigned to another analyst is
refused ``not_assignee`` before the gate runs. Operational
assembly writes (evidence capture, screening runs, drafting) are
shared work in a bank — any identified, non-read-only caller may
perform them; the gates and the sealed-case rule still bind.

Two derivation doors (clock refresh, narrative re-verification)
carry no actor of their own: they are the scheduler's and the
verifier's recomputations. Called with no caller identity, they
run under system scope — stated here, in the policy, rather than
discovered later. Called WITH an identity, that identity is
scope-checked like any other.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from .dispositions import canonical_person_id
from .errors import (
    AccessDeniedError,
    CaseNotFoundError,
    CustomerNotFoundError,
)
from .evidence import EvidenceService, case_is_sealed, ensure_case_mutable
from .models import AuditEvent, Case
from .ports import CaseStore, SealStore

#: The access policy's version. A case file (and a denial) can
#: always answer "under which policy version was this judged".
ACCESS_POLICY_VERSION = "2026.10.1"

ROLE_L1 = "l1_analyst"
ROLE_L2 = "l2_reviewer"
ROLE_OFFICER = "bsa_officer"
ROLE_AUDITOR = "auditor_readonly"
ROLE_SYSTEM = "system"

ACCESS_ROLES = frozenset(
    {ROLE_L1, ROLE_L2, ROLE_OFFICER, ROLE_AUDITOR, ROLE_SYSTEM}
)

#: The identity headers the API resolves a caller from (the CLI
#: takes the same pair as --caller/--role). The deployment's
#: gateway asserts them; the console sends them.
CALLER_ID_HEADER = "x-caller-id"
CALLER_ROLE_HEADER = "x-caller-role"

#: The gate vocabularies (analyst roles at the disposition /
#: approval gates, officer roles at the custody gate) name the
#: same people in the gates' own words. The access layer reads
#: both vocabularies and maps them onto its own — one person,
#: one access role, whichever door they arrived at.
ROLE_MAP = {
    "analyst": ROLE_L1,
    "senior_analyst": ROLE_L1,
    "l2_reviewer": ROLE_L2,
    "bsa_officer": ROLE_OFFICER,
    "auditor_readonly": ROLE_AUDITOR,
    "auditor": ROLE_AUDITOR,
    "system": ROLE_SYSTEM,
    ROLE_L1: ROLE_L1,
    ROLE_L2: ROLE_L2,
    ROLE_OFFICER: ROLE_OFFICER,
    ROLE_AUDITOR: ROLE_AUDITOR,
    ROLE_SYSTEM: ROLE_SYSTEM,
}

#: Every artefact family a case file is read or written in.
CASE_FAMILIES = frozenset(
    {
        "case",
        "evidence",
        "screening",
        "transactions",
        "typologies",
        "records",
        "dispositions",
        "narratives",
        "approvals",
        "custody",
        "export",
        "clocks",
        "reviews",
        "quarantine",
        "media",
        "ledger",
        "audit",
        "profiles",
        "assignment",
    }
)

#: Portfolio families: no single case behind them.
PORTFOLIO_FAMILIES = frozenset(
    {
        "reports",
        "daily_costs",
        "shared_counterparties",
        "denials",
        "confirmation_queue",
        "escalation_queue",
    }
)

#: Families that move into custody when a case is sealed: after
#: sealing, the first and second line no longer read them.
SEALED_CUSTODY_FAMILIES = frozenset({"evidence", "narratives", "records"})

#: The decision families: acts that decide a case. Assignment
#: scoping binds here for L1 callers.
DECISION_FAMILIES = frozenset(
    {"dispositions", "approvals", "custody", "reviews", "assignment"}
)

_L1_READ = CASE_FAMILIES - {"export"}
_L2_READ = _L1_READ | {"confirmation_queue", "escalation_queue"}
#: The officer's book: everything, including the export family.
_BOOK_READ = CASE_FAMILIES | PORTFOLIO_FAMILIES
#: The auditor's and the system's book: everything except the
#: export family — packages leave only in a BSA officer's
#: hands; the auditor verifies them offline.
_NON_EXPORT_BOOK_READ = (CASE_FAMILIES - {"export"}) | PORTFOLIO_FAMILIES

#: The policy, as data. ``scope`` is "assigned" (own cases +
#: the unassigned pickup queue) or "book" (every case).
#: ``sealed_custody`` marks the roles whose evidence/narrative/
#: record reads end when a case is sealed.
ROLE_POLICY: dict[str, dict] = {
    ROLE_L1: {
        "scope": "assigned",
        "read_families": _L1_READ,
        "sealed_custody": True,
    },
    ROLE_L2: {
        "scope": "book",
        "read_families": _L2_READ,
        "sealed_custody": True,
    },
    ROLE_OFFICER: {
        "scope": "book",
        "read_families": _BOOK_READ,
        "sealed_custody": False,
    },
    ROLE_AUDITOR: {
        "scope": "book",
        "read_families": _NON_EXPORT_BOOK_READ,
        "sealed_custody": False,
    },
    ROLE_SYSTEM: {
        "scope": "book",
        "read_families": _NON_EXPORT_BOOK_READ,
        "sealed_custody": False,
    },
}

#: Portfolio doors and the roles that hold them (reads).
PORTFOLIO_READ_ROLES: dict[str, frozenset[str]] = {
    "reports": frozenset({ROLE_OFFICER, ROLE_AUDITOR, ROLE_SYSTEM}),
    "daily_costs": frozenset({ROLE_OFFICER, ROLE_AUDITOR, ROLE_SYSTEM}),
    "denials": frozenset({ROLE_OFFICER, ROLE_AUDITOR, ROLE_SYSTEM}),
    "shared_counterparties": frozenset(
        {ROLE_L2, ROLE_OFFICER, ROLE_AUDITOR, ROLE_SYSTEM}
    ),
    "confirmation_queue": frozenset(
        {ROLE_L2, ROLE_OFFICER, ROLE_AUDITOR, ROLE_SYSTEM}
    ),
    "escalation_queue": frozenset(
        {ROLE_L2, ROLE_OFFICER, ROLE_AUDITOR, ROLE_SYSTEM}
    ),
}

#: Write doors that are not case families: who may use them.
DOOR_WRITE_ROLES: dict[str, frozenset[str]] = {
    # Case creation belongs to the monitoring system's door
    # (and an officer administering it) — not to an analyst.
    "intake": frozenset({ROLE_SYSTEM, ROLE_OFFICER}),
    # Governed reference data (list snapshots, rule packs) is
    # ingested by the feeds, or by an officer administering them.
    "reference_data": frozenset({ROLE_SYSTEM, ROLE_OFFICER}),
    # The continuing-review scheduler tick.
    "review_tick": frozenset({ROLE_SYSTEM, ROLE_OFFICER}),
}


class CallerIdentity(BaseModel):
    """One caller's asserted identity: a person id (or a service
    name, for system callers) and their access role."""

    person_id: str = Field(description="As presented; recorded verbatim.")
    role: str = Field(description="An access-vocabulary role.")

    @property
    def canonical_id(self) -> str:
        return canonical_person_id(self.person_id)

    @property
    def is_system(self) -> bool:
        return self.role == ROLE_SYSTEM


#: Actor names that are the deployment itself. Deliberately NOT
#: the gates' SYSTEM_ACTORS set: that set also names the strings
#: the gates refuse as deciders ("anonymous", "unknown", "none")
#: — a caller presenting one of those is nobody, not the system.
SERVICE_ACTORS = frozenset({"system", "aml-agent"})


def access_policy_document() -> dict:
    """The policy as data, for the CLI and for examiners: every
    role's scope, its readable families, and the portfolio
    doors. Nothing here is computed at call time — it is the
    shipped policy, rendered."""
    return {
        "version": ACCESS_POLICY_VERSION,
        "roles": {
            role: {
                "scope": policy["scope"],
                "case_families": sorted(policy["read_families"]),
                "portfolio_families": sorted(
                    fam
                    for fam, readers in PORTFOLIO_READ_ROLES.items()
                    if role in readers
                ),
                "sealed_custody_restricted": bool(
                    policy["sealed_custody"]
                ),
                "writes": role != ROLE_AUDITOR,
            }
            for role, policy in ROLE_POLICY.items()
        },
        "door_writes": {
            door: sorted(roles) for door, roles in DOOR_WRITE_ROLES.items()
        },
        "notes": [
            "an l1_analyst reads cases assigned to them and "
            "unassigned queue cases, never another analyst's case",
            "auditor_readonly writes nothing — every write is "
            "refused readonly_role before gate logic runs",
            "export packages are granted to bsa_officer alone",
            "a caller with no read right on a case receives the "
            "same not-found shape as a case that does not exist",
        ],
    }


def identity_for_actor(
    actor: str | None, role: str | None = None
) -> CallerIdentity | None:
    """Resolve a caller identity from an actor string and an
    optional role hint (either vocabulary).

    Service actors (``system``, ``aml-agent``, anything named
    ``*-service``) resolve to the system role — they are the
    deployment itself. A named person with a role hint takes the
    hint's mapped access role; a named person with no hint is an
    L1 analyst, the least-privilege human scope. No actor and no
    usable role: no identity (``None``)."""
    if actor is None and role is None:
        return None
    actor = actor or ""
    if role:
        mapped = ROLE_MAP.get(" ".join(role.split()).casefold())
        if mapped is not None:
            return CallerIdentity(person_id=actor, role=mapped)
    canonical = canonical_person_id(actor)
    if not canonical:
        return None
    if canonical in SERVICE_ACTORS or canonical.endswith("-service"):
        return CallerIdentity(person_id=actor, role=ROLE_SYSTEM)
    return CallerIdentity(person_id=actor, role=ROLE_L1)


class AccessService:
    """The one access-check module. The API layer and the CLI
    both enforce through it; the service layer below it is
    unchanged (the gates keep their own checks)."""

    def __init__(
        self,
        store: CaseStore,
        evidence: EvidenceService | None = None,
        seal_store: SealStore | None = None,
    ) -> None:
        self._store = store
        self._evidence = evidence
        self._seal_store = seal_store if seal_store is not None else store

    # -- identity ------------------------------------------------

    def header_identity(
        self, person_id: str | None, role: str | None
    ) -> CallerIdentity | None:
        """The identity a request's headers assert, or None when
        the request asserts none."""
        if person_id is None and role is None:
            return None
        return identity_for_actor(person_id or "", role)

    # -- scope ---------------------------------------------------

    def in_scope(self, identity: CallerIdentity | None, case: Case) -> bool:
        """May this caller know this case at all? Book roles:
        every case. L1: their own cases and the unassigned
        pickup queue. Anonymous: nothing."""
        if identity is None:
            return False
        policy = ROLE_POLICY[identity.role]
        if policy["scope"] == "book":
            return True
        if case.assigned_analyst is None:
            return True
        return (
            canonical_person_id(case.assigned_analyst)
            == identity.canonical_id
        )

    def filter_cases(
        self, identity: CallerIdentity | None, cases: list[Case]
    ) -> list[Case]:
        """The caller's view of a case list: out-of-scope cases
        simply do not appear."""
        return [c for c in cases if self.in_scope(identity, c)]

    def filter_case_ids(
        self,
        identity: CallerIdentity | None,
        case_ids: set[str] | None,
    ) -> set[str]:
        """The subset of a set of case ids the caller may see —
        for filtering portfolio queues whose rows name cases.
        ``case_ids=None`` means every case on the book."""
        if identity is None:
            return set()
        if case_ids is None:
            case_ids = {c.case_id for c in self._store.list_cases()}
        if ROLE_POLICY[identity.role]["scope"] == "book":
            return set(case_ids)
        visible = set()
        for case in self._store.list_cases():
            if case.case_id in case_ids and self.in_scope(identity, case):
                visible.add(case.case_id)
        return visible

    # -- denial recording -----------------------------------------

    def _record_denial(
        self,
        identity: CallerIdentity | None,
        *,
        code: str,
        family: str,
        action: str,
        case_id: str | None = None,
        detail: dict | None = None,
    ) -> None:
        record = {
            "code": code,
            "family": family,
            "action": action,
            "policy_version": ACCESS_POLICY_VERSION,
        }
        if detail:
            record.update(detail)
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=(
                    identity.person_id
                    if identity is not None and identity.person_id
                    else "anonymous"
                ),
                event="access_denied",
                detail=record,
            )
        )

    def denials(self) -> list[AuditEvent]:
        """Every recorded access denial, oldest first — the
        auditor's list. Reading it is itself a portfolio door
        (officer / auditor / system)."""
        return [
            e for e in self._store.list_all_audit()
            if e.event == "access_denied"
        ]

    # -- case reads ------------------------------------------------

    def check_read(
        self,
        identity: CallerIdentity | None,
        case_id: str,
        family: str,
    ) -> Case:
        """Authorise one case-scoped read, returning the case.

        Out of scope (or anonymous, or missing) ->
        CaseNotFoundError, the existence-hiding shape. In scope
        but family-restricted -> AccessDeniedError naming the
        family. Both refusals of an existing case are recorded."""
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        if not self.in_scope(identity, case):
            self._record_denial(
                identity,
                code="not_assignee" if identity is not None
                else "role_not_permitted",
                family=family,
                action="read",
                case_id=case_id,
                detail={"role": identity.role if identity else None},
            )
            raise CaseNotFoundError(case_id)
        assert identity is not None  # in_scope(None, ...) is False
        policy = ROLE_POLICY[identity.role]
        if family not in policy["read_families"]:
            self._record_denial(
                identity,
                code="role_not_permitted",
                family=family,
                action="read",
                case_id=case_id,
                detail={"role": identity.role},
            )
            raise AccessDeniedError(
                "role_not_permitted",
                family,
                f"access denied (role_not_permitted): role "
                f"{identity.role!r} may not read family {family!r}",
            )
        if (
            policy["sealed_custody"]
            and family in SEALED_CUSTODY_FAMILIES
            and case_is_sealed(self._seal_store, case_id)
        ):
            self._record_denial(
                identity,
                code="role_not_permitted",
                family=family,
                action="read",
                case_id=case_id,
                detail={"role": identity.role, "state": "sealed"},
            )
            raise AccessDeniedError(
                "role_not_permitted",
                family,
                f"access denied (role_not_permitted): case "
                f"{case_id} is sealed; family {family!r} is read "
                "in custody (bsa_officer / auditor_readonly)",
            )
        return case

    # -- case writes ------------------------------------------------

    def check_write(
        self,
        identity: CallerIdentity | None,
        case_id: str,
        family: str,
        *,
        derivation: bool = False,
    ) -> Case:
        """Authorise one case-scoped write, returning the case.

        The read-only role is refused first, before any scope or
        gate logic. Decision families bind assignment scoping for
        L1 callers (``not_assignee``). ``derivation`` doors (clock
        refresh, narrative re-verification) may be called with no
        identity at all: they are the scheduler's own
        recomputations and run under system scope — with an
        identity presented, that identity is checked normally."""
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        if identity is None:
            if derivation:
                return case
            self._record_denial(
                None,
                code="role_not_permitted",
                family=family,
                action="write",
                case_id=case_id,
            )
            raise AccessDeniedError(
                "role_not_permitted",
                family,
                "access denied (role_not_permitted): a write "
                "requires a named caller identity",
            )
        if identity.role == ROLE_AUDITOR:
            self._record_denial(
                identity,
                code="readonly_role",
                family=family,
                action="write",
                case_id=case_id,
                detail={"role": identity.role},
            )
            raise AccessDeniedError(
                "readonly_role",
                family,
                "access denied (readonly_role): the "
                "auditor_readonly role writes nothing — the "
                "refusal stands before any gate logic",
            )
        if family in DECISION_FAMILIES and not self.in_scope(
            identity, case
        ):
            self._record_denial(
                identity,
                code="not_assignee",
                family=family,
                action="write",
                case_id=case_id,
                detail={
                    "role": identity.role,
                    "assignee": case.assigned_analyst,
                },
            )
            raise AccessDeniedError(
                "not_assignee",
                family,
                f"access denied (not_assignee): case {case_id} "
                f"is assigned to {case.assigned_analyst!r}; "
                f"{identity.person_id!r} may not decide it",
            )
        return case

    # -- portfolio doors ----------------------------------------------

    def check_portfolio(
        self,
        identity: CallerIdentity | None,
        family: str,
    ) -> None:
        """Authorise a portfolio read (reports, denials, queues
        restricted to book roles, the shared-counterparty view,
        the daily model-spend rollup)."""
        roles = PORTFOLIO_READ_ROLES[family]
        if identity is None or identity.role not in roles:
            self._record_denial(
                identity,
                code="role_not_permitted",
                family=family,
                action="read",
                detail={"role": identity.role if identity else None},
            )
            raise AccessDeniedError(
                "role_not_permitted",
                family,
                f"access denied (role_not_permitted): family "
                f"{family!r} is held by "
                f"({', '.join(sorted(roles))})",
            )

    def check_door_write(
        self,
        identity: CallerIdentity | None,
        door: str,
    ) -> None:
        """Authorise a non-case write door (intake, reference
        data, the review tick). The read-only role is refused
        here too, before anything else."""
        if identity is not None and identity.role == ROLE_AUDITOR:
            self._record_denial(
                identity,
                code="readonly_role",
                family=door,
                action="write",
            )
            raise AccessDeniedError(
                "readonly_role",
                door,
                "access denied (readonly_role): the "
                "auditor_readonly role writes nothing",
            )
        roles = DOOR_WRITE_ROLES[door]
        if identity is None or identity.role not in roles:
            self._record_denial(
                identity,
                code="role_not_permitted",
                family=door,
                action="write",
                detail={"role": identity.role if identity else None},
            )
            raise AccessDeniedError(
                "role_not_permitted",
                door,
                f"access denied (role_not_permitted): the "
                f"{door!r} door is held by "
                f"({', '.join(sorted(roles))})",
            )

    # -- customer reads (profiles, counterparties, reviews) ---------

    def customer_cases(self, customer_id: str) -> list[Case]:
        return [
            c for c in self._store.list_cases()
            if c.customer_id == customer_id
        ]

    def check_customer_read(
        self, identity: CallerIdentity | None, customer_id: str
    ) -> list[Case]:
        """A customer's retrieval surface (profile view,
        counterparties, continuing-review history) follows the
        caller's access to the customer's cases: readable iff
        the caller can read at least one of them. A caller who
        can read none gets the unknown-customer shape — the
        customer's existence behind those cases is not leaked."""
        cases = self.customer_cases(customer_id)
        if not cases:
            raise CustomerNotFoundError(
                "no cases on record for the customer"
            )
        visible = [c for c in cases if self.in_scope(identity, c)]
        if not visible:
            self._record_denial(
                identity,
                code="not_assignee" if identity is not None
                else "role_not_permitted",
                family="profiles",
                action="read",
                detail={
                    "customer_id": customer_id,
                    "role": identity.role if identity else None,
                },
            )
            raise CustomerNotFoundError(
                "no cases on record for the customer"
            )
        return visible

    def check_customer_write(
        self, identity: CallerIdentity | None, customer_id: str
    ) -> list[Case]:
        """Assembling a profile is a write over the customer's
        cases: the read-only role is refused, and the caller
        must be able to read at least one of the cases."""
        if identity is not None and identity.role == ROLE_AUDITOR:
            self._record_denial(
                identity,
                code="readonly_role",
                family="profiles",
                action="write",
                detail={"customer_id": customer_id},
            )
            raise AccessDeniedError(
                "readonly_role",
                "profiles",
                "access denied (readonly_role): the "
                "auditor_readonly role writes nothing",
            )
        return self.check_customer_read(identity, customer_id)

    # -- assignment -----------------------------------------------------

    def assign_case(
        self,
        case_id: str,
        *,
        assignee_id: str,
        actor: CallerIdentity,
    ) -> tuple[Case, int | None]:
        """Assign (or reassign) a case — a recorded act.

        Assignment is recorded twice: an audit event and a
        ``case_assignment`` item on the case's evidence chain,
        so the case file itself carries who held it, when, and
        who set it. Who may assign: book roles and the system,
        freely; an L1 analyst may claim an UNASSIGNED case for
        themselves (the pickup act) and nothing more — assigning
        another analyst, or taking a case already held, is
        refused. A sealed case refuses (the chain is closed).
        Returns the updated case and the chain item's seq."""
        case = self._store.get_case(case_id)
        if case is None:
            raise CaseNotFoundError(case_id)
        # R19: the sealed check runs BEFORE the act writes
        # anything. Until this fix, the assignee was written to
        # the case record first and the evidence funnel's sealed
        # backstop refused the chain item afterwards — the act
        # raised, but the assignment had already silently taken
        # effect, with no chain item and no audit event.
        ensure_case_mutable(self._seal_store, case_id)
        if actor.role == ROLE_AUDITOR:
            self._record_denial(
                actor,
                code="readonly_role",
                family="assignment",
                action="write",
                case_id=case_id,
            )
            raise AccessDeniedError(
                "readonly_role",
                "assignment",
                "access denied (readonly_role): the "
                "auditor_readonly role writes nothing",
            )
        if actor.role == ROLE_L1:
            claiming_self = (
                canonical_person_id(assignee_id) == actor.canonical_id
            )
            if not claiming_self:
                self._record_denial(
                    actor,
                    code="role_not_permitted",
                    family="assignment",
                    action="write",
                    case_id=case_id,
                    detail={"assignee": assignee_id},
                )
                raise AccessDeniedError(
                    "role_not_permitted",
                    "assignment",
                    "access denied (role_not_permitted): an "
                    "l1_analyst may only claim a case for "
                    "themselves; assigning another analyst is "
                    "a book-role act",
                )
            if case.assigned_analyst is not None:
                self._record_denial(
                    actor,
                    code="not_assignee",
                    family="assignment",
                    action="write",
                    case_id=case_id,
                    detail={"assignee": case.assigned_analyst},
                )
                raise AccessDeniedError(
                    "not_assignee",
                    "assignment",
                    f"access denied (not_assignee): case "
                    f"{case_id} is already assigned to "
                    f"{case.assigned_analyst!r}",
                )
        previous = case.assigned_analyst
        case.assigned_analyst = assignee_id
        self._store.update_case(case)
        seq: int | None = None
        if self._evidence is not None:
            item = self._evidence.add_item(
                case_id,
                kind="case_assignment",
                content=json.dumps(
                    {
                        "assignee_id": assignee_id,
                        "previous_assignee": previous,
                        "actor": actor.person_id,
                        "actor_role": actor.role,
                        "policy_version": ACCESS_POLICY_VERSION,
                    },
                    sort_keys=True,
                ).encode(),
                source_ref="access-control:assignment",
                captured_by=actor.person_id or "system",
            )
            seq = item.seq
        self._store.append_audit(
            AuditEvent(
                case_id=case_id,
                actor=actor.person_id,
                event="case_assigned",
                detail={
                    "assignee": assignee_id,
                    "previous_assignee": previous,
                    "actor_role": actor.role,
                    "evidence_seq": seq,
                    "policy_version": ACCESS_POLICY_VERSION,
                },
            )
        )
        return case, seq
