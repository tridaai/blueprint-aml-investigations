"""R13 — the model gateway: profiles as data (fail-closed),
real adapters behind the port, and the cost ledger.

The gateway is the one configured path for drafting calls:
profiles resolve from governed data or refuse, live adapters are
real HTTP clients exercised here against stub transports (the
same response shapes the providers send), every call is priced
from the versioned price table into an append-only ledger, and
the per-case budget refuses live calls *before* transport once a
case's spend reaches the cap — with the refusal recorded, and no
profile ever switched silently.
"""

from __future__ import annotations

import copy
import json
from datetime import date, datetime, time, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from aml_investigations.composer import StatementDraft
from aml_investigations.dispositions import DispositionService
from aml_investigations.errors import (
    ComposerRefusalError,
    ModelBudgetExceededError,
    ModelProfileConfigError,
    ModelProfileNotConfiguredError,
    UnknownModelProfileError,
)
from aml_investigations.evidence import EvidenceService
from aml_investigations.gateway import (
    DEFAULT_PRICES_DATA,
    DEFAULT_PROFILES_DATA,
    ModelGateway,
    default_gateway_config,
    load_gateway_config,
    load_gateway_files,
)
from aml_investigations.intake import IntakeService, ListAlertFeed
from aml_investigations.investigation import InvestigationService
from aml_investigations.models import (
    AccountProfile,
    Alert,
    CaseStatus,
    DispositionOutcome,
    ListEntry,
    ListKind,
    ListSnapshot,
    RulePack,
    ScreeningSubject,
    Transaction,
)
from aml_investigations.object_store import LocalObjectStore
from aml_investigations.sar import SarNarrativeService
from aml_investigations.screening import ScreeningService
from aml_investigations.stores import InMemoryCaseStore, SqlCaseStore
from aml_investigations.transactions import ListTransactionFeed
from aml_investigations.typologies import TypologyService
from aml_investigations.workflow import CaseWorkflow

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXED_NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)


def fixed_clock() -> datetime:
    return FIXED_NOW


# ---------------------------------------------------------------------------
# Stub transports: provider-shaped responses, call counting.
# ---------------------------------------------------------------------------


class StubTransport:
    """Returns the prompt's candidate statement, provider-shaped.

    A real model may polish the candidate; this stub returns it
    verbatim, which is the grounded case — the gateway's figure
    gate then has exactly the offline text to verify. ``usage``
    pins the reported token counts; None omits the usage block
    entirely (the estimate-basis path).
    """

    def __init__(self, usage: dict | None, text_override: str | None = None):
        self.calls: list[dict] = []
        self._usage = usage
        self._text_override = text_override

    def post_json(self, url, *, headers, payload, timeout):
        self.calls.append(
            {"url": url, "headers": headers, "payload": payload}
        )
        prompt = payload["messages"][0]["content"]
        candidate = prompt.split("<<<STATEMENT>>>\n", 1)[1].split(
            "\n<<<END>>>", 1
        )[0]
        text = self._text_override if self._text_override else candidate
        if url.endswith("/v1/messages"):
            body: dict = {
                "content": [{"type": "text", "text": text}],
            }
            if self._usage is not None:
                body["usage"] = self._usage
            return body
        body = {"choices": [{"message": {"content": text}}]}
        if self._usage is not None:
            body["usage"] = self._usage
        return body


def gateway(
    store=None,
    *,
    environ=None,
    transport=None,
    config=None,
    evidence=None,
    audit=False,
) -> ModelGateway:
    return ModelGateway(
        config or default_gateway_config(),
        store if store is not None else InMemoryCaseStore(),
        environ=environ if environ is not None else {},
        transport=transport or StubTransport(None),
        clock=fixed_clock,
        audit_store=store if audit else None,
        evidence=evidence,
    )


def draft(template: str = "A total of {total} moved.", total: str = "9500.00"):
    return StatementDraft(
        template=template,
        values={"total": total},
        allowed={Decimal(total)},
    )


# ---------------------------------------------------------------------------
# Configuration: the shipped files and the canonical data agree,
# and the loader refuses every defect.
# ---------------------------------------------------------------------------


def test_shipped_files_match_canonical_data():
    from_files = load_gateway_files(
        REPO_ROOT / "data" / "model_profiles.json",
        REPO_ROOT / "data" / "model_prices.json",
    )
    canonical = default_gateway_config()
    assert from_files.profiles_version == canonical.profiles_version
    assert from_files.case_budget_usd == canonical.case_budget_usd
    assert set(from_files.profiles) == set(canonical.profiles)
    assert from_files.price_table.version == canonical.price_table.version
    assert from_files.price_by_model == canonical.price_by_model
    for profile_id, definition in canonical.profiles.items():
        assert from_files.profiles[profile_id] == definition


def test_loader_refuses_duplicate_profile_id():
    data = copy.deepcopy(DEFAULT_PROFILES_DATA)
    data["profiles"].append(dict(data["profiles"][0]))
    with pytest.raises(ModelProfileConfigError):
        load_gateway_config(data, DEFAULT_PRICES_DATA)


def test_loader_refuses_unpriced_model():
    data = copy.deepcopy(DEFAULT_PROFILES_DATA)
    data["profiles"][1]["model"] = "no-such-model"
    with pytest.raises(ModelProfileConfigError):
        load_gateway_config(data, DEFAULT_PRICES_DATA)


def test_loader_refuses_negative_price():
    prices = copy.deepcopy(DEFAULT_PRICES_DATA)
    prices["entries"][1]["input_per_mtok_usd"] = "-3.00"
    with pytest.raises(ModelProfileConfigError):
        load_gateway_config(DEFAULT_PROFILES_DATA, prices)


def test_loader_refuses_duplicate_price_entry():
    prices = copy.deepcopy(DEFAULT_PRICES_DATA)
    prices["entries"].append(dict(prices["entries"][1]))
    with pytest.raises(ModelProfileConfigError):
        load_gateway_config(DEFAULT_PROFILES_DATA, prices)


def test_loader_refuses_live_profile_without_endpoint():
    data = copy.deepcopy(DEFAULT_PROFILES_DATA)
    data["profiles"][2]["endpoint_env"] = None
    data["profiles"][2]["endpoint_default"] = None
    with pytest.raises(ModelProfileConfigError):
        load_gateway_config(data, DEFAULT_PRICES_DATA)


def test_loader_refuses_key_required_without_key_env():
    data = copy.deepcopy(DEFAULT_PROFILES_DATA)
    data["profiles"][1]["api_key_env"] = None
    with pytest.raises(ModelProfileConfigError):
        load_gateway_config(data, DEFAULT_PRICES_DATA)


def test_loader_refuses_malformed_budget():
    data = copy.deepcopy(DEFAULT_PROFILES_DATA)
    data["case_budget_usd"] = "two-fifty"
    with pytest.raises(ModelProfileConfigError):
        load_gateway_config(data, DEFAULT_PRICES_DATA)


def test_loader_refuses_missing_price_file(tmp_path):
    with pytest.raises(ModelProfileConfigError):
        load_gateway_files(
            tmp_path / "profiles.json", tmp_path / "prices.json"
        )


# ---------------------------------------------------------------------------
# Resolution: fail-closed, never a fallback.
# ---------------------------------------------------------------------------


def test_unknown_profile_refused():
    gw = gateway()
    with pytest.raises(UnknownModelProfileError):
        gw.composer_for("no-such-profile", case_id=None, purpose="sar_draft")


def test_unconfigured_live_profiles_refused():
    gw = gateway(environ={})
    with pytest.raises(ModelProfileNotConfiguredError):
        gw.composer_for(
            "hosted-frontier", case_id=None, purpose="sar_draft"
        )
    # in-boundary has no default endpoint: unconfigured by
    # construction until the deployment names its own server.
    with pytest.raises(ModelProfileNotConfiguredError):
        gw.composer_for("in-boundary", case_id=None, purpose="sar_draft")


def test_active_profile_validated_at_wiring_time():
    with pytest.raises(ModelProfileNotConfiguredError):
        ModelGateway(
            default_gateway_config(),
            InMemoryCaseStore(),
            environ={},
            active_profile="hosted-frontier",
        )
    with pytest.raises(UnknownModelProfileError):
        ModelGateway(
            default_gateway_config(),
            InMemoryCaseStore(),
            environ={},
            active_profile="nope",
        )
    # Configured + named: wires cleanly.
    ModelGateway(
        default_gateway_config(),
        InMemoryCaseStore(),
        environ={"ANTHROPIC_API_KEY": "test-key"},
        active_profile="hosted-frontier",
    )


def test_profile_summaries_never_carry_key_values():
    gw = gateway(environ={"ANTHROPIC_API_KEY": "test-secret-value"})
    summaries = {s["profile_id"]: s for s in gw.profile_summaries()}
    assert summaries["hosted-frontier"]["configured"] is True
    assert summaries["offline"]["configured"] is True
    assert summaries["in-boundary"]["configured"] is False
    assert "test-secret-value" not in json.dumps(summaries)


# ---------------------------------------------------------------------------
# Adapters + pricing: hand-computed fixtures, exact Decimals.
# ---------------------------------------------------------------------------


def test_offline_call_ledgers_at_zero():
    store = InMemoryCaseStore()
    gw = gateway(store)
    composer = gw.composer_for(
        "offline", case_id="CASE-1", purpose="record_draft"
    )
    assert composer.profile_name == "offline"
    assert composer.compose(draft()) == "A total of 9500.00 moved."
    entries = store.list_call_entries("CASE-1")
    assert len(entries) == 1
    entry = entries[0]
    assert entry.profile_id == "offline"
    assert entry.purpose == "record_draft"
    assert entry.tokens_in == 0 and entry.tokens_out == 0
    assert entry.cost_usd == Decimal("0")
    assert entry.price_table_version == "2026.10.1"
    assert entry.called_at == FIXED_NOW


def test_anthropic_call_priced_exactly():
    store = InMemoryCaseStore()
    transport = StubTransport(
        {"input_tokens": 1200, "output_tokens": 300}
    )
    gw = gateway(
        store,
        environ={"ANTHROPIC_API_KEY": "test-key"},
        transport=transport,
    )
    composer = gw.composer_for(
        "hosted-frontier", case_id="CASE-1", purpose="sar_draft"
    )
    text = composer.compose(draft())
    assert text == "A total of 9500.00 moved."
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == "https://api.anthropic.com/v1/messages"
    assert call["headers"]["x-api-key"] == "test-key"
    assert call["payload"]["model"] == "claude-sonnet-4-5"
    entry = store.list_call_entries("CASE-1")[0]
    assert entry.model == "claude-sonnet-4-5"
    assert entry.tokens_in == 1200 and entry.tokens_out == 300
    assert entry.token_basis == "reported"
    # (1200 * 3.00 + 300 * 15.00) / 1e6 = 8100 / 1e6
    assert entry.cost_usd == Decimal("0.0081")
    assert entry.input_per_mtok_usd == Decimal("3.00")
    assert entry.output_per_mtok_usd == Decimal("15.00")


def test_openai_compatible_call_priced_exactly():
    store = InMemoryCaseStore()
    transport = StubTransport(
        {"prompt_tokens": 2000, "completion_tokens": 500}
    )
    gw = gateway(
        store,
        environ={"IN_BOUNDARY_MODEL_URL": "http://models.bank.internal:8000/v1"},
        transport=transport,
    )
    composer = gw.composer_for(
        "in-boundary", case_id="CASE-9", purpose="record_draft"
    )
    assert composer.compose(draft()) == "A total of 9500.00 moved."
    call = transport.calls[0]
    assert (
        call["url"]
        == "http://models.bank.internal:8000/v1/chat/completions"
    )
    # Key not required and none set: no auth header is invented.
    assert "authorization" not in call["headers"]
    entry = store.list_call_entries("CASE-9")[0]
    # (2000 * 0.90 + 500 * 0.90) / 1e6 = 2250 / 1e6
    assert entry.cost_usd == Decimal("0.00225")
    assert entry.token_basis == "reported"


def test_unreported_usage_falls_back_to_stated_estimate():
    store = InMemoryCaseStore()
    gw = gateway(
        store,
        environ={"ANTHROPIC_API_KEY": "test-key"},
        transport=StubTransport(None),
    )
    composer = gw.composer_for(
        "hosted-frontier", case_id="CASE-2", purpose="sar_draft"
    )
    composer.compose(draft())
    entry = store.list_call_entries("CASE-2")[0]
    assert entry.token_basis == "estimated:chars/4"
    assert entry.tokens_in > 0 and entry.tokens_out > 0
    expected = (
        Decimal(entry.tokens_in) * Decimal("3.00")
        + Decimal(entry.tokens_out) * Decimal("15.00")
    ) / Decimal(1_000_000)
    assert entry.cost_usd == expected


def test_ungrounded_live_text_refused_but_ledgered():
    store = InMemoryCaseStore()
    transport = StubTransport(
        {"input_tokens": 100, "output_tokens": 50},
        text_override="A total of 12345 moved, trust me.",
    )
    gw = gateway(
        store,
        environ={"ANTHROPIC_API_KEY": "test-key"},
        transport=transport,
    )
    composer = gw.composer_for(
        "hosted-frontier", case_id="CASE-3", purpose="sar_draft"
    )
    with pytest.raises(ComposerRefusalError):
        composer.compose(draft())
    entries = store.list_call_entries("CASE-3")
    assert len(entries) == 1
    # The refused statement still cost what it cost.
    assert entries[0].cost_usd == Decimal("0.00105")


# ---------------------------------------------------------------------------
# Budget: refusal before transport, recorded, offline unaffected.
# ---------------------------------------------------------------------------


def test_budget_refusal_happens_before_transport_and_is_recorded(
    tmp_path,
):
    store = InMemoryCaseStore()
    objects = LocalObjectStore(tmp_path / "objects")
    evidence = EvidenceService(store, objects)
    # A case must exist for chain/audit records to land on.
    case = _make_case(store)
    config = load_gateway_config(
        {**copy.deepcopy(DEFAULT_PROFILES_DATA), "case_budget_usd": "0.01"},
        DEFAULT_PRICES_DATA,
    )
    transport = StubTransport(
        {"input_tokens": 1200, "output_tokens": 300}
    )
    gw = ModelGateway(
        config,
        store,
        environ={"ANTHROPIC_API_KEY": "test-key"},
        transport=transport,
        clock=fixed_clock,
        audit_store=store,
        evidence=evidence,
    )
    composer = gw.composer_for(
        "hosted-frontier", case_id=case.case_id, purpose="sar_draft"
    )
    composer.compose(draft())  # spend 0.0081
    composer.compose(draft())  # spend 0.0162 — at/over the cap
    with pytest.raises(ModelBudgetExceededError):
        composer.compose(draft())
    # The refused call never reached the transport.
    assert len(transport.calls) == 2
    # The refusal is recorded three ways: ledger event, case
    # audit, and an item on the case's hash chain.
    events = store.list_budget_events(case.case_id)
    assert len(events) == 1
    assert events[0].cap_usd == Decimal("0.01")
    assert events[0].spent_usd == Decimal("0.0162")
    assert events[0].evidence_seq is not None
    audit = store.list_audit(case.case_id)
    assert any(e.event == "model_budget_refused" for e in audit)
    kinds = [i.kind for i in store.list_evidence(case.case_id)]
    assert "model_budget_refusal" in kinds
    assert evidence.verify_chain(case.case_id)
    # The gateway never switched profiles — but the caller can
    # name offline, and the case continues at zero cost.
    offline = gw.composer_for(
        "offline", case_id=case.case_id, purpose="sar_draft"
    )
    assert offline.compose(draft()) == "A total of 9500.00 moved."
    assert gw.case_spend(case.case_id) == Decimal("0.0162")


def _make_case(store: InMemoryCaseStore):
    from aml_investigations.models import Case

    case = Case(
        case_id="CASE-B1",
        alert_id="ALRT-B1",
        customer_id="CUST-B1",
        account_id="ACCT-B1",
        rule_id="TM-STRUCTURING-01",
        detected_on=date(2026, 10, 20),
    )
    return store.create_case(case)


def test_no_cap_configured_means_no_budget_refusals():
    data = copy.deepcopy(DEFAULT_PROFILES_DATA)
    del data["case_budget_usd"]
    config = load_gateway_config(data, DEFAULT_PRICES_DATA)
    store = InMemoryCaseStore()
    transport = StubTransport({"input_tokens": 1200, "output_tokens": 300})
    gw = ModelGateway(
        config,
        store,
        environ={"ANTHROPIC_API_KEY": "k"},
        transport=transport,
        clock=fixed_clock,
    )
    composer = gw.composer_for(
        "hosted-frontier", case_id="CASE-X", purpose="sar_draft"
    )
    for _ in range(5):
        composer.compose(draft())
    assert len(transport.calls) == 5
    assert store.list_budget_events("CASE-X") == []


# ---------------------------------------------------------------------------
# Rollups + the SQL store round-trip.
# ---------------------------------------------------------------------------


def test_rollups_by_purpose_profile_and_day():
    store = InMemoryCaseStore()
    transport = StubTransport({"input_tokens": 1200, "output_tokens": 300})
    gw = gateway(
        store, environ={"ANTHROPIC_API_KEY": "k"}, transport=transport
    )
    live = gw.composer_for(
        "hosted-frontier", case_id="CASE-1", purpose="sar_draft"
    )
    live.compose(draft())
    live.compose(draft())
    off = gw.composer_for("offline", case_id="CASE-1", purpose="record_draft")
    off.compose(draft())
    system = gw.composer_for("offline", case_id=None, purpose="sar_draft")
    system.compose(draft())

    rollup = gw.case_rollup("CASE-1")
    assert rollup["calls"] == 3
    assert rollup["cost_usd"] == "0.0162"
    assert rollup["by_purpose"]["sar_draft"]["cost_usd"] == "0.0162"
    assert rollup["by_purpose"]["record_draft"]["calls"] == 1
    assert rollup["by_profile"]["hosted-frontier"]["tokens_in"] == 2400
    assert rollup["budget_cap_usd"] == "2.50"
    assert rollup["budget_refusals"] == 0

    rows = gw.portfolio_rollup()
    by_key = {(r["day"], r["profile_id"]): r for r in rows}
    assert by_key[("2026-10-25", "hosted-frontier")]["calls"] == 2
    assert by_key[("2026-10-25", "hosted-frontier")]["cost_usd"] == "0.0162"
    # The system-scope call is in the portfolio, under no case.
    assert by_key[("2026-10-25", "offline")]["calls"] == 2


def test_sql_store_ledger_round_trip(tmp_path):
    store = SqlCaseStore.sqlite(
        tmp_path / "aml.db", REPO_ROOT / "migrations"
    )
    gw = gateway(store)
    composer = gw.composer_for(
        "offline", case_id="CASE-SQL", purpose="record_draft"
    )
    composer.compose(draft())
    reopened = SqlCaseStore.sqlite(
        tmp_path / "aml.db", REPO_ROOT / "migrations"
    )
    entries = reopened.list_call_entries("CASE-SQL")
    assert len(entries) == 1
    assert entries[0].cost_usd == Decimal("0")
    assert entries[0].called_at == FIXED_NOW
    assert len(reopened.list_call_entries(None)) == 1


# ---------------------------------------------------------------------------
# Service integration: the wired drafting surfaces ledger every
# statement they compose — investigation records and SAR drafts,
# offline at zero and live at exact prices.
# ---------------------------------------------------------------------------

ACCOUNT = "ACCT-T-1"
CUSTOMER = "CUST-T-1"
ANALYST = "a.okafor"


def _txn(tid, day, amount, *, cash=False, channel="wire"):
    return Transaction(
        transaction_id=tid,
        account_id=ACCOUNT,
        posted_at=datetime.combine(day, time(10, 0), tzinfo=timezone.utc),
        direction="credit",
        amount=Decimal(amount),
        channel=channel,
        cash=cash,
    )


STRUCTURING_STREAM = [
    _txn("T-S1", date(2026, 2, 10), "4200.00", channel="ach"),
    _txn("T-1", date(2026, 3, 2), "9500", cash=True, channel="branch"),
    _txn("T-2", date(2026, 3, 4), "9600", cash=True, channel="branch"),
    _txn("T-3", date(2026, 3, 6), "9700", cash=True, channel="branch"),
    _txn("T-S2", date(2026, 3, 10), "4200.00", channel="ach"),
]

SANCTIONS = ListSnapshot(
    list_kind=ListKind.SANCTIONS,
    version="2026.10.1",
    published_at="2026-10-01T00:00:00Z",
    source_note="test feed",
    entries=[
        ListEntry(
            entry_id="SDN-1", name="Viktor Petrov",
            dob="1962-04-11", identifiers=["PP-XK-4471"],
        )
    ],
)

CUSTOMER_SUBJECT = ScreeningSubject(
    subject_ref=f"customer:{CUSTOMER}",
    name="Daniel Okafor",
    role="customer",
    dob=date(1985, 3, 4),
    identifiers=["PP-NG-2210"],
)


class GatewayStack:
    """The R6 test stack's shape, with the gateway wired into
    the two drafting services."""

    def __init__(self, tmp_path: Path, store: InMemoryCaseStore, gw):
        self.store = store
        self.objects = LocalObjectStore(tmp_path / "objects")
        self.evidence = EvidenceService(self.store, self.objects)
        self.workflow = CaseWorkflow(self.store, screening_store=self.store)
        alert = Alert(
            alert_id="ALRT-G-1",
            rule_id="TM-STRUCTURING-01",
            customer_id=CUSTOMER,
            account_id=ACCOUNT,
            severity="high",
            detected_on="2026-03-07",
            summary="Cash deposits clustering under the CTR threshold.",
            raw={
                "customer_name": "Daniel Okafor",
                "customer_dob": "1985-03-04",
                "customer_identifiers": ["PP-NG-2210"],
                "counterparties": [],
            },
        )
        self.intake = IntakeService(
            self.store, ListAlertFeed([alert]), self.evidence
        )
        self.screening = ScreeningService(
            self.store, self.store, self.evidence
        )
        self.typologies = TypologyService(
            self.store, self.store, self.evidence
        )
        self.investigations = InvestigationService(
            self.store, self.store, self.store, self.store, self.evidence,
            disposition_store=self.store,
            gateway=gw,
        )
        self.dispositions = DispositionService(
            self.store, self.store, self.store, self.store,
            self.evidence, self.workflow,
        )
        self.sar = SarNarrativeService(
            self.store, self.store, self.store, self.store, self.evidence,
            gateway=gw,
        )
        self.screening.ingest_snapshot(SANCTIONS, actor="test-feed")
        self.typologies.register_rule_pack(
            RulePack(pack_id="test-pack", version="1.0")
        )

    def sar_pending_case(self) -> tuple[str, object]:
        case_id = self.intake.open_case("ALRT-G-1").case_id
        self.workflow.transition(case_id, CaseStatus.ASSEMBLING, actor="test")
        self.screening.screen_case(
            case_id,
            {ListKind.SANCTIONS: "2026.10.1"},
            actor="test",
            subjects=[CUSTOMER_SUBJECT],
        )
        profile = AccountProfile(
            account_id=ACCOUNT,
            customer_id=CUSTOMER,
            opened_on=date(2026, 2, 1),
            account_type="business_checking",
            expected_monthly_amount=Decimal("30000"),
            expected_monthly_count=40,
        )
        feed = ListTransactionFeed([profile], {ACCOUNT: STRUCTURING_STREAM})
        self.typologies.ingest_from_source(case_id, feed, actor="test-feed")
        self.typologies.run_typologies(
            case_id, "test-pack", "1.0", actor="test-runner"
        )
        self.workflow.transition(
            case_id, CaseStatus.INVESTIGATING, actor="test"
        )
        record = self.investigations.run_investigation(case_id, actor="test")
        self.workflow.transition(
            case_id, CaseStatus.AWAITING_ANALYST, actor="test"
        )
        self.dispositions.record_disposition(
            case_id,
            analyst_id=ANALYST,
            analyst_role="analyst",
            outcome=DispositionOutcome.ESCALATE_SAR,
            rationale_codes=["STRUCTURING_SUSPECTED"],
            record_id=record.record_id,
            record_version=record.version,
        )
        assert self.store.get_case(case_id).status is CaseStatus.SAR_PENDING
        return case_id, record


def test_services_ledger_every_composed_statement(tmp_path):
    store = InMemoryCaseStore()
    gw = gateway(store, audit=True)
    stack = GatewayStack(tmp_path, store, gw)
    case_id, record = stack.sar_pending_case()
    narrative, verification = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service"
    )
    assert verification.all_verified

    entries = store.list_call_entries(case_id)
    record_entries = [e for e in entries if e.purpose == "record_draft"]
    sar_entries = [e for e in entries if e.purpose == "sar_draft"]
    # One ledger entry per composed statement — no call unpriced,
    # none double-counted.
    assert len(record_entries) == len(record.findings)
    statement_count = sum(
        len(s.statements) for s in narrative.sections
    )
    assert len(sar_entries) == statement_count
    assert all(e.cost_usd == Decimal("0") for e in entries)
    assert all(e.profile_id == "offline" for e in entries)
    assert all(e.price_table_version == "2026.10.1" for e in entries)


def test_live_sar_draft_through_gateway_priced_exactly(tmp_path):
    store = InMemoryCaseStore()
    transport = StubTransport({"input_tokens": 100, "output_tokens": 50})
    gw = ModelGateway(
        default_gateway_config(),
        store,
        environ={"ANTHROPIC_API_KEY": "test-key"},
        transport=transport,
        clock=fixed_clock,
        audit_store=store,
    )
    stack = GatewayStack(tmp_path, store, gw)
    case_id, _record = stack.sar_pending_case()
    narrative, verification = stack.sar.draft_narrative(
        case_id, actor="sar-drafting-service", profile="hosted-frontier"
    )
    assert verification.all_verified
    assert narrative.model_profile == "hosted-frontier"
    statement_count = sum(len(s.statements) for s in narrative.sections)
    live_entries = [
        e
        for e in store.list_call_entries(case_id)
        if e.profile_id == "hosted-frontier"
    ]
    assert len(live_entries) == statement_count
    assert len(transport.calls) == statement_count
    # (100 * 3.00 + 50 * 15.00) / 1e6 = 1050 / 1e6, per call.
    assert all(e.cost_usd == Decimal("0.00105") for e in live_entries)
    total = sum(e.cost_usd for e in live_entries)
    assert total == Decimal("0.00105") * statement_count
    assert gw.case_rollup(case_id)["by_profile"]["hosted-frontier"][
        "cost_usd"
    ] == format(total, "f")
