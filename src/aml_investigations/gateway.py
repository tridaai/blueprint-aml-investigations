"""The model gateway (R13): named profiles, real adapters, and
the cost ledger.

R4/R6 put composition behind a port (``composer.py``) with two
profiles: a deterministic offline composer and a ``hosted-frontier``
stub that refuses loudly until a key is wired. R13 builds the full
gateway on that port — the one configured path every drafting call
goes through when a deployment wires it:

**Profiles are data.** A profile is a definition (id, provider
kind, model, the *names* of the environment variables holding its
endpoint and key, a timeout) — never a code branch, and never a
secret value. Every profile's model must appear in the versioned
price table. The loader is **fail-closed**: a duplicate id, a live
profile with no endpoint, a missing or malformed price entry, or
a negative price refuses the whole configuration at load time.
Selecting an unknown profile, or a live profile whose endpoint/key
the deployment has not set, refuses loudly at call time. There is
no fallback anywhere in this module: the gateway never substitutes
one profile for another, at load, at wiring, or mid-case.

**Adapters are real HTTP clients** behind the port, one per
provider kind: the Anthropic Messages shape for a hosted frontier
model, the OpenAI-compatible shape for an open-weight model served
inside the bank's boundary, and the deterministic template
composer for ``offline``. Each returns the composed text plus the
call's token counts — the provider's reported usage when it sends
one, or the adapter's stated estimate basis when it does not. The
gateway applies the composer's figure gate to live text exactly
as to offline text: a statement carrying a figure outside the
draft's allowed set is refused, whoever wrote it.

**Every call is priced and ledgered.** A call through the gateway
appends one :class:`ModelCallEntry` — case, purpose, profile,
model, tokens, the price-table version and the unit prices it was
priced with, the exact Decimal cost, latency, and the injected
clock's timestamp. Offline calls ledger at zero: the ledger is
the complete record of drafting cost, not just the paid part.

**Budgets are enforced before transport.** A deployment sets a
per-case cap (configuration data). When a case's priced spend
reaches the cap, further live-profile calls for that case are
refused *before any transport is touched*, and the refusal is
recorded — a budget event in the ledger store, an audit event on
the case, and an item on the case's hash chain where the evidence
service is wired. The offline profile is never capped, and
continuing a case offline after a refusal is a normal recorded
path — taken by the caller naming ``offline``, never by the
gateway switching on its own.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable

from pydantic import ValidationError

from .composer import StatementDraft, ungrounded_figures
from .errors import (
    CaseSealedError,
    ComposerRefusalError,
    ModelBudgetExceededError,
    ModelGatewayError,
    ModelProfileConfigError,
    ModelProfileNotConfiguredError,
    UnknownModelProfileError,
)
from .models import (
    AuditEvent,
    ModelBudgetEvent,
    ModelCallEntry,
    ModelPrice,
    ModelProfileDefinition,
    PriceTable,
    ProviderKind,
    _utcnow,
)
from .ports import CaseStore, ModelLedgerStore

#: Purpose names the wired services compose under. The vocabulary
#: is open (a purpose is a label on the ledger entry), but these
#: are the drafting surfaces the blueprint ships.
PURPOSE_RECORD_DRAFT = "record_draft"
PURPOSE_SAR_DRAFT = "sar_draft"
PURPOSE_REVIEW_DRAFT = "review_draft"

#: Actor name on the audit/chain records a budget refusal writes.
GATEWAY_ACTOR = "model-gateway"

#: Evidence kind a budget refusal lands on the case chain under.
BUDGET_REFUSAL_KIND = "model_budget_refusal"


# ---------------------------------------------------------------------------
# Canonical configuration data. ``data/model_profiles.json`` and
# ``data/model_prices.json`` carry exactly this content for the
# file-based wiring; a test pins the two together so they cannot
# drift. Prices are governed reference data (see PriceTable).
# ---------------------------------------------------------------------------

DEFAULT_PROFILES_DATA: dict = {
    "version": "2026.10.1",
    "case_budget_usd": "2.50",
    "profiles": [
        {
            "profile_id": "offline",
            "provider_kind": "offline",
            "model": "offline-template-composer-v1",
        },
        {
            "profile_id": "hosted-frontier",
            "provider_kind": "anthropic",
            "model": "claude-sonnet-4-5",
            "endpoint_env": "ANTHROPIC_BASE_URL",
            "endpoint_default": "https://api.anthropic.com",
            "api_key_env": "ANTHROPIC_API_KEY",
            "key_required": True,
        },
        {
            "profile_id": "in-boundary",
            "provider_kind": "openai-compatible",
            "model": "llama-3.3-70b-instruct",
            "endpoint_env": "IN_BOUNDARY_MODEL_URL",
            "endpoint_default": None,
            "api_key_env": "IN_BOUNDARY_MODEL_API_KEY",
            "key_required": False,
        },
    ],
}

DEFAULT_PRICES_DATA: dict = {
    "version": "2026.10.1",
    "as_of": "2026-10-01",
    "entries": [
        {
            "model": "offline-template-composer-v1",
            "input_per_mtok_usd": "0",
            "output_per_mtok_usd": "0",
            "basis": "deterministic template composer — no model "
            "call, no cost; priced so every call can ledger",
        },
        {
            "model": "claude-sonnet-4-5",
            "input_per_mtok_usd": "3.00",
            "output_per_mtok_usd": "15.00",
            "basis": "provider list price at the table's as-of "
            "date — governed reference data, maintained by the "
            "deployment",
        },
        {
            "model": "llama-3.3-70b-instruct",
            "input_per_mtok_usd": "0.90",
            "output_per_mtok_usd": "0.90",
            "basis": "internal serving-cost allocation for the "
            "bank's own inference boundary, set by the deployment",
        },
    ],
}


# ---------------------------------------------------------------------------
# Configuration loading — fail-closed.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GatewayConfig:
    """Validated gateway configuration: profiles + price table +
    the per-case budget cap, ready to wire."""

    profiles_version: str
    case_budget_usd: Decimal | None
    profiles: dict[str, ModelProfileDefinition]
    price_table: PriceTable
    price_by_model: dict[str, ModelPrice]


def load_gateway_config(
    profiles_data: dict, prices_data: dict
) -> GatewayConfig:
    """Validate raw profile/price data into a GatewayConfig.

    Fail-closed: any defect refuses the whole configuration with
    :class:`ModelProfileConfigError`. A deployment with a broken
    profile table does not start, and no defect is ever repaired
    by substituting a different profile or a guessed price.
    """
    try:
        price_table = PriceTable.model_validate(prices_data)
    except ValidationError as exc:
        raise ModelProfileConfigError(
            f"price table is malformed: {exc}"
        ) from exc
    price_by_model: dict[str, ModelPrice] = {}
    for entry in price_table.entries:
        if entry.model in price_by_model:
            raise ModelProfileConfigError(
                f"price table {price_table.version} prices model "
                f"{entry.model!r} twice; a model has exactly one "
                "price per table version"
            )
        if entry.input_per_mtok_usd < 0 or entry.output_per_mtok_usd < 0:
            raise ModelProfileConfigError(
                f"price table {price_table.version} carries a "
                f"negative price for model {entry.model!r}; prices "
                "are reference data and a negative price is a "
                "malformed entry, not a discount"
            )
        price_by_model[entry.model] = entry

    version = profiles_data.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ModelProfileConfigError(
            "model profiles data carries no version; profiles are "
            "governed configuration and an unversioned set is "
            "refused"
        )
    raw_budget = profiles_data.get("case_budget_usd")
    case_budget: Decimal | None = None
    if raw_budget is not None:
        try:
            case_budget = Decimal(str(raw_budget))
        except Exception as exc:
            raise ModelProfileConfigError(
                f"case_budget_usd {raw_budget!r} is not a decimal "
                "amount; the per-case budget cap is configuration "
                "and a malformed cap is refused, not ignored"
            ) from exc
        if case_budget < 0:
            raise ModelProfileConfigError(
                "case_budget_usd is negative; a budget cap is a "
                "non-negative amount"
            )

    raw_profiles = profiles_data.get("profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise ModelProfileConfigError(
            "model profiles data names no profiles; a gateway with "
            "no profiles is a misconfiguration, not a default"
        )
    profiles: dict[str, ModelProfileDefinition] = {}
    for raw in raw_profiles:
        try:
            definition = ModelProfileDefinition.model_validate(raw)
        except ValidationError as exc:
            raise ModelProfileConfigError(
                f"model profile definition is malformed: {exc}"
            ) from exc
        if definition.profile_id in profiles:
            raise ModelProfileConfigError(
                f"model profile {definition.profile_id!r} is "
                "defined twice; profile ids are unique"
            )
        if definition.provider_kind is not ProviderKind.OFFLINE:
            if not definition.endpoint_env and not definition.endpoint_default:
                raise ModelProfileConfigError(
                    f"live model profile {definition.profile_id!r} "
                    "names no endpoint (neither endpoint_env nor "
                    "endpoint_default); a live profile without an "
                    "endpoint is refused at load, not at call time"
                )
            if definition.key_required and not definition.api_key_env:
                raise ModelProfileConfigError(
                    f"model profile {definition.profile_id!r} "
                    "requires an API key but names no api_key_env; "
                    "the key's variable must be named in the "
                    "definition"
                )
        if definition.model not in price_by_model:
            raise ModelProfileConfigError(
                f"model profile {definition.profile_id!r} names "
                f"model {definition.model!r}, which has no entry "
                f"in price table {price_table.version}; an "
                "unpriceable call is a configuration error, "
                "refused here — never discovered on an invoice"
            )
        profiles[definition.profile_id] = definition
    return GatewayConfig(
        profiles_version=version,
        case_budget_usd=case_budget,
        profiles=profiles,
        price_table=price_table,
        price_by_model=price_by_model,
    )


def default_gateway_config() -> GatewayConfig:
    """The gateway configuration from the canonical in-module
    data — the same content the shipped JSON files carry."""
    return load_gateway_config(DEFAULT_PROFILES_DATA, DEFAULT_PRICES_DATA)


def load_gateway_files(
    profiles_path: Path, prices_path: Path
) -> GatewayConfig:
    """Load + validate the gateway configuration from JSON files.
    A missing or unreadable file is a configuration error, not a
    reason to fall back to built-in defaults."""
    try:
        profiles_data = json.loads(Path(profiles_path).read_text("utf-8"))
        prices_data = json.loads(Path(prices_path).read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelProfileConfigError(
            f"gateway configuration files could not be read "
            f"({profiles_path}, {prices_path}): {exc}"
        ) from exc
    return load_gateway_config(profiles_data, prices_data)


# ---------------------------------------------------------------------------
# Transports and adapters.
# ---------------------------------------------------------------------------


@runtime_checkable
class ModelTransport(Protocol):
    """One JSON POST to a model endpoint. The real implementation
    is :class:`HttpxTransport`; tests inject stubs returning
    provider-shaped responses — the adapters are exercised against
    the same response shapes either way."""

    def post_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        payload: dict,
        timeout: float,
    ) -> dict: ...


class HttpxTransport:
    """The production transport: plain HTTPS JSON via httpx (the
    repo's one HTTP client)."""

    def post_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        payload: dict,
        timeout: float,
    ) -> dict:
        import httpx

        try:
            response = httpx.post(
                url, headers=headers, json=payload, timeout=timeout
            )
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            raise ModelGatewayError(
                f"model endpoint call failed ({url}): {exc}"
            ) from exc


@dataclass
class ModelCompletion:
    """One adapter call's raw product: the composed text (not yet
    figure-gated — the gateway gates it) and the call's token
    accounting, with the basis the counts stand on."""

    text: str
    tokens_in: int
    tokens_out: int
    token_basis: str


def _estimate_tokens(text: str) -> int:
    """The adapters' stated estimate when a provider reports no
    usage: one token per four characters, rounded up, minimum 1.
    Named on the ledger entry as ``estimated:chars/4`` — an
    estimate is labelled an estimate wherever it is recorded."""
    return max(1, -(-len(text) // 4))


def _prompt_for(draft: StatementDraft) -> str:
    """The live adapters' prompt: the draft's template, the exact
    values code computed for its slots, and the rendered candidate
    — with the instruction that binds every profile: produce the
    finished statement using only these figures."""
    rendered = draft.template.format(**draft.values)
    values_block = (
        json.dumps(draft.values, indent=2, sort_keys=True)
        if draft.values
        else "(no slot values — the statement is fixed text)"
    )
    return (
        "You are drafting one statement for a bank AML case file. "
        "The statement's facts and figures were computed in code "
        "from cited evidence; your task is only to produce the "
        "finished statement text.\n\n"
        "Template:\n"
        f"{draft.template}\n\n"
        "Values computed in code (use exactly these):\n"
        f"{values_block}\n\n"
        "Candidate statement (the template rendered with the "
        "values):\n"
        "<<<STATEMENT>>>\n"
        f"{rendered}\n"
        "<<<END>>>\n\n"
        "Return only the finished statement. You may polish the "
        "wording, but you must not introduce, alter, or drop any "
        "figure, date, name, or identifier: every number in your "
        "statement must appear in the values or the candidate "
        "above. A statement carrying an ungrounded figure is "
        "refused by a verifier in code."
    )


class _OfflineAdapter:
    """The ``offline`` profile's adapter: deterministic template
    rendering, no model call, zero tokens — the same rendering
    :class:`composer.OfflineComposer` performs, reached through
    the gateway so the call ledgers like every other."""

    def generate(self, draft: StatementDraft) -> ModelCompletion:
        return ModelCompletion(
            text=draft.template.format(**draft.values),
            tokens_in=0,
            tokens_out=0,
            token_basis="reported",
        )


class _AnthropicAdapter:
    """A hosted frontier model over the Anthropic Messages API."""

    def __init__(
        self,
        definition: ModelProfileDefinition,
        endpoint: str,
        api_key: str | None,
        transport: ModelTransport,
    ) -> None:
        self._definition = definition
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._transport = transport

    def generate(self, draft: StatementDraft) -> ModelCompletion:
        prompt = _prompt_for(draft)
        headers = {
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if self._api_key:
            headers["x-api-key"] = self._api_key
        body = self._transport.post_json(
            f"{self._endpoint}/v1/messages",
            headers=headers,
            payload={
                "model": self._definition.model,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=self._definition.timeout_seconds,
        )
        text = "".join(
            str(block.get("text", ""))
            for block in body.get("content", [])
            if isinstance(block, dict) and block.get("type") == "text"
        ).strip()
        usage = body.get("usage") or {}
        if "input_tokens" in usage and "output_tokens" in usage:
            return ModelCompletion(
                text=text,
                tokens_in=int(usage["input_tokens"]),
                tokens_out=int(usage["output_tokens"]),
                token_basis="reported",
            )
        return ModelCompletion(
            text=text,
            tokens_in=_estimate_tokens(prompt),
            tokens_out=_estimate_tokens(text),
            token_basis="estimated:chars/4",
        )


class _OpenAICompatibleAdapter:
    """An open-weight model served inside the boundary over an
    OpenAI-compatible chat-completions endpoint."""

    def __init__(
        self,
        definition: ModelProfileDefinition,
        endpoint: str,
        api_key: str | None,
        transport: ModelTransport,
    ) -> None:
        self._definition = definition
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._transport = transport

    def generate(self, draft: StatementDraft) -> ModelCompletion:
        prompt = _prompt_for(draft)
        headers = {"content-type": "application/json"}
        if self._api_key:
            headers["authorization"] = f"Bearer {self._api_key}"
        body = self._transport.post_json(
            f"{self._endpoint}/chat/completions",
            headers=headers,
            payload={
                "model": self._definition.model,
                "temperature": 0,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=self._definition.timeout_seconds,
        )
        choices = body.get("choices") or []
        text = ""
        if choices and isinstance(choices[0], dict):
            text = str(
                (choices[0].get("message") or {}).get("content", "")
            ).strip()
        usage = body.get("usage") or {}
        if "prompt_tokens" in usage and "completion_tokens" in usage:
            return ModelCompletion(
                text=text,
                tokens_in=int(usage["prompt_tokens"]),
                tokens_out=int(usage["completion_tokens"]),
                token_basis="reported",
            )
        return ModelCompletion(
            text=text,
            tokens_in=_estimate_tokens(prompt),
            tokens_out=_estimate_tokens(text),
            token_basis="estimated:chars/4",
        )


# ---------------------------------------------------------------------------
# The gateway.
# ---------------------------------------------------------------------------


@dataclass
class _ResolvedProfile:
    """A profile definition plus what the deployment's environment
    resolved for it at wiring time. The API key value lives only
    here, in memory — never on a record, a ledger entry, or a log
    line; summaries expose only ``configured``."""

    definition: ModelProfileDefinition
    endpoint: str | None
    api_key: str | None

    @property
    def is_live(self) -> bool:
        return self.definition.provider_kind is not ProviderKind.OFFLINE

    @property
    def configured(self) -> bool:
        if not self.is_live:
            return True
        if not self.endpoint:
            return False
        if self.definition.key_required and not self.api_key:
            return False
        return True


class ModelGateway:
    """The configured path for every model call: profile
    resolution (fail-closed), budget enforcement, adapter dispatch,
    the figure gate, and the cost ledger.

    ``ledger_store`` is required — a gateway without its ledger
    would make unrecorded calls, which is the one thing this
    module exists to prevent. ``clock`` is injected so timestamps
    on ledger entries are testable; production wiring takes the
    default wall clock, and no verdict anywhere derives from a
    ledger timestamp.
    """

    def __init__(
        self,
        config: GatewayConfig,
        ledger_store: ModelLedgerStore,
        *,
        environ: dict[str, str] | None = None,
        transport: ModelTransport | None = None,
        clock: Callable[[], datetime] | None = None,
        audit_store: CaseStore | None = None,
        evidence=None,
        active_profile: str | None = None,
    ) -> None:
        self._config = config
        self._ledger = ledger_store
        self._transport = transport or HttpxTransport()
        self._clock = clock or _utcnow
        self._audit = audit_store
        self._evidence = evidence
        env = os.environ if environ is None else environ
        self._resolved: dict[str, _ResolvedProfile] = {}
        for profile_id, definition in config.profiles.items():
            endpoint = None
            if definition.endpoint_env:
                endpoint = env.get(definition.endpoint_env) or None
            endpoint = endpoint or definition.endpoint_default
            api_key = None
            if definition.api_key_env:
                api_key = env.get(definition.api_key_env) or None
            self._resolved[profile_id] = _ResolvedProfile(
                definition=definition, endpoint=endpoint, api_key=api_key
            )
        if active_profile is not None:
            # Wiring-time fail-closed: the profile a deployment
            # names as its own must exist and be fully configured
            # before the stack starts — not on its first call.
            resolved = self._require_profile(active_profile)
            self._require_configured(resolved)

    # -- configuration surface -------------------------------------

    @property
    def config(self) -> GatewayConfig:
        return self._config

    @property
    def price_table(self) -> PriceTable:
        return self._config.price_table

    @property
    def case_budget_usd(self) -> Decimal | None:
        return self._config.case_budget_usd

    def profile_summaries(self) -> list[dict]:
        """Every profile, its model, its price, and whether this
        deployment has configured it. Key *values* never appear —
        only the variable names and the configured flag."""
        summaries = []
        for profile_id in sorted(self._resolved):
            resolved = self._resolved[profile_id]
            definition = resolved.definition
            price = self._config.price_by_model[definition.model]
            summaries.append(
                {
                    "profile_id": profile_id,
                    "provider_kind": definition.provider_kind.value,
                    "model": definition.model,
                    "configured": resolved.configured,
                    "endpoint_env": definition.endpoint_env,
                    "api_key_env": definition.api_key_env,
                    "key_required": definition.key_required,
                    "input_per_mtok_usd": format(
                        price.input_per_mtok_usd, "f"
                    ),
                    "output_per_mtok_usd": format(
                        price.output_per_mtok_usd, "f"
                    ),
                    "price_table_version": self._config.price_table.version,
                }
            )
        return summaries

    # -- resolution (fail-closed) -----------------------------------

    def _require_profile(self, profile_id: str) -> _ResolvedProfile:
        resolved = self._resolved.get(profile_id)
        if resolved is None:
            raise UnknownModelProfileError(
                f"unknown model profile {profile_id!r}; the gateway "
                f"holds: {', '.join(sorted(self._resolved))}. No "
                "profile is substituted for the one that was named"
            )
        return resolved

    def _require_configured(self, resolved: _ResolvedProfile) -> None:
        definition = resolved.definition
        if resolved.configured:
            return
        missing = []
        if not resolved.endpoint:
            missing.append(
                f"endpoint (set {definition.endpoint_env})"
                if definition.endpoint_env
                else "endpoint"
            )
        if definition.key_required and not resolved.api_key:
            missing.append(f"API key (set {definition.api_key_env})")
        raise ModelProfileNotConfiguredError(
            f"model profile {definition.profile_id!r} is not "
            f"configured in this deployment — missing: "
            f"{', '.join(missing)}. The call is refused; no other "
            "profile is substituted"
        )

    def _adapter_for(self, resolved: _ResolvedProfile):
        definition = resolved.definition
        if definition.provider_kind is ProviderKind.OFFLINE:
            return _OfflineAdapter()
        if definition.provider_kind is ProviderKind.ANTHROPIC:
            return _AnthropicAdapter(
                definition,
                resolved.endpoint or "",
                resolved.api_key,
                self._transport,
            )
        return _OpenAICompatibleAdapter(
            definition,
            resolved.endpoint or "",
            resolved.api_key,
            self._transport,
        )

    # -- composition --------------------------------------------------

    def composer_for(
        self,
        profile_id: str,
        *,
        case_id: str | None = None,
        purpose: str,
    ):
        """A composer bound to one case + purpose, satisfying the
        repo's NarrativeComposer protocol. Resolution is
        fail-closed here, before any drafting begins."""
        resolved = self._require_profile(profile_id)
        self._require_configured(resolved)
        return _GatewayComposer(self, resolved, case_id, purpose)

    def _price(
        self, model: str, tokens_in: int, tokens_out: int
    ) -> tuple[ModelPrice, Decimal]:
        price = self._config.price_by_model[model]
        cost = (
            Decimal(tokens_in) * price.input_per_mtok_usd
            + Decimal(tokens_out) * price.output_per_mtok_usd
        ) / Decimal(1_000_000)
        return price, cost

    def _compose(
        self,
        resolved: _ResolvedProfile,
        case_id: str | None,
        purpose: str,
        draft: StatementDraft,
    ) -> str:
        definition = resolved.definition
        if resolved.is_live and case_id is not None:
            self._enforce_budget(resolved, case_id, purpose)
        adapter = self._adapter_for(resolved)
        started = time.perf_counter()
        completion = adapter.generate(draft)
        latency_ms = int(round((time.perf_counter() - started) * 1000))
        price, cost = self._price(
            definition.model, completion.tokens_in, completion.tokens_out
        )
        entry = ModelCallEntry(
            case_id=case_id,
            purpose=purpose,
            profile_id=definition.profile_id,
            model=definition.model,
            tokens_in=completion.tokens_in,
            tokens_out=completion.tokens_out,
            token_basis=completion.token_basis,
            price_table_version=self._config.price_table.version,
            input_per_mtok_usd=price.input_per_mtok_usd,
            output_per_mtok_usd=price.output_per_mtok_usd,
            cost_usd=cost,
            latency_ms=latency_ms,
            called_at=self._clock(),
        )
        self._ledger.add_call_entry(entry)
        stray = ungrounded_figures(completion.text, draft.allowed)
        if stray:
            raise ComposerRefusalError(
                "statement would carry figure(s) not present in the "
                f"cited records or the finding's figures: "
                f"{', '.join(stray)} (profile "
                f"{definition.profile_id!r}; the call is recorded "
                "in the cost ledger — a refused statement still "
                "cost what it cost)"
            )
        return completion.text

    # -- budget -------------------------------------------------------

    def case_spend(self, case_id: str) -> Decimal:
        """The case's total priced spend across all profiles and
        purposes, from the ledger — the figure the cap tests."""
        total = Decimal("0")
        for entry in self._ledger.list_call_entries(case_id):
            total += entry.cost_usd
        return total

    def _enforce_budget(
        self,
        resolved: _ResolvedProfile,
        case_id: str,
        purpose: str,
    ) -> None:
        cap = self._config.case_budget_usd
        if cap is None:
            return
        spent = self.case_spend(case_id)
        if spent < cap:
            return
        definition = resolved.definition
        event = ModelBudgetEvent(
            case_id=case_id,
            profile_id=definition.profile_id,
            model=definition.model,
            purpose=purpose,
            cap_usd=cap,
            spent_usd=spent,
            recorded_at=self._clock(),
        )
        if self._evidence is not None:
            try:
                item = self._evidence.add_item(
                    case_id=case_id,
                    kind=BUDGET_REFUSAL_KIND,
                    content=event.model_dump_json(indent=2).encode("utf-8"),
                    source_ref=f"model-budget:{event.event_id}",
                    captured_by=GATEWAY_ACTOR,
                )
                event = event.model_copy(
                    update={"evidence_seq": item.seq}
                )
            except CaseSealedError:
                # A sealed case takes no new chain items; the
                # ledger event and the audit record below still
                # stand, and drafting on a sealed case is refused
                # at every service door in any event.
                pass
        self._ledger.add_budget_event(event)
        if self._audit is not None:
            self._audit.append_audit(
                AuditEvent(
                    case_id=case_id,
                    actor=GATEWAY_ACTOR,
                    event="model_budget_refused",
                    detail={
                        "event_id": event.event_id,
                        "profile_id": definition.profile_id,
                        "model": definition.model,
                        "purpose": purpose,
                        "cap_usd": format(cap, "f"),
                        "spent_usd": format(spent, "f"),
                        "evidence_seq": (
                            str(event.evidence_seq)
                            if event.evidence_seq is not None
                            else ""
                        ),
                    },
                )
            )
        raise ModelBudgetExceededError(
            case_id,
            definition.profile_id,
            format(cap, "f"),
            format(spent, "f"),
        )

    # -- rollups ------------------------------------------------------

    def case_rollup(self, case_id: str) -> dict:
        """The case's drafting cost, broken down by purpose and by
        profile, with the cap position. All money exact Decimal,
        rendered as strings at this boundary."""
        entries = self._ledger.list_call_entries(case_id)
        by_purpose: dict[str, dict] = {}
        by_profile: dict[str, dict] = {}
        total_cost = Decimal("0")
        total_in = 0
        total_out = 0
        for entry in entries:
            total_cost += entry.cost_usd
            total_in += entry.tokens_in
            total_out += entry.tokens_out
            for bucket, key in (
                (by_purpose, entry.purpose),
                (by_profile, entry.profile_id),
            ):
                row = bucket.setdefault(
                    key,
                    {
                        "calls": 0,
                        "tokens_in": 0,
                        "tokens_out": 0,
                        "cost_usd": Decimal("0"),
                    },
                )
                row["calls"] += 1
                row["tokens_in"] += entry.tokens_in
                row["tokens_out"] += entry.tokens_out
                row["cost_usd"] += entry.cost_usd

        def render(bucket: dict[str, dict]) -> dict:
            return {
                key: {
                    "calls": row["calls"],
                    "tokens_in": row["tokens_in"],
                    "tokens_out": row["tokens_out"],
                    "cost_usd": format(row["cost_usd"], "f"),
                }
                for key, row in sorted(bucket.items())
            }

        cap = self._config.case_budget_usd
        return {
            "case_id": case_id,
            "calls": len(entries),
            "tokens_in": total_in,
            "tokens_out": total_out,
            "cost_usd": format(total_cost, "f"),
            "by_purpose": render(by_purpose),
            "by_profile": render(by_profile),
            "budget_cap_usd": (
                format(cap, "f") if cap is not None else None
            ),
            "budget_spent_usd": format(total_cost, "f"),
            "budget_refusals": len(
                self._ledger.list_budget_events(case_id)
            ),
            "price_table_version": self._config.price_table.version,
        }

    def portfolio_rollup(self) -> list[dict]:
        """Every ledger entry grouped by UTC day + profile: the
        portfolio's drafting spend, day by day. No verdict derives
        from these timestamps — this is cost reporting, grouped by
        the injected clock's recorded instants."""
        rows: dict[tuple[str, str], dict] = {}
        for entry in self._ledger.list_call_entries(None):
            day = entry.called_at.date().isoformat()
            row = rows.setdefault(
                (day, entry.profile_id),
                {
                    "day": day,
                    "profile_id": entry.profile_id,
                    "model": entry.model,
                    "calls": 0,
                    "tokens_in": 0,
                    "tokens_out": 0,
                    "cost_usd": Decimal("0"),
                },
            )
            row["calls"] += 1
            row["tokens_in"] += entry.tokens_in
            row["tokens_out"] += entry.tokens_out
            row["cost_usd"] += entry.cost_usd
        return [
            {
                **row,
                "cost_usd": format(row["cost_usd"], "f"),
            }
            for _, row in sorted(rows.items())
        ]


class _GatewayComposer:
    """The NarrativeComposer a service drafts through: bound to
    one profile, one case, one purpose, so every compose() call
    ledgers against the right case with the right label."""

    def __init__(
        self,
        gateway: ModelGateway,
        resolved: _ResolvedProfile,
        case_id: str | None,
        purpose: str,
    ) -> None:
        self._gateway = gateway
        self._resolved = resolved
        self._case_id = case_id
        self._purpose = purpose
        self.profile_name = resolved.definition.profile_id

    def compose(self, draft: StatementDraft) -> str:
        return self._gateway._compose(
            self._resolved, self._case_id, self._purpose, draft
        )
