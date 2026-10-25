<p align="center">
  <img src="https://trida.ai/logos-rounded/trida-rounded.png" alt="Trida AI" width="96">
</p>

# Blueprint — AML Alert Investigation & Case File Agent

A working prototype of the deployment a bank's financial-crime team
needs between its transaction-monitoring system and its analysts:
alerts arrive, and the agent **assembles the case file, works the
investigation to a drafted disposition, and stops**. A named analyst
decides every case. Nothing files a SAR; the agent drafts the SAR
narrative, and a second person approves it.

The design centre is the **audit-ready case file**: every statement
in every draft carries a citation to a specific piece of evidence;
every piece of evidence carries a hash and a chain-of-custody record;
regulatory clocks run in code, not in someone's calendar.

The promise is precise, and it is enforced in code, not in prompts:

- **No case closes without a named analyst's disposition.** The state
  machine has no transition into a closed state except through the
  analyst gate, with the analyst's name and a reason code recorded.
- **SAR drafting is dual-control.** The analyst who dispositions a
  case "file SAR" cannot approve its narrative, and the narrative
  cannot be marked ready until every factual statement in it resolves
  to a citation — checked by a verifier in code.
- **The model never computes money.** Totals, structuring patterns
  and threshold tests are computed in code from transaction records.
- **Evidence is immutable and hash-chained.** Corrections are new
  items; each item's hash chains to the case's previous item.

This is an independent Trida AI blueprint built around a fictional
bank, Harborline Bank. It is **not affiliated with or endorsed by
any bank or vendor**; it shows how a forward-deployed team would put
an AML investigation agent into production inside a BSA/AML program.

> **Work in progress** — this blueprint is built and passing its automated test and eval gates, but it has not yet finished hands-on local testing, and its companion blog post is not yet published. Expect changes. This notice comes off when both are done.

---

## Try it in 3 commands

```bash
make install     # uv sync --extra dev  (or: make install-pip)
make demo        # one seeded alert walked end to end, fully offline
make serve       # API on http://localhost:8000  (docs at /docs)
```

Then open a case from the reference alert feed:

```bash
curl -s -X POST localhost:8000/alerts/intake -H 'content-type: application/json' \
  -d '{"alert_id": "ALRT-2026-1001"}'
```

Or use the full stack (app + PostgreSQL + SeaweedFS evidence store):

```bash
docker compose up --build
```

## What is built at this round (R4 of 20)

- **Case model + LangGraph state machine** — states `opened →
  assembling → investigating → awaiting_analyst → closed /
  filed_sar / escalated`, with the lawful transition table enforced
  by the compiled graph; refused transitions are audited.
- **Alert intake port** with a reference feed; intake is idempotent
  per alert, stamps the initial-detection date (the anchor for every
  regulatory clock), and captures the verbatim alert payload as the
  case file's first evidence item.
- **Hash-chained evidence store** — S3-compatible object storage
  (SeaweedFS in compose) behind a port, per-item SHA-256 chained per
  case, with a verifier that recomputes every link from the stored
  blobs. No update or delete exists on the evidence port.
- **Append-only audit log** for every intake, transition, refusal,
  and evidence capture.
- **Case store behind a port** — PostgreSQL in production profile
  (numbered SQL migrations + startup runner), SQLite file locally,
  in-memory doubles for tests.
- **FastAPI surface** — `/health`, `/readiness`, alert intake, case
  reads/transitions, evidence add/list/verify, audit read; structured
  JSON logs with request and case IDs.
- **Screening on version-pinned snapshots (R2)** — sanctions/PEP/
  adverse-media lists ingested as immutable, content-hashed
  snapshots; a case's screening runs against an explicitly pinned
  set of snapshot versions and refuses to run unpinned. A new list
  version delta-re-screens open cases that ran on older pins and
  flags them stale; a case with an unresolved sanctions hit cannot
  be plainly closed — escalation is the only lawful exit.
- **Typology engine (R3)** — transactions enter a case only as
  evidence-backed batches (each batch lands on the hash chain), and
  five deterministic checks run over the stored records: structuring
  (same-day and multi-day variants), velocity against the account's
  own baseline, dormancy-then-burst, round-amount dominance, and
  rapid in-out with per-cent retention. Every figure is an exact
  Decimal computed in code — the model never computes money. Rules
  live in immutable, versioned rule packs; every finding records
  its pack version, and re-running the same pack over the same
  evidence is idempotent. The reference transaction feed ships the
  Harborline streams the seed alerts point at, planted patterns and
  clean controls included.
- **Investigation graph (R4)** — a LangGraph graph
  (assemble → draft → counter-search → compose → verify → persist)
  works a case in `investigating` into a versioned investigation
  record. Every finding is a statement plus citations that must
  resolve to a specific element of a specific evidence item
  (transaction, screening hit, typology finding, alert field,
  profile fact, prior case) — a finding whose citations do not
  resolve is refused at record time, mechanically. The record
  separates facts, the working hypothesis (labelled, naming its
  supporting *and* counter findings), and open questions (each
  naming the evidence that would resolve it). The counter-evidence
  search is a real step: named checks look for innocent explanations
  in the data — a regular cadence or documented expectation beyond
  the flagged cluster, an established counterparty, a cleared
  namesake — and record what they found either way. Narrative text
  comes through a model port whose default offline profile is a
  deterministic composer that refuses any figure not present in its
  cited inputs; a live profile is defined behind the same port and
  refuses loudly until a key is wired. Records are hash-chained
  evidence, versioned: new evidence produces the next version with
  a computed diff, the superseded version stays on the chain.

The rest of the investigation — the disposition gate, SAR narrative
+ citation verification, dual-control approval, regulatory clocks —
lands in rounds R5–R9 per the round map in `docs/architecture.md`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | _(unset)_ | Postgres case store when set; SQLite otherwise |
| `AML_SQLITE_PATH` | `./data/aml.db` | Local case-store file |
| `S3_ENDPOINT_URL` | _(unset)_ | S3-compatible evidence store (e.g. `http://minio:8333` in compose) |
| `S3_BUCKET` | `aml-evidence` | Evidence bucket |
| `OBJECT_STORE_DIR` | `./data/evidence-objects` | Filesystem object store when no S3 endpoint is set |
| `SEED_ALERTS_PATH` | `./data/seed_alerts.json` | Reference alert feed |
| `TRANSACTION_STREAMS_PATH` | `./data/transaction_streams.json` | Reference transaction feed (full-history streams) |
| `TYPOLOGY_RULES_PATH` | `./data/typology_rules.json` | Reference typology rule-pack feed |
| `MIGRATIONS_DIR` | `./migrations` | Numbered SQL migrations |
| `LOG_LEVEL` | `INFO` | Log level |

## Tests and evals

```bash
make test    # pytest — state machine, hash chain, intake, screening, typologies, investigations, API, SQL store
make evals   # eval gate — zero-tolerance counters must stay 0
```

Eval counters include: cases closed without an analyst disposition
(0), unlawful transitions accepted (0), evidence chains failing
verification (0), duplicate cases per alert (0), audit gaps (0),
screening runs accepted without a pin (0), stale screenings left
unflagged (0), planted typologies missed (0), typology false fires
on control accounts (0), typology figure mismatches (0), typology
runs not idempotent (0), findings without their rule version (0),
investigation citations failing to resolve (0), unresolvable
findings accepted at record time (0), investigation hypotheses
wrong or incomplete (0), statement figures not tracing to citations
(0), investigation re-runs duplicating records (0).

## Honest status

- Screening lists are stand-ins — real OFAC/PEP/adverse-media feeds
  are licensed integrations, wired behind the screening port in R2.
- The monitoring system is a port with a reference feed; no real
  core/monitoring vendor is connected.
- Investigation narrative (R4) runs on the deterministic offline
  composer; the live model profile is defined behind the model port
  and not yet exercised — it refuses loudly until a key is wired.
  Live-model SAR drafting (R6) follows the same pattern.
- No SAR is ever actually filed — the blueprint ends at an approved,
  sealed case file.
- The Docker image builds in CI-grade environments; the compose
  stack is the supported local full-stack path.

## Data note

The Harborline book in `data/` — customers, accounts, alerts — is
generated for this blueprint, with typologies planted by construction
so the eval gates know the right answers. It is the only dataset the
repo ships.

## License

Apache 2.0 — see `LICENSE`.
