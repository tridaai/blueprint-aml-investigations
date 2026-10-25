# Architecture — AML Alert Investigation & Case File Agent

Blueprint #15 · Banking / Financial Crime (BSA/AML) · fictional bank:
Harborline Bank.

## The shape of the system

```
monitoring system ──(AlertSource port)──▶ intake ──▶ case opened
                                                        │ detection date stamped
                                                        ▼
                              evidence assembly ──▶ hash-chained evidence store
                                                        │ (ObjectStore port)
                                                        ▼
                              screening (R2) ──▶ typology engine, in code (R3)
                                                        ▼
                              investigation graph (R4): cited findings
                                                        ▼
                              disposition recommendation ──▶ ANALYST GATE
                                                        ▼
                              SAR narrative (R6) ──▶ citation verifier
                                                        ▼
                              SECOND-PERSON APPROVAL (R7) ──▶ sealed case file
```

At R1 the spine exists end to end: intake, the case state machine,
the evidence store with its hash chain, the audit log, and the API.
R2 added screening on top of it: version-pinned list snapshots,
delta re-screening, and the sanctions must-escalate guard. R3 added
the typology engine: evidence-backed transaction ingestion and five
deterministic money-computation checks under versioned rule packs.
Rounds R4–R20 fill in the remaining investigation stages behind the
same case and evidence model; the round map is at the bottom of
this document.

## Case state machine (LangGraph)

States: `opened`, `assembling`, `investigating`, `awaiting_analyst`,
`escalated`, `closed`, `filed_sar`. The lawful edges:

| From | To |
|---|---|
| opened | assembling |
| assembling | investigating |
| investigating | awaiting_analyst, escalated |
| awaiting_analyst | investigating (send-back), escalated, closed, filed_sar |
| escalated | investigating, awaiting_analyst |
| closed, filed_sar | — (terminal) |

The compiled LangGraph graph is the executor: its nodes are the
states, the entry router sends a run to the node for the case's
current state, and that node validates the requested transition
against the table and applies the guards. One invocation applies one
transition; the case store persists the result, which keeps every
step resumable and individually auditable.

**Law 1 (no close without an analyst).** The only edges into
`closed`/`filed_sar` start at `awaiting_analyst`, and both require a
`Disposition` — analyst name, decision, reason code — whose decision
matches the target. A refusal raises `IllegalTransitionError` and is
written to the audit log as `transition_refused`. The eval gate
probes every non-gate state with disposition-less close attempts;
the counter must stay 0.

## Evidence store and the hash chain (Law 5)

Evidence content lives in an object store behind the `ObjectStore`
port (S3-compatible; SeaweedFS in compose, filesystem locally). The
port exposes `put`/`get` only — there is no update or delete, so an
item, once captured, cannot be edited; a correction is a new item.

Each item's metadata (in the case store) records:

- `content_sha256` — SHA-256 of the blob;
- `prev_hash` — the previous item's chain hash on the same case;
- `chain_hash = sha256(prev_hash | content_sha256 | case_id | seq | kind)`,
  with the literal `GENESIS` as the first item's predecessor.

`verify_chain` recomputes every link from the stored blobs, so blob
tampering, metadata tampering, reordering, deletion, and a forged
case head hash all fail verification. The case record carries
`evidence_head_hash` plus BSA retention fields (`retention_until`,
`legal_hold`).

## Screening: version-pinned snapshots (Law 3)

Sanctions, PEP, and adverse-media lists enter the system only as
**snapshots**: an immutable, versioned bundle of entries with a
publisher version label, a publication timestamp, and a SHA-256
content hash computed at ingest over the canonical entries. The
ingest path is the only write path, and it enforces immutability —
re-ingesting the same kind + version with identical content is an
idempotent no-op; with different content it is refused. A corrected
list is a new version, never an edit.

A **screening run** screens a case's subjects (the customer, known
aliases, and counterparties found in the alert payload — fuller KYC
subject assembly arrives in R11) against an **explicitly pinned
snapshot set** (list kind → version). There is no "screen against
current" mode: a run without a pin is refused, and every run records
its pins, its subjects, and its hits as a hash-chained
`screening_result` evidence item on the case. The case record keeps
a per-list `screened_against` entry naming the snapshot version each
list was last screened at, so the file always answers "screened
against what, when."

**Name matching is deterministic** — no model, no embeddings.
Names are normalised (Unicode decomposition, diacritics stripped,
lowercased, punctuation removed, tokenised) and scored by ordered
rules: exact sequence 1.00, same token set 0.95, token subset 0.85,
token overlap (Jaccard ≥ 0.5, ≥ 2 shared tokens) at the Jaccard
value. Subject and entry aliases are surfaces in the same matching.
Dates of birth and identifiers then resolve the match:

- a shared identifier, or a matching DOB, makes the hit **strong**;
- a name match with a **contradicting DOB** is the namesake trap:
  it is recorded as a *cleared* hit with reason
  `date_of_birth_mismatch` — visible on the record, never silently
  dropped, and it never blocks the case;
- an analyst can clear or confirm any hit, with a reason that stays
  on the hit and in the audit log.

**Delta re-screening.** Ingesting a snapshot whose `published_at`
is newer than a version an open case was screened against flags the
case `STALE_SCREENING` (a visible flag on the case record, plus an
audit event). Terminal cases are sealed history and are never
flagged. A re-screen on the new version clears the flag; both runs
stay in the case's run history, so the file shows what the case
looked like under each list version.

**The sanctions consequence.** A case with an unresolved sanctions
hit (open or confirmed — anything not cleared) is in a
must-escalate posture: the workflow refuses a plain `closed`
transition even with a well-formed close disposition, and records
the refusal in the audit log. The lawful exits are escalate,
file_sar, or an analyst clearing the hit with a reason first. The
eval gate grades this end to end (clean on v1 → flagged on the v2
delta → hit on re-screen → close refused) with the counters
`screening_without_pin`, `stale_screening_unflagged`, and
`sanctions_close_blocked_violations` all at zero tolerance.

## Typology engine (R3) — Law 4, in code

The typology engine is the blueprint's money arithmetic, and it is
entirely deterministic code: no model computes, rounds, or estimates
a figure anywhere in this layer. A language model may later (R4)
narrate what the engine found; it never decides what the numbers
are.

**Transactions are evidence first.** A case's subject-account
transactions enter only through ingestion: each batch is stored as
transaction records and captured as a `transaction_batch` evidence
item whose content is the canonical serialization of the batch, so
the hash chain covers the exact records the engine later reads. The
engine reads only stored records — there is no path that runs a
check over ad-hoc input. The transaction feed contract is a
**full-history stream**: the account's transactions from opening,
which is what lets dormancy measure the gap from `opened_on` and
velocity build a baseline. A reference feed ships the Harborline
streams in which the R1 seed alerts' patterns are actually planted.

**Five checks**, each a pure function over the stored transactions
and the account profile, returning findings that name the exact
transaction ids involved and carry every computed figure as an exact
decimal string:

- **Structuring** — cash transactions inside the near-threshold band
  (default 9,000 to just under the 10,000 CTR threshold), aggregated
  per direction. A same-calendar-day group of at least the minimum
  count totalling at least the threshold fires as `same_day` and
  claims its transactions; overlapping multi-day windows (default 7
  days) over the remainder merge into `multi_day` findings.
- **Velocity** — the trailing observation window (default 7 days)
  against the account's own baseline (everything earlier, requiring
  at least 60 days of history). Fires on the transaction-count
  multiple (default 5×); amounts and daily rates are reported
  alongside so an analyst sees scale, not just frequency.
- **Dormancy-then-burst** — a gap of at least 180 days between
  activity boundaries (the account's opening date is the first
  boundary), followed by a burst of at least two transactions
  totalling at least 5,000 within three days of resumption.
- **Round-amount** — transactions at or above 5,000 that are exact
  multiples of the round unit (default 1,000) must also dominate:
  at least five of them, at least half the stream, at least 25,000
  in total. Any one test alone is ordinary business.
- **Rapid in-out** — each credit of at least 10,000 opens a lot;
  debits inside the following 72 hours are allocated to the oldest
  open lot first. A lot fires when at least 90% passed through, and
  the finding reports the retained remainder to the cent.

**Rule packs are versioned data.** Every threshold above lives in a
rule pack (`pack_id` + `version`), content-hashed at registration.
A pack, once registered, is immutable: changing a threshold means
registering a new version, never editing the old one — and every
finding records the pack id and version that produced it, so
findings from different versions coexist and stay distinguishable.
Runs are idempotent by construction: a run is keyed by an input
fingerprint (the stored transaction ids, their batch hashes, the
account profile, and the pack's content hash), so re-running the
same pack over the same evidence returns the existing run instead
of duplicating findings, while a new pack version produces a new,
distinguishable run. Each run's findings are also captured as a
`typology_findings` evidence item on the case.

**Negative controls are graded, not assumed.** The eval gate runs a
business that deposits 9,500 in cash every ten days for months —
inside the band every time, never aggregated — and any finding on a
control account fails the gate outright (zero tolerance), alongside
exact-set and exact-figure checks on every planted pattern.

## Stores and migrations

The `CaseStore` port has one SQL implementation used over SQLite
(local default, `./data/aml.db`) and PostgreSQL (when `DATABASE_URL`
is set), plus an in-memory double for tests. Payloads are JSON text
in both dialects; filterable columns (status, severity, detection
date) are broken out. Schema changes are numbered SQL files under
`migrations/<dialect>/`, applied in order by the startup runner and
recorded in `schema_migrations`. Migration 0002 added the screening
tables (`list_snapshots`, `screening_runs`, `screening_hits`);
migration 0003 added the typology tables (`rule_packs`,
`account_profiles`, `transaction_batches`, `transactions`,
`typology_runs`, `typology_findings`).
Later rounds add: LangGraph checkpointing on Postgres, pgvector for
adverse-media similarity (R12), and the clock/scheduler tables (R8).

## Ports

| Port | Production adapter | Local/test double |
|---|---|---|
| `AlertSource` | monitoring-platform feed (deployment-specific) | reference JSON feed |
| `CaseStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `ObjectStore` | S3-compatible (SeaweedFS in compose) | local filesystem |
| `ScreeningListSource` | licensed list feed (OFAC/PEP/media) | reference JSON feed |
| `ScreeningStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `TransactionSource` | core-banking full-history stream | reference JSON feed |
| `RulePackSource` | governed rule-pack distribution | reference JSON feed |
| `TypologyStore` | PostgreSQL via migrations | SQLite file; in-memory |

The model gateway (R13) and adverse media (R12) arrive as further
ports behind the same discipline: decisions in code, citations on
everything, untrusted input quarantined (Law 7).

## The eight laws, as a checklist

1. No case closes without a named analyst's disposition — state
   machine + disposition guard (R1) ✓
2. SAR drafting is dual-control; narrative statements must resolve to
   citations, verified in code — R6/R7.
3. Screening is version-pinned; new list versions trigger delta
   re-screening of open cases — snapshots, pins, delta flags, and
   the sanctions close-guard (R2) ✓
4. The model never computes money; typologies are code — five
   deterministic checks over evidence-backed transactions, under
   immutable versioned rule packs (R3) ✓
5. Evidence is immutable and hash-chained — evidence service (R1) ✓
6. Regulatory clocks are code (SAR 30/60-day, continuing-activity
   90/120-day) — detection date stamped at intake (R1) ✓, clocks R8/R9.
7. Prompt injection inside evidence is a case event, quarantined — R10.
8. Rubber-stamping is measured (draft-vs-final diff) — R5/R17.

## Round map (20)

R1 core: case model, state machine, ports, intake, evidence store
with hash chain · R2 screening snapshots + delta re-screening · R3
typology engine (code) · R4 investigation graph + cited findings ·
R5 disposition + analyst gate · R6 SAR narrative drafting + citation
verifier · R7 dual-control approval + sealing/export · R8 regulatory
clocks + escalation · R9 continuing-activity reviews · R10 injection
defences + quarantine · R11 KYC profile assembly + counterparty views
· R12 adverse-media port + similarity · R13 model gateway profiles +
cost ledger · R14 analyst console (static UI) · R15 eval depth:
namesake/stale-list/threshold traps · R16 Postgres profile + prod
smoke · R17 reporting: queue ageing, clock board, rubber-stamp
metrics · R18 access control: role-scoped case access, retrieval
ACLs · R19 red team: narrative-fact transposition, citation-to-passage
verification · R20 release hardening (Docker contract, docs, final
gates).
