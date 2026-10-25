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
Rounds R2–R20 fill in the investigation stages behind the same case
and evidence model; the round map is at the bottom of this document.

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

## Stores and migrations

The `CaseStore` port has one SQL implementation used over SQLite
(local default, `./data/aml.db`) and PostgreSQL (when `DATABASE_URL`
is set), plus an in-memory double for tests. Payloads are JSON text
in both dialects; filterable columns (status, severity, detection
date) are broken out. Schema changes are numbered SQL files under
`migrations/<dialect>/`, applied in order by the startup runner and
recorded in `schema_migrations`. Later rounds add: screening
snapshots (R2), LangGraph checkpointing on Postgres, pgvector for
adverse-media similarity (R12), and the clock/scheduler tables (R8).

## Ports

| Port | Production adapter | Local/test double |
|---|---|---|
| `AlertSource` | monitoring-platform feed (deployment-specific) | reference JSON feed |
| `CaseStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `ObjectStore` | S3-compatible (SeaweedFS in compose) | local filesystem |

Screening (R2), model gateway (R13), and adverse media (R12) arrive
as further ports behind the same discipline: decisions in code,
citations on everything, untrusted input quarantined (Law 7).

## The eight laws, as a checklist

1. No case closes without a named analyst's disposition — state
   machine + disposition guard (R1) ✓
2. SAR drafting is dual-control; narrative statements must resolve to
   citations, verified in code — R6/R7.
3. Screening is version-pinned; new list versions trigger delta
   re-screening of open cases — R2.
4. The model never computes money; typologies are code — R3.
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
