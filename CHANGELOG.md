# Changelog — AML Alert Investigation & Case File Agent

## 1.0.0 — 2026-10-25

The blueprint at v1.0: the full twenty-round build, frozen by a
release-hardening pass (R20) that re-ran every gate on the finished
tree — the full test suite on the default profile and on
PostgreSQL 16 with parity graded at zero gap, the eval gate on
both profiles with every scenario reporting, the production smoke
walking a case over HTTP to a sealed, offline-verified export, and
the demo running exactly as the README describes. The README and
architecture docs were audited claim by claim against the code;
the gaps that remain are stated in the README's Honest status
section and are unchanged by this release: screening lists and
the adverse-media corpus are stand-ins for licensed feeds, the
monitoring system is a port with a reference feed, live-model
drafting is adapter-complete and stub-tested with no live key
wired, no SAR is ever filed by this system, and the Docker image
build is graded statically rather than run (no Docker daemon in
the build sandbox).

### The twenty rounds

- **R1 — Core.** Case model and LangGraph state machine with a
  lawful-transition table; alert intake port with a reference
  feed; hash-chained evidence store on S3-compatible storage;
  append-only audit log; case store behind a port (PostgreSQL /
  SQLite / in-memory) with numbered migrations; FastAPI surface
  with `/health` and `/readiness`.
- **R2 — Screening.** Sanctions/PEP/adverse-media lists as
  immutable, content-hashed, version-pinned snapshots; pinned
  screening runs; delta re-screening of open cases on a new list
  version with stale flags; an unresolved sanctions hit blocks a
  plain close.
- **R3 — Typology engine.** Transactions enter only as
  evidence-backed batches; five deterministic checks in code
  (structuring, velocity, dormancy-then-burst, round-amount,
  rapid in-out) over exact Decimals under immutable, versioned
  rule packs; runs idempotent by input fingerprint.
- **R4 — Investigation graph.** Assemble → draft →
  counter-search → compose → verify → persist; findings are
  statements plus citations that must resolve to a specific
  element of a specific evidence item; facts, labelled
  hypothesis, and open questions kept separate; records are
  versioned, hash-chained evidence.
- **R5 — Disposition gate.** The analyst's decision as an
  append-only artefact: named analyst, coded role, five coded
  outcomes, coded rationale from a versioned vocabulary, a
  citation to the current investigation record; adverse closures
  park for a second-line reviewer's confirmation (dual control).
- **R6 — SAR narrative drafting.** Narrative composed over the
  current record through the model port (deterministic offline
  composer by default); a citation verifier in code re-resolves
  every statement's citations, figures, and asserted values; no
  SAR is ever filed by this system.
- **R7 — Dual-control approval + sealing/export.** The approver
  may be neither the dispositioning analyst nor the drafter;
  approval completes the case file; a named officer seals a
  terminal file under a certified manifest, making it read-only;
  the sealed file exports as one package an offline verifier
  re-checks end to end; legal hold is first-class and no purge
  path exists.
- **R8 — Regulatory clocks.** Filing deadlines in code from the
  initial-detection date (30-day, 60-day outer where no subject
  is identified — identification derived, never asserted);
  derived clock states; no-file endings documented by the
  standing disposition's coded rationale; continuing-activity
  clocks (90/120-day) started at intake; escalation crossings
  recorded on the evidence chain.
- **R9 — Continuing-activity reviews.** Per-cycle reviews
  assembling the window's activity under the same citation
  resolver; a coded continuation assessment derived in code; a
  named analyst's disposition per cycle — file-continuing routes
  through the R5 gate into SAR drafting, no-file is documented
  by coded rationale; only a recorded disposition answers the
  clock; cycles chain, rolling 90/120.
- **R10 — Injection defences.** A deterministic scanner
  (versioned pattern pack) runs over untrusted text at
  ingestion; matches are quarantined as case events on the hash
  chain with exact spans, never rejected and never obeyed;
  composers receive the text only fenced; verifiers ground
  against the span-masked token set, so a figure inside an
  instruction grounds nothing.
- **R11 — KYC profile assembly + counterparty views.** A
  profile view derived in code from stored artefacts only, each
  fact sourced, conflicts shown never merged; KYC freshness
  against a versioned policy; counterparty aggregates in exact
  Decimals with shared-counterparty links computed exactly.
- **R12 — Adverse media.** A recall-oriented source port
  (reference corpus shipped; a production deployment wires a
  licensed news database); articles enter only as evidence
  through the quarantine scanner; relevance scored in code by a
  deterministic, versioned scorer — never a model, never
  embeddings; hard identifier/DOB contradictions clear as
  namesakes with the reason recorded; media is findings-path
  only.
- **R13 — Model gateway + cost ledger.** Profiles as governed
  data (`offline`, `hosted-frontier`, `in-boundary`) behind a
  fail-closed loader — no fallback anywhere; a versioned price
  table; every call ledgered, including refused-output calls; a
  per-case budget cap refuses live calls before transport, with
  the refusal recorded three ways.
- **R14 — Analyst console.** One static HTML file at
  `/console`: the queue as a join of cases, clock board, and
  quarantine queue; the workspace rendering the whole file in
  analyst order; action surfaces that are exactly the human
  gates, with vocabularies served by the API; no markup sink
  anywhere in the file.
- **R15 — Trap suite.** Twenty graded adversarial fixtures:
  namesakes, stale lists, typology threshold edges graded on
  both sides, clock traps, gate traps, a second injection
  family, data traps. Two genuine defects found and fixed —
  dual control compared person ids as raw strings (identity now
  compares in canonical form at both gates), and altered
  transaction re-delivery could orphan a batch (an identity
  pre-check now refuses the whole delivery).
- **R16 — Postgres profile + production smoke.** The entire
  suite runs against a real PostgreSQL 16 with parity graded at
  zero gap; migrations graded from an empty database and on
  re-run; `scripts/prod_smoke.py` walks the seeded structuring
  case over HTTP through twenty asserted steps, intake to a
  sealed, offline-verified export. Parity caught two real
  defects, both fixed in the owning modules.
- **R17 — Management reporting.** A pure, content-addressed
  report pack derived from the stored artefacts: queue ageing,
  the clock board with windowed deadline performance (a late
  documented no-file counts late, never satisfied), rubber-stamp
  metrics from the draft-vs-final diffs with their limits
  stated in the artefact, and operations rollups — measurements
  only, no scores.
- **R18 — Access control.** One access module with a versioned
  role policy (L1 analyst, L2 reviewer, BSA officer,
  auditor-read-only, system); assignment as a recorded act on
  the evidence chain; read-only roles refused before gate logic;
  existence hiding — a case the caller may not read answers
  byte-identically to a case that does not exist; every refusal
  recorded as an `access_denied` audit event; the sealed export
  leaves only in a BSA officer's hands.
- **R19 — Red team.** Twenty-six attacks over the system's own
  guarantees, twenty graded in the eval gate. Thirteen held;
  thirteen exposed defects, all fixed with the attacks kept as
  regressions — per-element grounding in both verifiers
  (transposed facts no longer verify), the quarantine sentence
  boundary, named clock-nonsense violations, half-applied
  sealed assignments, and gate races serialised on per-service
  locks.
- **R20 — Release hardening.** The freeze described above:
  every gate re-run on the finished tree, the docs audited
  against the code, deployment artefacts checked, and the
  package versioned 1.0.0. No new features.
