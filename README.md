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

## What is built at this round (R17 of 20)

- **Case model + LangGraph state machine** — states `opened →
  assembling → investigating → awaiting_analyst → closed /
  filed_sar / escalated`, joined at the gate (R5) by
  `pending_confirmation`, `sar_pending`, and `monitoring`, with the
  lawful transition table enforced by the compiled graph; refused
  transitions are audited.
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
- **Disposition gate (R5)** — the analyst's decision is an
  append-only artefact, not a form field: a named analyst id and a
  coded role (anonymous and system actors are refused mechanically),
  one of five coded outcomes (close, close-under-monitoring with a
  review period, escalate to SAR drafting, escalate to the second
  line, or send back for named missing evidence), and coded
  rationale from a versioned vocabulary — free text may supplement
  the codes, never replace them. The disposition must cite the
  investigation-record version it relied on, and only the current
  record may be cited; when a newer record supersedes the cited one
  the case is flagged `DISPOSITION_STALE` until a fresh disposition
  answers it. An unresolved sanctions hit blocks both closing
  outcomes at the gate, on the same definition the state machine's
  close guard uses. And an adverse closure is dual-control: closing
  a case whose hypothesis is adverse parks it in
  `pending_confirmation` until a second-line reviewer — never the
  dispositioning analyst — confirms; a decline sends the case back
  to investigation with the refusal kept in history. Dispositions
  and confirmations sit on the evidence hash chain like everything
  else, and the confirmation and escalation work queues are read
  straight from the gate's records.
- **SAR narrative drafting + citation verifier (R6)** — for a case
  the gate has routed to `sar_pending`, the drafting service
  assembles the SAR narrative from the current investigation
  record: subject identification, activity summary, chronology,
  amounts and instruments, branch facts where the evidence holds
  them, and a "what remains unknown" section that must carry every
  open question in the record. Drafting is refused — with the
  reason named — unless the case stands in `sar_pending` on a
  current `escalate_sar` disposition, the record identifies its
  subject, and a typology finding carries a flagged total the
  narrative can state (the drafting side never totals transactions
  itself). Text is composed through the model port — the
  deterministic offline composer by default; a live profile refuses
  loudly until a key is wired. Then the **citation verifier**, in
  code over the finished text, re-resolves every statement's
  citations, figures, and asserted values against the cited
  evidence: a statement that cannot be verified is named, and the
  narrative cannot stand as verified while any statement fails.
  Drafts are versioned artefacts on the hash chain with derived
  standing — a verified narrative whose record is superseded drops
  back to stale. The round ends at a verified draft: approval is a
  second person's act (R7), and **no SAR is ever filed by this
  system**.
- **Dual-control approval + sealing/export (R7)** — the verified
  narrative is decided by a second person, mechanically: the
  approver may be neither the analyst who recorded the
  `escalate_sar` disposition nor the actor who drafted the
  narrative (either match is a named refusal, not a warning), and
  only a narrative standing verified over the case's current
  record can be decided at all. Approval completes the case file
  (`filed_sar`); rejection requires coded reasons from a versioned
  vocabulary and returns the narrative to drafting standing — the
  answer to a rejection is a re-draft, never a second decision on
  the same version. A named officer then **seals** a terminal case
  file: the seal re-verifies the evidence chain, certifies a
  manifest over every evidence item plus the operative artefacts
  (record, dispositions, narrative, verification, approval) by id
  and version, and makes the case read-only — every mutating path
  refuses on it with the one named reason. The sealed file exports
  as a single package that an offline verifier re-checks end to
  end, naming any altered, dropped, or added item. Unsealing is an
  officer's coded act; the seal history is append-only, and a
  reseal is the next seal version. Legal hold is placed and
  released the same way: it blocks archive seals, is stated on the
  seal's retention metadata (the BSA five-year posture), and there
  is no purge path anywhere in the system for it — or anything —
  to unblock. Approval and sealing end at an approved, sealed case
  file: **no SAR is ever filed by this system**.
- **Regulatory clocks + escalation (R8)** — Law 6 runs in code,
  not in someone's calendar. Every case carries a filing clock
  computed from its initial-detection date: the SAR deadline is
  detection + 30 days, and where the record identifies no
  subject, the 60-day outer limit governs instead — whether a
  subject is identified is derived from the record (the alert
  payload's subject facts, or a corroborated screening hit),
  never asserted by an analyst. Clock states are derived at the
  date you ask about — on track, due soon, due, overdue — and a
  clock ends satisfied at `filed_sar`, or closed-no-file when
  the analyst gate's standing disposition documents the
  decision: the clock names that disposition, whose coded
  rationale is the no-file documentation. A terminal case with
  no disposition anywhere is reported as a clock violation, not
  passed over. When a new alert opens for a customer with a
  prior filed case, intake starts a continuing-activity clock
  on the new case (review due at the prior determination + 90
  days, filing due at + 120). Escalation is a case event: the
  first time a clock is found due or overdue for a deadline,
  the crossing is recorded on the case's evidence chain —
  idempotently, so re-computation never duplicates it — and
  the escalation queue and clock board read the same
  derivation, most urgent first, each entry naming its
  deadline.
- **Continuing-activity reviews (R9)** — the workflow that
  answers the clock above. For each cycle, a review assembles
  the window's activity over the linked case's current
  investigation record: the prior filing's facts, the cases
  and alerts opened since the determination, the transactions
  posted in the window, the record's hypothesis and typology
  findings restated verbatim, and the screening state — every
  item cited under the same CitationResolver as the record
  itself, and verified at a gate before the review is stored.
  Whether the activity continues the filed typology is a coded
  assessment derived in code, never a free-text claim. A named
  analyst then decides the cycle: file_continuing mints an
  escalate_sar disposition through the R5 gate, and the
  continuing narrative that follows opens by citing this
  review and the prior filing; no_file_this_cycle is
  documented by coded rationale and starts the next cycle from
  its own decision date — rolling 90/120, chained by review
  id. Only the recorded disposition answers the clock: a
  review opened but not dispositioned satisfies nothing, and
  past the filing deadline the unanswered cycle escalates as
  overdue. One open review stands per cycle; a review whose
  record has moved stands stale and is superseded by a fresh
  one, never edited.
- **Injection defences + quarantine (R10)** — Law 7 in code.
  Text that arrives from outside the bank — transaction memos
  and counterparty names, alert summaries and payload fields,
  screening subject and list-entry names, uploaded documents —
  is untrusted by construction, and some of it will eventually
  be written by someone who knows an AI reads the case file. A
  deterministic scanner (a versioned pattern pack covering
  instruction-override phrases, role-play and system-prompt
  markers, directives aimed at the case workflow, output
  dictation, and encoded payloads) runs over that text at
  ingestion. A match never rejects the evidence — evidence is
  evidence. It records a **quarantine event** on the case's
  hash chain naming the item, the field, the pattern, and the
  exact span: the injection attempt becomes a case event an
  analyst can see. Everywhere the text is consumed, the
  matched spans are fenced — composers receive the value with
  each span replaced by a fence marker, never as bare prose a
  model could follow — and the record, narrative, and review
  verifiers compute their groundable token set with the spans
  masked out, so a figure planted inside an instruction
  grounds nothing however it is cited. The guarantees are
  graded, not asserted: payloads planted in memos and an
  alert summary leave the investigation record byte-identical
  to the clean run and change no case state, and the SAR
  narrative follows none of the injected imperatives. A named
  analyst may mark a quarantine record reviewed from the
  quarantine queue — an audit act recorded on the chain that
  never un-fences anything; the fences derive from the
  append-only record itself and are permanent.
- **KYC profile assembly + counterparty views (R11)** — the
  analyst no longer re-gathers what the bank already knows. A
  **profile view** is assembled in code from stored artefacts
  only — alert payloads on case chains, screening runs and
  hits, account profiles, transaction records, dispositions,
  approvals; nothing in it is hand-entered. Identity facts each
  carry the artefact they were read from, and **conflicts are
  shown, never merged**: two dates of birth on record both
  stand, flagged `identity_conflict`, with no winner picked.
  The view also carries the customer's accounts, their full
  case history with disposition standing and SAR outcomes,
  their screening history per list and version — including
  namesake clearances with the reason they were cleared — and
  **KYC freshness**: when each fact class was last
  corroborated, with stale classes named against a versioned
  freshness policy. The view is a derived artefact:
  content-addressed, append-only versions, rebuilding over
  unchanged inputs returns the stored view. The R4
  investigation consumes the assembled view for its profile
  facts when one exists, capturing it on the case's chain so
  the record's profile citations resolve to it. **Counterparty
  views** aggregate the customer's stored transactions in code
  (Decimal totals in and out, counts, first/last seen, the
  name's screening state across the store) and compute the
  **shared-counterparty links** exactly — a counterparty
  standing on more than one customer's cases is a network
  signal, not an anecdote. Counterparty names are rendered
  through R10's quarantine fencing; the stored values are
  never touched by a fence.
- **Adverse media (R12).** A recall-oriented source port (in
  production, a licensed news database; here, a labelled
  reference corpus) returns candidate articles for a case's
  subject, and every article enters the case only as an
  evidence item that passes the quarantine scanner like any
  other untrusted text — an instruction planted in an article
  body quarantines and fences exactly as one in a memo does.
  Relevance is scored in code, never by a model: name-match
  strength from the screening matcher, disambiguation signals
  read against the assembled customer profile (identifier,
  date of birth, stated age, geography, occupation,
  associated entities — each recorded with its contribution),
  and adverse categories from a versioned keyword taxonomy
  with the matched terms named. A name match contradicted by
  the profile's date of birth lands in the `namesake_cleared`
  band with the contradiction stated — screening's namesake
  discipline, carried into media. Assessments are
  append-only, pin the scorer and taxonomy versions and the
  profile version used, and surface in the investigation
  record as cited findings with their band stated; media
  never dispositions a case and never moves its state.
- **Model gateway + cost ledger (R13).** Every drafting call
  now goes through a gateway whose profiles are governed data,
  not code branches: `offline` (the deterministic composer),
  `hosted-frontier` (a hosted frontier model over the Anthropic
  Messages API), and `in-boundary` (an open-weight model served
  inside the bank's boundary over an OpenAI-compatible
  endpoint). Loading is fail-closed — a duplicate profile id, a
  live profile with no endpoint, a model with no price entry,
  or a malformed price refuses the configuration outright —
  and selecting an unknown or unconfigured profile refuses
  loudly at call time. There is no fallback anywhere: the
  gateway never substitutes one profile for another. The live
  adapters are real HTTP clients (exercised against stub
  transports in the tests and evals), and their text passes the
  same figure gate offline text does. **Every call is priced
  and ledgered** — case, purpose (`record_draft`, `sar_draft`),
  profile, model, tokens and their basis (provider-reported, or
  the adapter's stated estimate), the versioned price table's
  unit prices, and the exact Decimal cost — offline calls
  included, at zero. A per-case budget cap (configuration)
  refuses further live calls for a case whose spend reaches
  it, *before* any transport is touched; the refusal is
  recorded as a ledger budget event, a case audit event, and
  an item on the case's hash chain, and the caller may still
  finish the case on the offline profile — named by the
  caller, never switched to silently. Rollups read per case
  (by purpose and by profile, with the budget position) and
  per day across the portfolio.
- **Analyst console (R14).** The analyst's working surface is
  one static HTML file served by the app at `/console` —
  inline CSS and vanilla JS, no build step, no framework —
  following the portfolio console standard (light theme, the
  Trida footer). The queue joins the case list to the clock
  board and the quarantine queue, so every row carries its
  filing-clock state and deadline, its continuing-review due
  state, and its quarantine badges, sortable by clock urgency.
  The workspace renders the whole file in analyst order: the
  alert, the regulatory clocks, the KYC profile with identity
  conflicts standing as conflicts, the hash-chained evidence
  with quarantined items fenced and badged, screening against
  its pinned snapshots, transactions, typology findings, the
  investigation record with its citations, media assessments,
  and the case's priced model ledger. The action surfaces are
  the human gates themselves — disposition, confirmation of an
  adverse close, SAR approval or rejection, quarantine review,
  continuing-review disposition — each a form built from the
  coded vocabularies the API serves at `/vocabulary`, carried
  under an analyst identity the console requires before it
  will submit, and every gate refusal renders as the plain
  error text the API returned. The console adds no write path
  of its own (the eval gate scans every call it makes against
  the app's route table), and it renders everything as text:
  the file holds no markup sink, so a memo carrying a script
  is displayed as the data it is, never executed.
- **Trap suite (R15).** Eval depth as adversarial fixtures
  with hand-computed expectations, graded in the test suite
  and as eval counters (scenario 18, every failure counter
  zero-tolerance). *Namesakes*: same name and city with a
  contradicting date of birth clears with the reason recorded;
  the same name and DOB with a merely different identifier
  stays strong and open — in screening and in media scoring
  alike; middle-name and alias variants match by the stated
  rules; an entry that exists only in list v2 flags the
  v1-screened case `STALE_SCREENING` and surfaces only on a
  deliberate re-screen. *Threshold edges*: every typology
  boundary graded on both sides — 9,999.99 is structuring
  material and 10,000.00 is not, velocity 4.9× is quiet and
  5.0× fires, a 179-day dormancy is quiet and 180 fires,
  round-amount share just under half is quiet and exactly
  half fires, 89% pass-through is quiet and 90% fires.
  *Clocks*: leap-day and plain-year deadline arithmetic, a
  strong hit flipping the operative deadline while a cleared
  namesake identifies nobody, a no-file decision recorded
  after the deadline standing documented *and* visibly late
  on the clock's face, a continuing clock anchored on a prior
  determination that was itself late. *Gates*: a disposition
  citing the current record id with a superseded version is
  refused; a seal attempted over a chain with a gap introduced
  by direct store manipulation is refused at seal time.
  *Injection, second family*: an instruction split across two
  memos (each half scans clean alone — the scanner is
  field-scoped, a boundary this round states rather than
  hides) changes nothing; a payload in a counterparty name is
  fenced in the profile view and in the console's API data;
  a payload in a media headline is quarantined and never
  composed. *Data*: an alert payload name that disagrees with
  the profile's name stands as a conflict with both sources.
  Two traps found genuine defects, both fixed with the trap
  kept as the regression: dual control compared person ids as
  raw strings, so the dispositioner could confirm their own
  closure — or the drafter approve their own narrative — by
  re-casing their id (identity now compares in canonical form
  at both gates); and transaction ingestion wrote its batch
  record before storing transactions, so a re-delivered batch
  with one amount altered orphaned a batch a retry silently
  honoured (a stored id re-used with different content is now
  refused whole, before anything is written, and identical
  re-deliveries dedupe).

- **R16 — the Postgres production profile, proven.** Until now
  the SQL adapter was sampled: the suite ran on the in-memory
  double with one SQLite replay per domain. R16 runs the
  *entire* suite against a real PostgreSQL 16 — a parity mode
  (`AML_TEST_DATABASE_URL`, see `tests/pg_parity.py`) swaps
  every store construction for a Postgres store over its own
  migrated schema, reopen tests included: **389 passed, the
  same count as the default profile**. The migration runner
  is graded on an empty Postgres database (0001–0011 apply in
  order; a re-run applies nothing), and a production smoke
  (`scripts/prod_smoke.py`) boots the real app on a fresh
  database and walks the seeded structuring case over HTTP
  through all 20 lifecycle steps — intake to a sealed,
  offline-verified export — asserting state at each one. The
  eval gate carries the three legs as Scenario 19 when a
  server is provided, and counts the skip when none is.
  Parity caught two real defects, both fixed at the owning
  layer: the migration runner read its own ledger in a way a
  dict-row Postgres connection raises on (a migrated database
  could not be reopened), and four migrations had drifted to
  `JSONB` payload columns against the store's JSON-text
  contract (the columns are `TEXT` now, both dialects alike).

- **R17 — management reporting, derived in code.** A versioned
  report pack (`2026.10.1`) computed from the stored artefacts
  at a named `as_of` — a pure read-model in the clocks'
  discipline: nothing is stored, and the pack is
  content-addressed, so the same artefacts at the same date
  rebuild the same pack byte for byte. Four sections, each
  naming the store reads its figures came from, with the pack
  counting the artefacts it was derived from. *Queue ageing*:
  open cases by status × age bucket, by rule and severity, the
  oldest cases, and the two queues that wait on named humans —
  pending confirmations (waiting on an L2 reviewer, the
  dispositioning analyst named from the record) and SAR-pending
  cases by stage (drafting, citation verification, dual-control
  approval). *Clock board*: the R8 clocks portfolio-wide, the
  overdue list, and deadline performance over a window — a
  documented no-file decision recorded after its deadline
  counts as LATE here, never as satisfied, the R15 honesty
  carried through unchanged. *Rubber-stamp metrics* (Law 8's
  payoff): findings added / removed / changed between the
  first composed investigation record and the version the
  disposition was decided on; SAR narratives approved without
  any edit vs after a re-draft, with the draft-to-approved
  distance in stated bands; confirmation patterns at the
  adverse-close gate, including a per-analyst confirmation-rate
  table; and decision-latency distributions (median / p90) at
  the three gates. Measurements only — the section states in
  words what it measures and what it cannot (it cannot show
  whether anyone read the evidence, or whether a decision was
  right), and it scores and ranks nobody. *Operations*:
  typology finding volume by check and rule-pack version,
  screening outcomes by list version with namesake clearances
  counted separately, quarantine counts by pattern family,
  the media band distribution, and model spend by profile and
  purpose from the R13 ledger. Served at `GET /reports/pack`
  (plus one route per section), from the CLI (`report-pack`
  and friends), and in the analyst console's new Reports view
  — read-only everywhere; the console gains no write path.
  The eval gate grades the pack against a hand-computed
  fixture book as Scenario 20 (every headline figure, the
  late-counts-late rule, and the rubber-stamp metrics are
  zero-tolerance).

The rest — access control, the red team, and release
hardening — lands in R18–R20 per the round map in
`docs/architecture.md`.

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
| `ADVERSE_MEDIA_PATH` | `./data/adverse_media.json` | Reference adverse-media corpus (stand-in for a licensed news database) |
| `MODEL_PROFILES_PATH` | `./data/model_profiles.json` | Model gateway profiles + per-case budget cap (R13), validated fail-closed at startup |
| `MODEL_PRICES_PATH` | `./data/model_prices.json` | The versioned model price table (R13) — governed reference data |
| `AML_MODEL_PROFILE` | `offline` | The deployment's own model profile; resolved at startup — unknown or unconfigured refuses the boot |
| `ANTHROPIC_API_KEY` | _(unset)_ | Key for the `hosted-frontier` profile; unset means that profile is unconfigured and refuses loudly |
| `ANTHROPIC_BASE_URL` | `https://api.anthropic.com` | Endpoint override for the `hosted-frontier` profile |
| `IN_BOUNDARY_MODEL_URL` | _(unset)_ | The bank-boundary model server's base URL for the `in-boundary` profile; unset means unconfigured |
| `IN_BOUNDARY_MODEL_API_KEY` | _(unset)_ | Key for the `in-boundary` endpoint, when that server requires one |
| `MIGRATIONS_DIR` | `./migrations` | Numbered SQL migrations |
| `LOG_LEVEL` | `INFO` | Log level |

## Tests and evals

```bash
make test    # pytest — state machine, hash chain, intake, screening, typologies, investigations, dispositions, SAR narratives, approvals, sealing, regulatory clocks, continuing reviews, quarantine, KYC profiles, counterparties, adverse media, model gateway, analyst console, management reporting, the trap suite, API, SQL store
make evals   # eval gate — zero-tolerance counters must stay 0
```

The Postgres profile (R16) is graded, not assumed. With a
server available:

```bash
AML_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5433/aml_parity make test
# the entire suite on the Postgres adapter — same 389 passes
DATABASE_URL=postgresql://postgres@127.0.0.1:5433/aml_parity make prod-smoke
# the real app on a fresh database, 20 lifecycle steps over HTTP
AML_EVAL_DATABASE_URL=postgresql://postgres@127.0.0.1:5433/aml_parity make evals
# Scenario 19 grades migrations, the smoke, and suite parity
```

Without a server, the Postgres tests skip (counted) and the
eval gate counts Scenario 19 as skipped — never silent.

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
(0), investigation re-runs duplicating records (0), anonymous or
system dispositions accepted (0), dispositions without an
investigation record accepted (0), sanctions-blocked closures
accepted (0), self-confirmations accepted (0), free-text-only
rationale accepted (0), stale dispositions left unflagged (0),
superseded-record citations accepted (0), disposition positive
paths failed (0), SAR self-approvals accepted (0),
dispositioner-approvals accepted (0), unverified or stale
narrative approvals accepted (0), mutations of a sealed case
accepted (0), tampered exports passing verification (0),
seals with an incomplete manifest accepted (0), wrong clock
deadlines computed (0), wrong clock boundary states (0),
overdue clocks missing from the escalation queue (0), ended
clocks still escalated (0), duplicate escalation events
recorded (0), terminal cases without a disposition going
undetected by the clock (0), continuing clocks satisfied
without a recorded review disposition (0), second concurrent
reviews accepted (0), reviews with uncited window activity
accepted (0), no-file cycles without coded rationale
accepted (0), broken continuing cycle chains (0), injected
instructions changing an investigation record (0), alert-summary
payloads reaching a record unfenced (0), injected imperatives
followed in a SAR narrative (0), payloads without a quarantine
event (0), quarantined spans grounding a figure (0), injected
instructions changing case state (0), quarantine false positives
on ordinary banking prose (0), reviews un-fencing quarantined
content (0), namesakes graded strong in media screening (0),
media changing a case's state (0), article instructions left
unquarantined (0), uncited media claims in a record (0), and
media relevance bands wrong on the graded corpus (0), model
calls without a priced ledger entry (0), silent profile
fallbacks accepted (0), budget-breaching calls reaching the
transport (0), ledger costs not matching tokens × price
(0), console queue inputs disagreeing (0), console workspace
artefact kinds missing (0), console-only write paths (0),
unescaped render paths in the console (0), and console
positive paths failing (0). With a Postgres server provided,
the gate adds: Postgres migration failures (0), production
smoke step failures (0), and suite outcome gaps between the
Postgres and default profiles (0).

## Honest status

- Screening lists are stand-ins — real OFAC/PEP/adverse-media feeds
  are licensed integrations, wired behind the screening port in R2.
- Adverse media runs on a reference corpus behind the port. The
  scoring, the quarantine discipline, and the findings path are
  real; a production deployment wires a licensed news database
  to the port, and no shipped article is real reporting.
- The monitoring system is a port with a reference feed; no real
  core/monitoring vendor is connected.
- Investigation narrative (R4) and SAR narrative drafting (R6)
  run on the deterministic offline composer by default. The
  gateway's live profiles (R13) are real adapters behind the
  model port, exercised against stub transports with
  provider-shaped responses; no live key is wired in this repo,
  so a live profile selected without its endpoint/key refuses
  loudly — it is never silently replaced by the offline
  composer. Prices in `data/model_prices.json` are governed
  reference data with a stated basis and as-of date, maintained
  by the deployment.
- No SAR is ever actually filed — the blueprint ends at an approved,
  sealed case file. As of R10 the line stops exactly there: a
  narrative approved under dual control, its case file sealed and
  exportable, the export verifiable offline — every case carrying a
  regulatory clock that says, in code, whether the file is on time,
  due, overdue, satisfied, or documented as a no-file decision —
  for a returning subject, a continuing-activity review per
  cycle that answers that clock with cited window activity and a
  named analyst's coded decision — and every piece of untrusted
  text on the file scanned at ingestion, with anything that reads
  as an instruction quarantined on the chain and fenced out of
  every composer and verifier that touches it — the whole file
  readable in the analyst console (R14), which renders it as
  text and acts on it only through the same gated routes.
- The Postgres production profile is verified (R16): the full
  test suite passes unchanged on PostgreSQL 16 (389 tests,
  parity-graded in the eval gate), the migrations apply and
  re-run cleanly on an empty database, and the production
  smoke walks a case end to end over HTTP on a fresh database.
  The Docker image build itself was not run in the build
  sandbox (no Docker daemon there) — the Dockerfile and
  compose contracts are graded statically
  (`tests/test_docker_contract.py`), and the compose stack
  remains the supported local full-stack path.

## Data note

The Harborline book in `data/` — customers, accounts, alerts — is
generated for this blueprint, with typologies planted by construction
so the eval gates know the right answers. It is the only dataset the
repo ships.

## License

Apache 2.0 — see `LICENSE`.
