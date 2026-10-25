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
| awaiting_analyst | investigating (send-back), escalated, pending_confirmation, sar_pending, monitoring, closed, filed_sar |
| pending_confirmation | closed (confirmed), investigating (declined), escalated |
| sar_pending | investigating, escalated |
| monitoring | investigating (review re-opens) |
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

## Investigation graph (R4) — cited findings, hypothesis discipline

The investigation graph turns what R1–R3 put on the case into an
**investigation record**: the document an analyst actually works
from. It is a second LangGraph graph — distinct from the case state
machine — that runs over a case in `investigating`:

    assemble -> draft -> counter_search -> compose -> verify -> persist

**Assembly** gathers the alert payload, the latest screening run and
its hits, the latest typology run and its findings, the stored
transactions, the customer's prior cases, and the account profile.
The profile joins the case's evidence on first assembly (kind
`account_profile`) so that profile facts are citable like everything
else; the run refuses, with a typed error, for a case that is not in
`investigating`.

**Findings are statements plus proof.** Every finding carries
citations, and a citation addresses a *specific element* of a
*specific evidence item*: `finding:<id>`, `transaction:<id>`,
`hit:<id>`, `run:<id>` (an object inside the item's JSON, found by
its id), or `field:<dotted.path>` (a field of a JSON payload). Prior
cases are cited cross-case, with the case id named. A citation
resolves only if the item exists *and* the element is inside it —
a citation to a real item naming a non-existent element is exactly
as refused as one to a missing item.

**The record separates facts, hypothesis, and open questions.** The
working hypothesis is chosen deterministically from the assembled
picture (an open sanctions hit outranks typology patterns;
structuring outranks the rest) and is labelled a hypothesis: it
names the findings that support it and the findings that cut
against it. Open questions each name the evidence type that would
resolve them — an adverse hypothesis with no source-of-funds
documentation on the file always carries that question.

**The counter-evidence search is a graph step, not a label.** For
the working hypothesis, named checks run over the stored records:
for structuring, a regular-cadence check and a documented-expectation
check over the in-band population *beyond the flagged cluster* (the
innocent explanation for a cluster is that the same deposits recur
on a documented cadence outside it); for velocity, a search of the
account's own baseline for a comparable surge plus the same
expectation test; for dormancy, the burst's size against the
documented expectation; for rapid in-out, an established-relationship
search on the counterparty; for a sanctions match, a namesake search
over the case's screening history plus the hit's corroboration
strength. Every check is recorded with its outcome — found, not
found, or not applicable with the reason — and what it covered, so a
record with zero counter-findings states what was searched. A check
that finds counter-evidence produces its own finding, cited to the
transactions or records it computed from.

**Narrative text comes through the model port** (`composer.py`).
The default `offline` profile is a deterministic stand-in composer:
it renders statements from values code computed out of the cited
records, and *refuses* a statement whose figures are not all in its
inputs. The live `hosted-frontier` profile's interface is defined
behind the same port and, until a deployment wires a key, selecting
it is a loud refusal — never a silent fall-back to offline text
under a live profile's name. The record names the profile that
produced its text. The full gateway (routing, cost ledger) is R13.

**The record gate is mechanical.** Before anything persists, the
verify node re-resolves every citation from the store, checks that
figures copied from source records appear in the cited records
(figure provenance), checks that no statement carries an
ungrounded figure, and checks the hypothesis discipline (support
and counter ids name findings of the matching direction; a
counter-search record with at least one check exists). Any failure
raises and nothing is stored. The same gate is a public method —
the eval suite poisons records with it (fake element in a real
item, missing item, uncited finding, invented figure) and requires
refusal every time.

**Records are versioned evidence.** A record is stored as an
`investigation_record` evidence item on the hash chain plus an
append-only record row. Re-running over unchanged inputs is
idempotent — an input fingerprint (alert hash, screening runs and
hit states, typology runs and findings, the transaction fingerprint,
prior-case states, source-of-funds presence) returns the existing
record. New evidence produces the next version, which supersedes
the previous in the case view while it stays on the chain; the diff
between versions (findings added / removed / changed, computed over
stable finding keys that name the pattern rather than a run's
random ids, plus whether the hypothesis moved) is computed and
stored on the new record.

## Disposition gate (R5) — Law 1, with depth

The analyst gate is a service (`dispositions.py`) standing between
the investigation record and every state the record can lead to. A
disposition is an append-only artefact — `DispositionRecord` —
never a form field on the case:

- **Identity, mechanically.** Analyst id + coded role
  (`analyst | senior_analyst | l2_reviewer`) are required. Blank,
  anonymous, and service/system actors are refused with the named
  reason `anonymous_or_system_actor` before anything else is
  examined — the system routes work to the gate; it never decides
  at it.
- **Five coded outcomes.** `close_no_action`, `close_monitor`
  (with a mandatory 1..365-day review period and a computed
  review-due date), `escalate_sar` (routes to `sar_pending`, the
  R6 entry point — nothing is filed), `escalate_l2`, and
  `request_more_evidence` (which must name the missing evidence
  types in the R4 open-question vocabulary).
- **Coded rationale from a versioned vocabulary.** Each outcome
  has its own reason-code set (`RATIONALE_CODES`, vocabulary
  `2026.10.1`, recorded on every disposition). At least one code
  is mandatory; the free-text note supplements, never substitutes.
- **The record citation.** A disposition names the investigation
  record id *and version* it relied on, and the gate refuses
  anything but the case's current record
  (`record_citation_not_current`), just as it refuses a case with
  no record at all. When a later record version supersedes the
  cited one, the investigation graph's persist step flags the
  case `DISPOSITION_STALE`; a fresh disposition on the current
  record clears it. A disposition's derived standing — effective,
  pending_confirmation, confirmed, declined, superseded — is
  computed from the append-only history, never stored as an edit.
- **The sanctions posture binds.** The gate uses the same
  unresolved-sanctions-hits definition as the workflow's close
  guard (one helper in `workflow.py`): `close_no_action` and
  `close_monitor` over an unresolved hit are refused at the gate,
  before the close guard would have to fire.
- **Dual control on adverse closures.** A `close_no_action` whose
  record's hypothesis is adverse (any label but
  `no_adverse_pattern`) records the disposition but parks the case
  in `pending_confirmation`; the closure takes effect only when an
  `l2_reviewer` — never the dispositioning analyst
  (`self_confirmation` is refused) — confirms. A decline returns
  the case to `investigating`, with the declined disposition kept
  in history. Confirmations are their own append-only records.

Every disposition and confirmation is also captured as a
hash-chained evidence item (`disposition`,
`disposition_confirmation`), and every refusal is written to the
audit log as `disposition_refused` with its named reason before it
is raised. The gate drives state exclusively through the case
workflow, so the transition table above stays the single source of
which moves exist. The work queues an analyst actually lives in —
cases awaiting confirmation, cases escalated or SAR-pending — are
read models over the same records (`GET /queues/...`).

## SAR narrative drafting + citation verifier (R6) — Law 2, first half

A case standing in `sar_pending` holds everything a SAR narrative
needs and one thing it must not do without: the analyst's recorded
decision to file. The drafting service (`sar.py`) enforces that
order mechanically:

- **Entry gates, all named.** Drafting is lawful only in
  `sar_pending` (`case_not_sar_pending`); only over the case's
  current investigation record; only when the case's latest
  disposition is the `escalate_sar` that routed it
  (`sar_disposition_missing`) and that disposition cites the
  current record (`sar_disposition_not_current`). Two completeness
  gates follow: the record must carry a **subject identification
  basis** — a subject name plus a date of birth or recorded
  identifier, from the alert payload's facts or a corroborated
  screening hit (`subject_identification_missing`) — and at least
  one typology finding must carry a **flagged total** the
  narrative can state (`flagged_amounts_not_statable`; the
  drafting side never totals transactions itself — Law 4).
- **Composition through the model port.** Statements are produced
  by the composers of `composer.py`: the deterministic offline
  composer by default; the `hosted-frontier` profile is defined
  behind the same port and refuses loudly until a key is wired —
  no silent fallback, and nothing is stored when it refuses. A
  statement either restates a cited finding verbatim or fills a
  template with values read out of cited evidence elements; in
  both shapes the port's figure gate re-checks the text against
  the cited records before the statement may stand.
- **Sections, in filing order.** Subject identification (alert
  facts + the profile finding) · activity summary (the labelled
  hypothesis, its supporting and counter findings, the screening
  outcome) · chronology (the alert, then the typology findings in
  window order) · amounts and instruments (one statement per
  typology finding stating its computed total under its rule pack
  id + version, the channels present, the cash fact) · branch and
  office facts (only where branch-channel transactions are among
  the cited evidence) · what remains unknown (one statement per
  open question in the record — always present, even when the
  record holds none).
- **The citation verifier (the round's centrepiece).** A code act
  over the finished narrative text, per statement: every citation
  re-resolves through R4's `CitationResolver` — the same resolver,
  deliberately not a second one; every figure must appear in the
  cited records; every asserted value must appear in the cited
  elements; every bound finding must exist in the cited record.
  Narrative-level checks stand behind the per-statement ones:
  required sections present, a statable flagged total carried,
  and *every open question in the record carried in the unknowns
  section* — a narrative that hides what is not known fails by
  construction. Verdicts are stored per statement as their own
  append-only record; `all_verified` is the only path to the
  VERIFIED standing.
- **Versioning and derived standing.** Drafts are append-only
  versions, each pinning the record id + version and the routing
  disposition id, each captured on the hash chain
  (`sar_narrative`); verification runs are chained too
  (`sar_narrative_verification`). Standing is derived, never
  stored: **superseded** by a newer draft, **stale** when the
  cited record has been superseded (a verified narrative drops
  back — it cannot proceed to approval on a moved basis),
  **verified** when the latest verification passes, **draft**
  otherwise. Re-drafting over unchanged inputs returns the
  standing draft.
- **The boundary.** This round ends at a verified draft. The
  narrative is never approved here (dual-control approval is R7)
  and **no SAR is ever filed by this system** — the case stands in
  `sar_pending` before and after drafting; filing is not a state
  the blueprint reaches.

## Dual-control approval + sealing/export (R7) — Laws 2 and 5, completed

R6 produced a verified draft and stopped. R7 is where the file is
decided and then put under custody:

- **The approval gate (`approval.py`).** A narrative is decided
  exactly once, by a named person with a coded role — anonymous and
  system approvers are refused before anything else is read. Dual
  control is mechanical, in both directions of Law 2: the approver
  may not be the analyst who recorded the routing `escalate_sar`
  disposition (`approver_is_dispositioner`) and may not be the
  actor who drafted the narrative (`approver_is_drafter`). The
  gate reads the narrative's derived standing from the drafting
  service: only `verified` may be decided — a draft, a stale
  narrative, or an already-decided version is refused with its
  standing named. **Rejection is coded** from a versioned
  vocabulary and returns the narrative to drafting standing (its
  standing becomes `rejected`; the case stays in `sar_pending`;
  the answer is a re-draft, the next version). An approval carries
  no codes. On approval the service records the decision on the
  hash chain (`sar_approval`) and drives the case along the
  machine's `sar_pending → filed_sar` edge, minting the R1 closing
  token from the routing disposition at the moment the closure
  takes effect — the approval is the second person's act that lets
  the analyst's recorded decision complete the file. Nothing is
  transmitted anywhere: **no SAR is ever filed by this system.**
- **Sealed state is derived, never stored.** The operative seal is
  the latest seal (by chain position) that no later unseal lifts.
  One helper — `evidence.operative_seal` — derives it, and one
  guard — `evidence.ensure_case_mutable` — speaks for it: every
  mutating service entry calls it (evidence intake, screening and
  hit disposition, typology ingest and runs, investigation,
  dispositions and confirmations, drafting, approval), and the
  evidence funnel itself refuses as a backstop, so a path that
  forgot its guard still cannot write to a sealed case. The only
  writes a sealed case accepts are the sealing service's own
  custody records, which pass an explicit flag through the funnel.
- **Sealing (`sealing.py`).** Lawful only from a terminal state
  (`closed`, `filed_sar`) and only by a named officer
  (`senior_analyst` / `l2_reviewer` — custody is senior work).
  Before certifying anything, sealing re-verifies the case's
  whole evidence chain: a chain that does not verify cannot be
  sealed. The **manifest** then lists every evidence item (seq,
  kind, content hash, chain hash), the chain head, and the
  operative artefacts pinned by id and version — current
  investigation record, every disposition, current narrative, its
  verification verdict, its approval — and the seal hash is taken
  over the manifest's canonical JSON. The seal records the
  retention posture on its face: the BSA five-year basis and the
  computed retention date, plus the legal-hold state at seal time.
- **Legal hold.** Placed and released by a named officer with
  coded reasons, recorded on the chain like everything else; the
  case row's hold flag is a projection of the latest event. A hold
  in force refuses an **archive** seal (a custody seal still
  lands, and states the hold). Retention here authorises no
  destruction: **no purge path exists anywhere in the system** —
  the hold is recorded so that if one were ever built, the bar
  would already be a fact of the file, not a hope.
- **Unsealing** is an officer's act with a coded reason, chained
  the same way. It lifts the operative seal and nothing else: the
  seal stays in the append-only history, a reseal is the next seal
  version, and `seal_history` reads seals and unseals interleaved
  in chain order.
- **Export + offline verification.** `export_case_file` produces
  one package (`harborline-case-file-export/1`): the case, the
  operative seal, its manifest, the custody and hold history, the
  audit trail, and the full content of exactly the items the
  manifest certifies. `verify_export_package` is a pure function
  over that package — no store, no network: it recomputes the
  seal hash over the carried manifest, re-hashes every item's
  content against the certified value, recomputes every chain
  link up to the manifest's head, and refuses items the manifest
  does not certify. Every failure names its item by seq; `ok` is
  true only when there are none. The same check is exposed over
  the API (`POST /cases/export/verify`) and the CLI
  (`verify-export`, exit 1 on any failure).

## Regulatory clocks + escalation (R8) — Law 6

Every round before this one stamped dates; this round is where
the dates become deadlines, computed in code (`clocks.py`) — the
system's only clocks, with nobody's calendar consulted:

- **The filing clock.** Every case carries one from the day it
  opens, as pure date arithmetic over the initial-detection date
  stamped at intake: the SAR initial deadline is detection + 30
  calendar days; where the record identifies no subject, the
  outer limit — detection + 60 — is the operative deadline
  instead. Subject identification is itself derived from the
  record (the alert payload's name plus a date of birth or a
  recorded identifier, or a corroborated screening hit — strong
  or confirmed): a bare name does not identify anyone, and the
  move to the outer deadline is a coded state of the clock,
  never an analyst's assertion. Both deadlines are always
  carried on the clock view; the operative one is named.
- **States are derived, never stored.** Against an `as_of` the
  caller names (the computation reads no wall clock, so a board
  rendered for a date is reproducible for that date), a live
  clock stands `on_track`, `due_soon` (within seven days),
  `due`, or `overdue`. It ends `satisfied` when the case reaches
  `filed_sar`, or `closed_no_file` when a standing closing
  disposition at the gate documents the no-file decision — and
  the clock names that disposition: its coded rationale *is*
  the no-file documentation Law 6 requires. A pending-
  confirmation closure has not taken effect and does not end
  the clock; a case reopened after a monitoring closure is
  live again. A terminal case with no disposition anywhere on
  its record is reported as a clock **violation**
  (`terminal_without_disposition`): the gates make it
  unreachable, so its appearance means the record itself is
  wrong, and the clock says so rather than hiding it.
- **The continuing-activity clock.** When intake opens a case
  for a customer with a prior `filed_sar` case, it records a
  `continuing_activity_link` evidence item on the new case —
  naming the prior case and the filing determination date (the
  prior case's approval date, or its closing disposition's) —
  and a second clock starts: review due at determination + 90
  days, filing due at + 120, per FinCEN's continuing-activity
  guidance. Until the review date the review is the operative
  deadline; past it, the filing deadline governs and the clock
  carries `review_overdue`. The review workflow that answers
  this clock is R9; R8 starts it and escalates it.
- **Escalation is a case event.** The first time a refresh
  finds a clock at `due` or `overdue` for a deadline, the
  crossing is written onto the case's evidence chain
  (`clock_escalation`, with the deadline and the state it was
  found in) — idempotently, by reading the recorded events
  back before writing: re-computation never duplicates a
  crossing, and reaching `overdue` after `due` on the same
  deadline is a second, distinct crossing. The refresh is the
  in-app scheduler tick (`refresh_all_escalations`); reading
  the clock board or the escalation queue over the API or CLI
  runs it first. The **escalation queue** is the same
  derivation read as a worklist — overdue, then due, then
  due_soon, each entry naming its deadline and the time to it;
  satisfied and closed clocks never appear. The **clock
  board** is every case's clocks at an `as_of`, most urgent
  first — R17 builds the reporting surface on it.
- **No clock table exists.** Clocks are derived views over
  stored facts (the case record, the disposition history, the
  evidence chain), so there is no migration for this round and
  no stored state a hand could edit into compliance.

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
`typology_runs`, `typology_findings`); migration 0004 added
`investigation_records` (append-only record versions); migration
0005 added `dispositions` and `disposition_confirmations`
(append-only gate records); migration 0006 added `sar_narratives`
and `sar_narrative_verifications` (append-only draft versions and
verifier runs); migration 0007 added `sar_approvals`, `case_seals`,
`case_unseals`, and `legal_hold_events` (the approval gate's
decisions and the custody layer's records — all append-only, with
sealed state derived from the seal/unseal history, never stored).
R8's regulatory clocks added no tables at all — clocks are derived
views over the case, disposition, and evidence records (see the
clocks section above), and their escalation events ride the
evidence chain. Later rounds add: LangGraph checkpointing on
Postgres, and pgvector for adverse-media similarity (R12).

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
| `InvestigationStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `DispositionStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `SarNarrativeStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `ApprovalStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `SealStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `NarrativeComposer` (model port) | hosted frontier profile (key wired per deployment) | deterministic offline composer |

The model gateway (R13) and adverse media (R12) arrive as further
ports behind the same discipline: decisions in code, citations on
everything, untrusted input quarantined (Law 7).

## The eight laws, as a checklist

1. No case closes without a named analyst's disposition — state
   machine + disposition guard (R1) ✓; the gate itself (R5):
   coded outcomes and rationale, record-version citation with
   staleness flagging, sanctions posture, dual control on adverse
   closures ✓
2. SAR drafting is dual-control; narrative statements must resolve to
   citations, verified in code — the drafting + citation verifier
   (R6) ✓: entry gates on the routing disposition, completeness
   gates, per-statement verdicts, derived standing with staleness;
   the dual-control approval (R7) ✓: named second-person gate,
   dispositioner and drafter barred mechanically, coded rejections,
   the decision on the hash chain.
3. Screening is version-pinned; new list versions trigger delta
   re-screening of open cases — snapshots, pins, delta flags, and
   the sanctions close-guard (R2) ✓
4. The model never computes money; typologies are code — five
   deterministic checks over evidence-backed transactions, under
   immutable versioned rule packs (R3) ✓
5. Evidence is immutable and hash-chained — evidence service (R1) ✓;
   retention and legal hold first-class (R7) ✓: terminal case files
   sealed under a certified manifest, read-only everywhere, legal
   hold recorded on the chain and stated on the seal, export
   verifiable offline — and no purge path anywhere.
6. Regulatory clocks are code (SAR 30/60-day, continuing-activity
   90/120-day) — detection date stamped at intake (R1) ✓; the
   clocks themselves (R8) ✓: deadlines as pure date arithmetic,
   the no-subject outer limit as a coded state, derived states,
   no-file endings naming the documenting disposition,
   terminal-without-disposition reported as a violation,
   continuing-activity clocks started at intake, escalation
   crossings recorded on the chain idempotently, board + queue.
   The review workflow over the continuing clock is R9.
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
