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
inputs. The live profiles sit behind the same port; until a
deployment wires a key, selecting one is a loud refusal — never a
silent fall-back to offline text under a live profile's name. The
record names the profile that produced its text. R13 built the
full gateway behind the port — profiles as governed data,
real adapters, the per-case budget, and the cost ledger (see
the gateway section below).

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

## Continuing-activity reviews (R9) — the workflow answering the clock

R8's continuing-activity clock asked a question it could not
itself answer: has the returning subject's activity continued,
and is a continuing SAR being filed? R9 is the workflow that
answers it, one cycle at a time, under the same discipline as
everything upstream (`reviews.py`):

- **Assembly is citation-bound.** A `ContinuingReview` is
  assembled per cycle over the linked case's *current*
  investigation record. Its activity items gather, each with
  citations that resolve under R4's `CitationResolver` (there
  is no second resolver): the prior filing's facts (the prior
  record's hypothesis and its approved narrative, cited across
  the prior case's chain), the customer's cases and alerts
  opened since the determination, the transactions posted in
  the window (cited to their batch items), the current record's
  hypothesis, its typology findings restated verbatim under
  their own citations and figures, and the screening state.
  Before the review is stored, a verification gate re-resolves
  every citation and requires every figure the items state —
  in text or figure map — to appear in the records they cite.
  A review that fails the gate is refused, never stored.
- **The continuation assessment is coded.** Derived in code
  from the filed record's hypothesis label, the current
  record's typology findings (each record finding's key names
  its typology and the transactions it rests on), and which of
  those transactions were posted inside the window:
  `continues_filed_typology`, `new_pattern_in_window`,
  `no_adverse_activity_in_window`, or
  `activity_unrelated_to_filing` (the findings rest on
  pre-window activity). The derivation's basis is stated in
  words beside the code.
- **Only a recorded disposition answers the clock.** A named
  analyst (the R5 identity discipline: no system actors, roles
  from the analyst vocabulary) records a
  `ContinuingReviewDisposition` per cycle.
  `file_continuing` mints an `escalate_sar` disposition through
  the R5 gate — its vocabulary, its record citation, its
  transition to `sar_pending` — and the R6 narrative drafted on
  it opens its activity section with a statement citing the
  review disposition, the review, the prior case, and the prior
  narrative, held to the citation verifier's standard.
  `no_file_this_cycle` is documented by coded rationale from
  the review vocabulary family (versioned alongside the
  disposition vocabulary).
- **The clock learns the outcome by extension, not by fork.**
  `RegulatoryClockService` takes an optional review store and
  derives the cycle chain: cycle 1 from the R8 link; each
  no-file disposition starts the next cycle at its own decision
  date (rolling 90/120), the new cycle naming the review that
  started it (`prior_review_id`) and the answered cycle naming
  the review that answered it (`answered_by_review_id` /
  `answered_outcome`). A file-continuing answer leaves its
  cycle live against the filing deadline — only the case
  reaching `filed_sar` satisfies it. A review opened but not
  dispositioned changes nothing: past the filing deadline the
  cycle escalates as overdue on R8's machinery. Without a
  review store attached, the derivation is exactly R8's.
  `CaseClocks` carries the full cycle history
  (`continuing_history`); `continuing_activity` remains the
  live cycle the escalation machinery reads.
- **Cycle discipline.** One open review stands per cycle — a
  second open attempt is refused. A dispositioned review is
  immutable, and a review whose cited record has been
  superseded stands *stale*: it cannot be dispositioned, and a
  fresh review is opened in its place, naming the one it
  supersedes — supersession, never an edit. Reviews and their
  dispositions are append-only rows (migration 0008) and
  hash-chained evidence items (`continuing_review`,
  `continuing_review_disposition`). A scheduler tick
  (`open_due_reviews`) opens reviews for cycles whose review
  deadline has arrived — recording the tick as the opening
  actor, like any other opening — and skips cases with no
  investigation record: the tick never fabricates an
  assessment.

## Injection defences + quarantine (R10) — Law 7

The threat is structural, so the defence is too. Untrusted text
enters the case file from several directions — transaction
memos and counterparty names (written by customers and their
banks), alert summaries and payload fields (repeated by the
monitoring feed), screening subject names and list-entry names
(the subject's side and the vendor's side), and caller-supplied
document uploads — and from there it can reach the composers
(record and narrative drafts), screening and matching inputs,
and analyst-facing renderings. Law 7's rule: that text is data,
never instructions, and the system enforces it in code at three
points — scan, fence, ground.

- **Scan at ingestion.** A deterministic scanner runs a
  versioned pattern pack (`2026.10.1`: override phrases of the
  "ignore previous instructions" family including domain-targeted
  variants, role-play and mode-switch markers, system-prompt
  markers and token shapes, imperatives aimed at the case
  workflow — close, dismiss, mark cleared, do-not-file —
  output dictation, and encoded-payload markers including a
  base64-blob detector tuned to leave hex digests and IBANs
  alone) over untrusted text where it lands: alert intake
  (summary plus every string in the raw payload), transaction
  ingestion (per-transaction memo and counterparty fields),
  screening runs (hit subject and entry names), and the
  evidence funnel itself for every caller-supplied document
  kind — the kinds the system's own services write are scanned
  with field precision by their own services or are
  system-generated, and are exempt at the funnel so nothing is
  recorded twice. A match never rejects the evidence: the item
  stands verbatim, and the scan records a **quarantine event**
  on the case's hash chain naming the item, each field, the
  pattern matched, and the exact character span (an imperative
  span runs to the end of its sentence — the whole clause is
  the payload). Quarantine state is derived from the chain, so
  R10 adds no tables and no migration.
- **Fence at consumption.** Wherever untrusted text reaches a
  composer — the alert summary and screening names in record
  drafts, the subject name in narrative drafts — the value is
  passed with each matched span replaced by a fence marker
  (`[quarantined instruction text removed]`). The payload never
  reaches a model, a template, or a rendering as bare prose.
  Matching itself is deterministic code over the raw names and
  is unaffected; screening still matches a payload-carrying
  name exactly as it matched a clean one.
- **Ground against the mask.** The verifiers' cited-token
  computation — the record gate, the narrative verifier, the
  review gate, and the composers' allowed sets — tokenises the
  cited element with quarantined spans masked out, and the
  narrative verifier's value comparison runs against the
  fenced form of the evidence, the same form the composer was
  allowed to see. A figure that appears only inside an
  instruction span is therefore ungroundable: a finding or
  statement built on it fails at the gate exactly like an
  invented figure. Citation rules are unchanged — a citation
  still resolves to the whole element; the quarantined spans
  of that element simply contribute no tokens.
- **Review is an audit act.** The quarantine queue (API:
  `/queues/quarantine`; per case: `/cases/{id}/quarantine`)
  lists every record with its item, patterns, spans, and
  review status. A named analyst may mark a record reviewed —
  refusing anonymous and system actors, and a second review
  of the same record. The review is recorded on the chain and
  changes nothing else: the fences derive from the append-only
  quarantine record, so review can never un-fence content, and
  a record composed after a review fences exactly as one
  composed before it.
- **Graded, not asserted.** The eval gate (Scenario 13) plants
  payloads in memos, an alert summary, and a planted-figure
  memo, and grades zero-tolerance counters: record divergence
  from the clean run, unfenced summary payloads, injected
  imperatives in the narrative, payloads without a quarantine
  event, quarantined spans grounding a figure, state
  divergence, false positives on ordinary banking prose
  (including legitimate "transfer instructions" language), and
  reviews un-fencing content — all zero, with the clean and
  dirty positive paths landing.

## KYC profile assembly + counterparty views (R11)

Everything before this round works one case at a time. An
analyst, though, works on a customer: what the bank already
knows about them, across every case, is the context every
decision is made in. R11 assembles that context as a derived
artefact — the **profile view** — under three disciplines.

- **Stored artefacts only, every fact sourced.** The view is
  assembled in code from what the earlier rounds stored: alert
  payloads on case chains (identity facts), screening runs and
  hits (corroboration, hits and clearances), account profiles,
  transaction records, disposition records (standing, via the
  R5 service's own derivation) and approvals (SAR outcomes).
  Nothing is hand-entered; each identity fact carries its
  source kind, the case it came from, a human-readable source
  reference, and the evidence item it was read from. A customer
  with no cases has no profile — assembly refuses rather than
  fabricate an empty one.
- **Conflicts are shown, never merged.** `name` and `dob` are
  single-valued identity attributes: two distinct values on
  record produce an `identity_conflict` entry carrying both
  values and every fact behind them, and neither value is
  promoted. Identifiers are multi-valued (a passport and a
  licence are both facts), so they stand side by side without a
  conflict flag. Screening history is carried per list kind and
  snapshot version with hits and clearances alike — a namesake
  cleared by the deterministic matcher stands with its
  `date_of_birth_mismatch` reason visible, not dropped.
- **Derived, content-addressed, append-only.** The content hash
  covers the derived facts (including the freshness verdicts,
  which are computed at an `as_of` passed in — no wall-clock
  reads inside the derivation, the clocks' rule). Rebuilding
  over unchanged inputs returns the stored view; changed
  inputs append the next version and earlier versions stand.
  Freshness is judged per fact class (identity, account,
  screening, activity) against a versioned policy recorded on
  the view; a class never corroborated is named stale, not
  silently absent.

The investigation graph consumes the view: when a stored view
exists for a case's customer, assembly captures it on the
case's chain as a `customer_profile_view` evidence item
(reused while unchanged, like the account-profile capture),
and the record's profile finding cites it alongside the raw
account profile — so the record's profile facts trace to the
assembled, provenance-carrying view as well. With no view
stored, nothing changes (R4's behaviour is untouched).

**Counterparty views** aggregate the stored transactions in
code: per counterparty, Decimal totals in and out (Law 4 — the
model computes no money), transaction count, first/last seen,
the currencies and accounts touched, and the name's screening
state across every case in the store (each hit naming its
case, list and status). Grouping is by normalised name over
verbatim stored values. **Shared counterparties** — names
standing on more than one customer's cases — are computed
exactly and served as their own view: the network signal an
analyst needs, derived, not anecdotal. Display names pass
through R10's quarantine fencing (a counterparty name carrying
an instruction renders with the fence marker in the composed
view); the stored transaction keeps the name verbatim.

Graded by eval Scenario 14 with zero-tolerance counters:
identity conflicts merged silently, profile figures wrong
against hand-computed Decimal totals, counterparty links
missed or extra, stale fact classes left unnamed, and profile
facts built from an unstated source — all zero, with the
positive paths (the seed customer, a multi-case fixture
customer with an exact counterparty aggregate set, the
shared-counterparty link) landing.

## Adverse media: the port + similarity scoring (R12)

Screening (R2) answers "is this name on a list a vendor asserts
is adverse?" Adverse media asks the harder question a news feed
poses: "here are forty articles that mention this name — which
of them are about *this* customer, and what do they say?" R12
answers it under the same disciplines as everything else here:
a port, ingestion as evidence, scoring in code, findings only.

- **The port is a licensed-product boundary.** `AdverseMediaSource`
  is a recall-oriented name search, exactly as a news database
  behaves: it returns candidates — namesakes and loose matches
  included — and never claims they are about the subject. A
  production deployment wires a licensed news database behind
  it; the blueprint ships a labelled reference corpus in
  `data/adverse_media.json`, stand-in data that is never
  presented as real reporting.
- **Ingestion is evidence, and evidence is untrusted.** A
  candidate article enters a case only as an evidence item
  (kind `adverse_media`) through the funnel, and its text fields
  are scanned at ingestion by R10's quarantine service with
  field precision: an instruction planted in an article body
  becomes a quarantine case event and is fenced everywhere the
  article is consumed, exactly as one in a transaction memo is.
  The article itself is never rejected or edited (Law 5).
- **Similarity is computed, not embedded.** The scorer is
  deterministic code — deliberately not vector similarity: a
  relevance band a bank must defend to an examiner has to be
  reproducible from stated rules, the same argument that made
  screening's matcher deterministic in R2. Name-match strength
  reuses that matcher (exact / token-set / fuzzy, over the
  subject's names and aliases against the article's named
  subjects). Disambiguation signals are read against the
  customer profile — the assembled R11 view when one is stored
  (pinned by id and version on the assessment), merged with the
  case's own alert payload facts: identifier, date of birth,
  stated age, geography, occupation, associated entities. Every
  signal is recorded with its outcome (supports / contradicts /
  absent), its signed contribution, and the facts it was read
  from; the similarity score is the name match weighted with
  those contributions. Adverse categories come from a versioned
  keyword taxonomy over headline and body, with the matched
  terms recorded per category.
- **R2's namesake discipline, carried over.** A name match
  contradicted by the profile's date of birth (or by a stated
  age inconsistent with it) is a different person: the band is
  `namesake_cleared` and the contradiction is named in the
  band's basis — never silently dropped, never left standing as
  a hit. An identifier match prevails over a contradicting date
  of birth, with the conflict recorded for an analyst, as at
  screening. Geography and occupation mismatches are soft
  signals only: people move and change jobs, and neither alone
  ever clears a match. The bands are ordered rules over these
  signals: no name match → `irrelevant`; hard contradiction →
  `namesake_cleared`; identifier match, or an exact/token-set
  name match with at least one supporting signal → `strong`;
  anything else that matched a name → `possible`. Article age
  (`as_of − published_on`) is computed and shown on every
  assessment.
- **Findings only.** An assessment is an append-only artefact
  (migration 0010), captured on the case's hash chain (kind
  `media_assessment`). The investigation graph cites assessments
  as findings — statement built from code-computed values (band,
  similarity score, categories, publication date) and the
  article's fenced outlet; article prose never enters a
  statement, the finding's direction is context (media supports
  no hypothesis), and it reaches a SAR narrative only as such a
  cited finding, with its band stated. The media service holds
  no workflow reference and writes no case state: after a
  search, a case stands exactly where it stood, and no
  disposition exists that media created. What a strong match
  means for the case is the analyst's decision at the gate.

Graded by eval Scenario 15 against a fixed corpus — a true
adverse hit, a namesake with a contradicting date of birth, a
same-name different-geography possible, an unrelated namesake,
a non-adverse mention, and an article carrying a planted
instruction — with zero-tolerance counters: namesakes graded
strong, media-driven disposition or state changes, article
instructions left unquarantined, uncited media claims in a
record, and bands wrong on the graded fixtures — all zero, with
the positive paths (six articles ingested as evidence, six
assessments recorded with versions pinned, six cited findings
in the next record version) landing.

## Model gateway + cost ledger (R13)

R4/R6 put composition behind a port with named profiles; R13
builds the gateway those profiles live behind (`gateway.py`) —
the one configured path for drafting calls, under the same
disciplines as every other subsystem: configuration as governed
data, refusals that are loud and recorded, and nothing priced
by implication.

- **Profiles are data, loaded fail-closed.** A profile
  definition names an id, a provider kind, a model, and the
  *environment variables* holding its endpoint and key — never
  the values. Three ship: `offline` (the deterministic
  composer), `hosted-frontier` (Anthropic Messages API), and
  `in-boundary` (an open-weight model on an OpenAI-compatible
  endpoint inside the bank's boundary). The loader refuses the
  whole configuration over any defect: duplicate ids, a live
  profile with no endpoint, a key-required profile naming no
  key variable, a model with no price-table entry, a duplicate
  or negative price, a malformed budget cap. Wiring validates
  the deployment's own profile (`AML_MODEL_PROFILE`) at
  startup. At call time, an unknown profile raises
  `UnknownModelProfileError` and an unconfigured live profile
  raises `ModelProfileNotConfiguredError` — the R6 stub's loud
  refusal, now issued by the gateway that owns the configured
  path. There is no fallback in the module: no code path
  substitutes one profile for another, at load, at wiring, or
  mid-case.
- **Adapters are real HTTP clients.** One per provider kind,
  over httpx, exercised in tests and evals against stub
  transports returning provider-shaped responses. Each returns
  the composed text plus token counts — the provider's reported
  usage when sent, else the adapter's estimate, recorded with
  its basis (`estimated:chars/4`) so an estimate is never
  mistaken for a measurement. The gateway applies the
  composer's figure gate to the returned text exactly as it
  does to offline text: an ungrounded figure refuses the
  statement, whoever wrote it — and the call is ledgered
  first, because a refused statement still cost what it cost.
- **Every call is priced into an append-only ledger**
  (migration 0011: `model_call_ledger`, `model_budget_events`).
  An entry carries the case (or the system scope), the purpose
  (`record_draft`, `sar_draft`), profile and model, tokens and
  their basis, the price-table version *and the unit prices
  applied*, latency, and a timestamp from the gateway's
  injected clock — so the cost re-computes from the entry
  alone, and a later price-table version never reprices a
  recorded call. Offline calls ledger at zero: the ledger is
  the complete record of drafting cost, not just the paid part.
  Money is Decimal end to end; the price table
  (`data/model_prices.json`) is governed reference data with a
  version, an as-of date, and a stated basis per model.
- **The per-case budget is enforced before transport.** The
  cap is configuration (`case_budget_usd` in the profiles
  data). Before a live call for a case, the gateway sums the
  case's ledgered spend; at or over the cap, the call is
  refused with `ModelBudgetExceededError` — the stub
  transport's call count in the evals proves the refused call
  never reaches the endpoint. The refusal is recorded three
  ways: a budget event in the ledger store, an audit event on
  the case, and an item on the case's hash chain (kind
  `model_budget_refusal`, a system kind the quarantine funnel
  does not rescan). The offline profile is never capped, and
  finishing a case offline after a refusal is a normal path —
  taken by the caller naming `offline`, never by the gateway
  switching on its own. API keys live only in the gateway's
  in-memory resolution: profile summaries expose variable
  names and a `configured` flag, never values.
- **Rollups are reads over the ledger**: per case (totals by
  purpose and by profile, tokens, the budget position and
  refusal count) and per day × profile across the portfolio —
  exposed on the API (`/model/profiles`,
  `/cases/{id}/model-ledger`, `/cases/{id}/model-costs`,
  `/model-costs/daily`) and the CLI (`model-profiles`,
  `case-costs`, `case-ledger`, `portfolio-costs`). No verdict
  anywhere derives from ledger data; it is cost accounting,
  kept separate from the case's evidence and clocks.

Graded by eval Scenario 16: an offline investigation + SAR
draft ledger exactly one entry per composed statement, all at
zero and all recomputing from their tokens and prices; a
stubbed hosted-frontier draft prices every statement at the
hand-computed fixture cost; unknown/unconfigured profiles, an
unpriced model in the configuration, and an unconfigured
active profile at wiring are all refused; and a case capped at
two calls' spend sees its third live statement refused before
transport, the refusal on its chain, and its offline draft
land afterwards. Zero-tolerance counters: unpriced calls,
silent fallbacks accepted, budget breaches executed, and
ledger costs wrong — all zero.

## Analyst console (R14) — the human surface, no new authority

Everything before this round is services and gates; R14 is the
surface an analyst actually works on. It is deliberately the
thinnest layer in the system: one static HTML file
(`src/aml_investigations/static/console.html`, inline CSS and
vanilla JS, no build step, no framework), served by the app at
`GET /console`, following the portfolio console standard —
light theme, indigo accent, the Trida footer. The console
holds no state of its own beyond the analyst identity the
operator types into the header, and it reaches the system
only through the routes the API already serves.

The queue is a join, computed in the browser from three reads
(`GET /cases`, `GET /clocks/board`, `GET /queues/quarantine`):
each row carries the case's status, its filing-clock state and
operative deadline, its continuing-review state when one
runs, and its count of unreviewed quarantine records, and the
list sorts by clock urgency (the worse of the filing and
continuing clocks decides), by detection date, or by severity,
with status filters over the same data. The workspace is the
case file in analyst order — alert, clocks, KYC profile,
evidence chain, screening, transactions, typology findings,
investigation record, dispositions, SAR narrative, continuing
reviews, media assessments, model ledger — one read per panel
from the endpoints each earlier round built, including the
chain-verification read, so what the analyst sees is the
system's own account of the file, not a reporting copy.

Three disciplines keep the console honest:

- **Rendering is text-only.** Every value the API returns is
  placed into the page as text (text-node assignment through
  one set of DOM builders); the file contains no markup sink
  at all. Evidence content is untrusted by Law 7, and the
  console treats it that way: a transaction memo carrying a
  script displays as the characters it is. Quarantined items
  are badged on the chain, and their matched spans render
  inside a fence block carrying the same marker the composers
  fence with — `[quarantined instruction text removed]` — with
  the pattern, family, field, and excerpt visible as data.
- **Forms are built from the served vocabularies.**
  `GET /vocabulary` serves the gates' own coded sets — the
  disposition rationale per outcome and the missing-evidence
  types (R5), the confirmation outcomes, the SAR rejection
  codes (R7), and the continuing-review no-file codes with
  their descriptions (R9) — so a console form can only offer
  codes the corresponding gate will accept, and the gate still
  re-checks every one server-side.
- **Actions are the gates, unchanged.** The console's only
  writes are the human acts the rounds before it built: a
  disposition, a confirmation, a SAR approval or rejection, a
  quarantine review, opening a continuing review, and a
  review disposition. Each is submitted under the header
  identity (name + coded role); without one the form will not
  submit, and the API refuses anonymous and system actors on
  its own side regardless. A refusal comes back as the API's
  error text and is rendered as-is — the console never retries
  around a refusal, offers a weaker path, or hides one.

Graded by eval Scenario 17 over the production wiring and the
reference feeds: the page serves with its footer markers; the
queue's inputs agree on the case set; a case worked end to
end over HTTP aggregates every artefact kind in the workspace;
a surface scan reconstructs every call the console makes and
checks it against the app's route table (28 call sites at
this round, six of them writes — every one an existing gated
route); and a static scan finds no markup sink and exactly
one fetch site, the console's own API helper. Zero-tolerance
counters: queue mismatches, workspace gaps, console-only
write paths, unescaped render paths, and console positive
paths failed — all zero.

## The trap suite (R15) — eval depth as adversarial grading

R15 adds no surface; it attacks the surfaces R1–R14 built.
The suite lives in `tests/test_traps_r15.py` and as eval
Scenario 18, each trap graded with hand-computed expectations
— zero-tolerance where the behaviour is a law, graded-exact
where it is a boundary:

- **Namesakes.** The grading matrix is symmetric across
  screening and media: name + contradicting DOB clears with
  the reason recorded; name + matching DOB corroborates even
  when the identifier merely differs (a differing identifier
  is recorded, never treated as proof of a different person);
  an identifier match prevails over a DOB contradiction, with
  the contradiction standing on the record; middle-name and
  alias variants match by the stated token rules at potential
  strength. The stale-list trap: a subject whose entry exists
  only in list v2 leaves the v1-screened case flagged, with
  no hit silently added or cleared, until a re-screen.
- **Threshold edges.** Each typology rule is graded just
  under and exactly at its boundary (structuring band top
  and bottom, velocity multiple, dormancy gap, round-amount
  share, in-out pass-through), figures asserted exactly.
- **Clocks.** Deadline arithmetic across leap and plain
  years; identification flipping the operative deadline (and
  a cleared namesake hit identifying nobody); a late no-file
  graded on both of its facts — documented, and late on the
  clock's face; a continuing clock anchored on the actual
  determination date of a prior filing that was itself late.
- **Gates.** Dual control is graded against respelt identity
  strings; a citation pairing the current record id with a
  superseded version number is refused like any stale
  citation; a seal is attempted over a chain with a gap
  introduced by direct store manipulation and refused at
  seal time, because the seal re-verifies before certifying.
- **Injection, second family.** The memo-split trap states
  the scanner's boundary honestly: matching is field-scoped,
  two fragments that are harmless per field are not joined —
  and the pair still changes no record, graded byte-exact
  against a clean twin. Counterparty-carried and
  headline-carried payloads grade the fencing and quarantine
  of the two fields R10's prose scenarios did not ride.
- **Data.** Re-delivery is graded in all three forms:
  identical (idempotent), overlapping-identical (dedupe,
  growth lands), and altered (refused — see below).

Two traps found genuine defects; both were fixed in the
owning module with the trap kept as the regression:

1. **Dual control compared raw strings.** The confirmation
   and approval gates compared person ids exactly, so a
   dispositioner could confirm their own closure — or a
   drafter approve their own narrative — by re-casing or
   re-spacing their id. Person ids now compare in canonical
   form (`canonical_person_id` in `dispositions.py`:
   whitespace collapsed, case-folded) at both gates and at
   the system-actor check; ids are still recorded exactly as
   presented. Dual control binds persons, not spellings.
2. **Ingestion could orphan a batch.** `ingest_transactions`
   wrote the batch record and its evidence item before the
   transaction rows, so a re-delivery re-using a stored id
   with altered content crashed mid-write, leaving an orphan
   batch that a retry returned as if ingested — the
   alteration silently swallowed. The identity check now runs
   before any write: a stored id arriving with different
   content refuses the whole delivery
   (`TransactionConflictError`); byte-identical records in a
   later batch are stored once, which is what lets a
   full-history feed grow a case's stream lawfully.

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
evidence chain. Migration 0008 added `continuing_reviews` and
`continuing_review_dispositions` (append-only review artefacts and
their decisions; the clock's cycle derivation reads them).
Migration 0009 added `profile_views` (append-only assembled KYC
profile versions, content-addressed; counterparty views are
computed from the transaction tables at read time and need no
storage of their own). Migration 0010 added `media_assessments`
(append-only adverse-media assessments; the articles themselves
ride the evidence chain, and the similarity scoring is
deterministic code over stored records, so no vector store is
needed). Migration 0011 added `model_call_ledger` and
`model_budget_events` (the model gateway's append-only cost
ledger and its budget-refusal records; see the gateway section
above). Later rounds add LangGraph checkpointing on Postgres.

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
| `ContinuingReviewStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `ProfileStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `AdverseMediaSource` | licensed news database (deployment-specific) | reference JSON corpus |
| `MediaStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `NarrativeComposer` (model port) | the model gateway's profiles (R13): hosted frontier / in-boundary, keys wired per deployment | deterministic offline composer |
| `ModelLedgerStore` | PostgreSQL via migrations | SQLite file; in-memory |
| `ModelTransport` | HTTPS JSON via httpx | stub transports returning provider-shaped responses |

The model gateway (R13) sits behind the composer port under
the same discipline: decisions in code, citations on
everything, untrusted input quarantined (Law 7) — and every
call priced, ledgered, and budget-checked before transport.

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
7. Prompt injection inside evidence is a case event, quarantined —
   R10: the versioned pattern pack scans untrusted text at
   ingestion, matches land on the hash chain as quarantine
   events with exact spans, composers receive the text only
   fenced, verifiers ground against the span-masked token set,
   and an analyst's review is an audit act that never un-fences.
8. Rubber-stamping is measured (draft-vs-final diff) — the raw
   material lands at R5 (every disposition cites the record
   version it relied on; every record version stores its diff;
   narratives are append-only versions decided once), and R17
   builds the measurement surface on it: findings added /
   removed / changed between first draft and decided version,
   narratives approved unedited vs after a re-draft with the
   distance in stated bands, confirmation patterns, and
   decision-latency distributions — presented as measurements
   with their limits stated, never as scores.

## Postgres profile + production smoke (R16) — the store, proven

Until this round the SQL adapter was proven the way most suites
prove it: the in-memory double carried the tests, and one replay
per domain exercised SQLite. The Postgres adapter — the one a
deployment actually runs — was only ever constructed, never graded
end to end. R16 grades it three ways, all against a real
PostgreSQL 16 server:

- **Full-suite parity** (`tests/pg_parity.py`). With
  `AML_TEST_DATABASE_URL` set, conftest swaps every store
  construction in the suite — after collection, so no test file
  changes — for a real `SqlCaseStore` over its own freshly
  migrated Postgres schema, and `SqlCaseStore.sqlite(path)` for a
  Postgres schema keyed by that path (reopen tests keep their
  meaning). The whole suite then runs on the production adapter:
  389 passed, the same count as the default profile. The two
  tests that tamper with evidence through the in-memory double's
  internals do the same tampering as SQL UPDATE/DELETE through a
  live view the parity store exposes — an attacker with database
  access is the same attacker in both profiles.
- **Migrations on Postgres, graded directly**
  (`tests/test_postgres_profile.py`): on an empty database the
  runner applies 0001–0011 in order and a re-run applies nothing;
  `SqlCaseStore.postgres` — the construction production wiring
  uses — persists a case across connections. Parity found two
  genuine defects here, both fixed at the owning layer: the
  migration runner read its ledger with tuple indexing, which a
  psycopg dict-row connection (what `SqlCaseStore.postgres`
  builds) raises on — a migrated database could not be reopened;
  and migrations 0008–0011 declared payload columns `JSONB`,
  drifting from the store's JSON-text contract (0001–0007), so
  psycopg handed back parsed objects where every reader expects
  the stored text. The columns are `TEXT` now, both dialects
  alike.
- **The production smoke** (`scripts/prod_smoke.py`): boots the
  real app under uvicorn with `DATABASE_URL` at a fresh, empty
  database and walks the seeded structuring case over HTTP —
  intake, pinned screening, typologies, investigation, escalate,
  draft + verify, dual-control approval, seal, export, offline
  export verification, and a sealed-mutation refusal — asserting
  state at each of the 20 steps, then drops its database. The
  eval gate runs all three legs as Scenario 19 when a server is
  provided (`AML_EVAL_DATABASE_URL`), and counts the skip when
  none is — the zero-tolerance counters are `pg_migration_failures`,
  `prod_smoke_step_failures`, and `pg_suite_parity_gap`.

The deployment artefacts were already the production shape —
compose runs `pgvector/pgvector:pg16` with the app wired by
`DATABASE_URL` and SeaweedFS as the S3 evidence store — so R16
changed no compose topology; it verified the profile the compose
stack selects. One boundary is stated plainly: the Docker image
build itself was not run in the build sandbox (no Docker daemon
there); the image and compose contracts are graded statically by
`tests/test_docker_contract.py`, and the smoke proves the
application the image ships, on the store the compose stack
provisions.

## Management reporting (R17) — Law 8, measured

`reporting.py` builds the management report pack from the same
stored artefacts the gates wrote. It is a pure read-model in the
derived-artefact discipline of the clocks (R8) and the profile
views (R11): nothing is stored, every figure is reproducible
from the underlying records, the pack names its `as_of`, and
`pack_id = rep-<sha256[:16]>` over the pack's canonical JSON —
the same artefacts at the same date rebuild the same pack byte
for byte. The pack carries an `inputs` counter (artefact family
→ records read), and every section carries a `sources` list
naming the store reads its figures came from; a figure with no
stated source is an eval failure, not a style point.

- **Queue ageing.** Open cases (status not terminal) aged from
  detection date at `as_of`, grouped by status, monitoring rule
  and severity over stated buckets (`0-7, 8-30, 31-60, 61-90,
  91+`), plus the ten oldest. The two queues that wait on named
  humans are aged separately: `pending_confirmation` cases name
  the dispositioning analyst and disposition from the standing
  unconfirmed confirmation-requiring disposition and wait on the
  `l2_reviewer` role; `sar_pending` cases are staged from the
  artefacts — `awaiting_draft` (after escalation or a rejection),
  `awaiting_verification` (a draft stands unverified),
  `awaiting_approval` (verified, undecided) — and name the
  routing disposition's analyst. Person-level detail is exactly
  what the artefacts already record; the report aggregates
  nothing about a person beyond it.
- **Clock board.** The R8 derivation read portfolio-wide at
  `as_of`: filing clocks by state, each case's current
  continuing cycle by state, and the overdue list (days overdue
  from the clock's own days-remaining). Deadline performance
  grades every clock that reached a terminal state: a filing
  ends satisfied on its determination date (approval date, else
  closing disposition date — the clock service's own rule) or
  closed-no-file on the standing no-file decision date; a
  continuing cycle answered by a review disposition is measured
  against its review deadline (no-file) or filing deadline
  (file-continuing with a filing), and a cycle the case's own
  ending closed against its filing deadline. Lateness is
  `ended_on > operative deadline` — so a documented no-file
  decision recorded after its deadline counts LATE: the
  documentation stands, and so does the lateness (the R15 rule,
  carried into reporting unchanged). The performance section is
  windowed (`window_start`/`window_end`); states and the overdue
  list read at `as_of`.
- **Rubber-stamp metrics.** Records: per case, the diffs stored
  on record versions 2..decided-version are summed (decided
  version = the standing — latest — disposition's cited
  version; a version carrying no stored diff falls back to a
  recomputed key-set diff, the R4 discipline restated); headline
  counts split cases decided on the first draft vs a revised
  record. Narratives: the approved version's rendered text is
  compared to the first draft's — identical is `approved
  without edit`; otherwise a normalised edit distance
  (1 − difflib `SequenceMatcher` ratio) in stated bands (none /
  light ≤ 0.10 / moderate ≤ 0.35 / heavy), with re-draft
  approvals counted. Confirmations: of the dispositions that
  required a second person, how many stand confirmed (with /
  without a note — a confirmation cannot modify what it
  answers, so the note is the only recorded trace of engagement
  beyond the act), declined, or awaiting, plus a per-analyst
  table. Decision times: hours from the artefact a gate decided
  on to the decision, per deciding actor at each of the three
  gates, as median and nearest-rank p90. The section ships its
  `measures` and `cannot_measure` lists in the artefact itself:
  it cannot show whether anyone read the evidence or whether a
  decision was right, and no figure in it ranks or scores a
  person.
- **Operations.** Typology volume grouped by check and
  rule-pack version (findings per run of the pack as an exact
  Decimal string, against the pack's portfolio run count);
  screening grouped by list version — hits by standing, with
  namesake clearances (`cleared_reason =
  date_of_birth_mismatch`) counted separately and cases screened
  read from the runs' pins; quarantine records and matches by
  pattern family and source kind, with flagged/reviewed standing
  from the queue (when no quarantine service is wired the
  section reports `available: false` and no figures, rather
  than invented ones); the media band distribution zero-filled
  over the full band vocabulary; and model spend from the R13
  ledger — calls, tokens and exact Decimal cost by profile and
  by purpose.

Surfaces: `GET /reports/pack` (with `as_of`, `window_start`,
`window_end`) and one route per section, all reads; the CLI's
`report-*` commands print the same artefacts; the analyst
console gains a Reports view fed by the pack route through its
existing single `api()` helper — the surface scan still proves
every console call maps to a real route, and the view adds no
write path. The eval gate grades the derivations as Scenario 20
against a purpose-built book with hand-computed expectations:
`report_figure_wrong`, `report_late_counted_on_time`,
`report_rubber_stamp_wrong`, `report_unstated_source` and
`report_positive_paths_failed` are zero-tolerance.

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
the trap suite (namesakes, thresholds, clocks, gates, injection
II, data) · R16 Postgres profile + prod
smoke · R17 reporting: queue ageing, clock board, rubber-stamp
metrics · R18 access control: role-scoped case access, retrieval
ACLs · R19 red team: narrative-fact transposition, citation-to-passage
verification · R20 release hardening (Docker contract, docs, final
gates).
