"""Command-line entry point: intake, case inspection, screening, typologies.

Usage:
    aml-agent intake <alert_id>     open a case from a feed alert
    aml-agent list [--status S]     list cases
    aml-agent show <case_id>        show one case + evidence + audit
    aml-agent verify <case_id>      verify the evidence hash chain
    aml-agent ingest-lists          ingest snapshots from the list feed
    aml-agent snapshots             list ingested snapshots
    aml-agent screen <case_id> --sanctions V [--pep V] [--adverse-media V]
                                    screen a case against a pinned set
    aml-agent register-packs        register rule packs from the feed
    aml-agent packs                 list registered rule packs
    aml-agent ingest-transactions <case_id>
                                    pull the case account's stream from
                                    the transaction feed (evidence-backed)
    aml-agent run-typologies <case_id> --pack ID --version V
                                    run the typology engine over the case
    aml-agent findings <case_id>    list a case's typology findings
    aml-agent investigate <case_id> [--profile P]
                                    run the investigation graph and
                                    record the investigation record
    aml-agent investigation <case_id>
                                    show the current record + history
    aml-agent disposition <case_id> --analyst ID --role ROLE
              --outcome OUTCOME --code CODE [--code CODE ...]
              --record-id ID --record-version N [--note TEXT]
              [--review-days N] [--missing TYPE ...]
                                    record an analyst disposition at
                                    the gate (R5)
    aml-agent confirm <case_id> --confirmer ID --role ROLE
              --outcome confirmed|declined [--note TEXT]
                                    a second person answers a pending
                                    disposition (dual control)
    aml-agent dispositions <case_id>
                                    show the disposition history
    aml-agent queue confirmations|escalations
                                    the L2 / escalation work queues
    aml-agent draft-sar <case_id> [--profile P] [--actor A]
                                    draft the SAR narrative for a
                                    sar_pending case and run the
                                    citation verifier over it (R6)
    aml-agent sar <case_id>         show the current SAR narrative
                                    draft + its version history
    aml-agent verify-sar <case_id>  re-run the citation verifier
                                    over the current draft and show
                                    the verification record
    aml-agent approve-sar <case_id> --approver ID --role ROLE
              --outcome approved|rejected [--code CODE ...] [--note T]
                                    the dual-control decision on the
                                    verified narrative (R7): the
                                    approver may be neither the
                                    dispositioning analyst nor the
                                    drafter; a rejection needs codes
    aml-agent case-file <case_id>   show the case's custody state:
                                    operative seal, seal history,
                                    legal-hold state (R7)
    aml-agent seal <case_id> --officer ID --role ROLE
              [--purpose custody|archive]
                                    seal a terminal case file (R7)
    aml-agent unseal <case_id> --officer ID --role ROLE --code CODE
              [--note TEXT]         lift the seal, with a coded
                                    reason (R7)
    aml-agent hold <case_id> --officer ID --role ROLE --code CODE
              [--note TEXT]         place a legal hold (R7)
    aml-agent release-hold <case_id> --officer ID --role ROLE
              --code CODE [--note TEXT]
                                    release a legal hold (R7)
    aml-agent export <case_id> [--out FILE]
                                    export the sealed case file as
                                    one package (to FILE, or stdout)
    aml-agent verify-export <file>  re-verify an exported package
                                    end to end, offline; exit 1 when
                                    anything in it fails to verify
    aml-agent clock <case_id> [--as-of YYYY-MM-DD]
                                    a case's regulatory clocks (R8):
                                    the SAR filing clock (30-day
                                    initial / 60-day outer when no
                                    subject is identified) and its
                                    continuing-activity clock when
                                    one was started — states derived
                                    in code at the named date
    aml-agent clock-board [--as-of YYYY-MM-DD]
                                    every case's clocks, most urgent
                                    first; reading the board records
                                    any new due/overdue crossings on
                                    the cases' chains first
    aml-agent clock-escalations [--as-of YYYY-MM-DD]
                                    the clock escalation queue:
                                    overdue, then due, then due_soon,
                                    each entry naming its deadline
    aml-agent open-review <case_id> [--actor A]
                                    open the current cycle's
                                    continuing-activity review (R9):
                                    the window's activity assembled
                                    over the case's current record,
                                    verified at the citation gate
    aml-agent review <case_id>     the case's reviews: the current
                                    cycle's operative review, the
                                    per-cycle history, and the cycle
                                    clocks they answer
    aml-agent reviews --customer ID
                                    the customer's continuing-activity
                                    history across their cases
    aml-agent disposition-review <case_id> <review_id>
              --analyst ID --role ROLE
              --outcome file_continuing|no_file_this_cycle
              --code CODE [--code CODE ...] [--note TEXT]
                                    record the cycle's decision —
                                    the only act that answers the
                                    clock for the cycle (R9)
    aml-agent open-due-reviews [--as-of YYYY-MM-DD] [--actor A]
                                    the scheduler tick: open a
                                    review for every case whose
                                    cycle's review deadline arrived
    aml-agent quarantine <case_id>  the case's quarantine records:
                                    item, pattern, span, review
                                    status (R10, Law 7)
    aml-agent quarantine-queue      every quarantine record across
                                    every case — the review work list
    aml-agent quarantine-review <case_id> <quarantine_seq>
              --reviewer ID [--note TEXT]
                                    record a named analyst's review
                                    of one quarantine record — an
                                    audit act; the content stays
                                    fenced permanently
    aml-agent profile <customer_id> [--as-of YYYY-MM-DD] [--actor A]
                                    assemble the customer's KYC
                                    profile view from stored
                                    artefacts (R11); unchanged
                                    inputs return the stored view
    aml-agent profile-show <customer_id>
                                    the customer's latest stored
                                    profile view
    aml-agent case-profile <case_id>
                                    the profile view for a case's
                                    customer
    aml-agent counterparties <customer_id>
                                    the customer's counterparties:
                                    Decimal totals, first/last seen,
                                    screening state, shared links
    aml-agent counterparty <customer_id> <name>
                                    one counterparty's view for one
                                    customer
    aml-agent shared-counterparties counterparties standing on more
                                    than one customer's cases — the
                                    network view
"""

from __future__ import annotations

import argparse
import json
import sys

from .errors import AmlError
from .wiring import build_services


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aml-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    p_intake = sub.add_parser("intake")
    p_intake.add_argument("alert_id")
    p_list = sub.add_parser("list")
    p_list.add_argument("--status", default=None)
    p_show = sub.add_parser("show")
    p_show.add_argument("case_id")
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("case_id")
    sub.add_parser("ingest-lists")
    sub.add_parser("snapshots")
    p_screen = sub.add_parser("screen")
    p_screen.add_argument("case_id")
    p_screen.add_argument("--sanctions", default=None)
    p_screen.add_argument("--pep", default=None)
    p_screen.add_argument("--adverse-media", default=None)
    p_screen.add_argument("--actor", default="screening-service")
    sub.add_parser("register-packs")
    sub.add_parser("packs")
    p_ingest_txn = sub.add_parser("ingest-transactions")
    p_ingest_txn.add_argument("case_id")
    p_run_typo = sub.add_parser("run-typologies")
    p_run_typo.add_argument("case_id")
    p_run_typo.add_argument("--pack", required=True)
    p_run_typo.add_argument("--version", required=True)
    p_run_typo.add_argument("--actor", default="typology-service")
    p_findings = sub.add_parser("findings")
    p_findings.add_argument("case_id")
    p_investigate = sub.add_parser("investigate")
    p_investigate.add_argument("case_id")
    p_investigate.add_argument("--profile", default="offline")
    p_investigate.add_argument("--actor", default="investigation-service")
    p_investigation = sub.add_parser("investigation")
    p_investigation.add_argument("case_id")
    p_disposition = sub.add_parser("disposition")
    p_disposition.add_argument("case_id")
    p_disposition.add_argument("--analyst", required=True)
    p_disposition.add_argument("--role", required=True)
    p_disposition.add_argument("--outcome", required=True)
    p_disposition.add_argument("--code", action="append", default=[])
    p_disposition.add_argument("--record-id", required=True)
    p_disposition.add_argument("--record-version", type=int, required=True)
    p_disposition.add_argument("--note", default="")
    p_disposition.add_argument("--review-days", type=int, default=None)
    p_disposition.add_argument("--missing", action="append", default=[])
    p_confirm = sub.add_parser("confirm")
    p_confirm.add_argument("case_id")
    p_confirm.add_argument("--confirmer", required=True)
    p_confirm.add_argument("--role", required=True)
    p_confirm.add_argument(
        "--outcome", choices=["confirmed", "declined"], required=True
    )
    p_confirm.add_argument("--note", default="")
    p_dispositions = sub.add_parser("dispositions")
    p_dispositions.add_argument("case_id")
    p_queue = sub.add_parser("queue")
    p_queue.add_argument("kind", choices=["confirmations", "escalations"])
    p_draft_sar = sub.add_parser("draft-sar")
    p_draft_sar.add_argument("case_id")
    p_draft_sar.add_argument("--profile", default="offline")
    p_draft_sar.add_argument("--actor", default="sar-drafting-service")
    p_sar = sub.add_parser("sar")
    p_sar.add_argument("case_id")
    p_verify_sar = sub.add_parser("verify-sar")
    p_verify_sar.add_argument("case_id")
    p_approve_sar = sub.add_parser("approve-sar")
    p_approve_sar.add_argument("case_id")
    p_approve_sar.add_argument("--approver", required=True)
    p_approve_sar.add_argument("--role", required=True)
    p_approve_sar.add_argument(
        "--outcome", choices=["approved", "rejected"], required=True
    )
    p_approve_sar.add_argument("--code", action="append", default=[])
    p_approve_sar.add_argument("--note", default="")
    p_case_file = sub.add_parser("case-file")
    p_case_file.add_argument("case_id")
    p_seal = sub.add_parser("seal")
    p_seal.add_argument("case_id")
    p_seal.add_argument("--officer", required=True)
    p_seal.add_argument("--role", required=True)
    p_seal.add_argument("--purpose", default="custody")
    p_unseal = sub.add_parser("unseal")
    p_unseal.add_argument("case_id")
    p_unseal.add_argument("--officer", required=True)
    p_unseal.add_argument("--role", required=True)
    p_unseal.add_argument("--code", required=True)
    p_unseal.add_argument("--note", default="")
    p_hold = sub.add_parser("hold")
    p_hold.add_argument("case_id")
    p_hold.add_argument("--officer", required=True)
    p_hold.add_argument("--role", required=True)
    p_hold.add_argument("--code", required=True)
    p_hold.add_argument("--note", default="")
    p_release_hold = sub.add_parser("release-hold")
    p_release_hold.add_argument("case_id")
    p_release_hold.add_argument("--officer", required=True)
    p_release_hold.add_argument("--role", required=True)
    p_release_hold.add_argument("--code", required=True)
    p_release_hold.add_argument("--note", default="")
    p_export = sub.add_parser("export")
    p_export.add_argument("case_id")
    p_export.add_argument("--out", default=None)
    p_verify_export = sub.add_parser("verify-export")
    p_verify_export.add_argument("file")
    p_clock = sub.add_parser("clock")
    p_clock.add_argument("case_id")
    p_clock.add_argument("--as-of", default=None)
    p_clock_board = sub.add_parser("clock-board")
    p_clock_board.add_argument("--as-of", default=None)
    p_clock_esc = sub.add_parser("clock-escalations")
    p_clock_esc.add_argument("--as-of", default=None)

    p_open_review = sub.add_parser("open-review")
    p_open_review.add_argument("case_id")
    p_open_review.add_argument(
        "--actor", default="continuing-review-service"
    )
    p_review = sub.add_parser("review")
    p_review.add_argument("case_id")
    p_reviews = sub.add_parser("reviews")
    p_reviews.add_argument("--customer", required=True)
    p_disp_review = sub.add_parser("disposition-review")
    p_disp_review.add_argument("case_id")
    p_disp_review.add_argument("review_id")
    p_disp_review.add_argument("--analyst", required=True)
    p_disp_review.add_argument("--role", required=True)
    p_disp_review.add_argument("--outcome", required=True)
    p_disp_review.add_argument("--code", action="append", default=[])
    p_disp_review.add_argument("--note", default="")
    p_open_due = sub.add_parser("open-due-reviews")
    p_open_due.add_argument("--as-of", default=None)
    p_open_due.add_argument("--actor", default="clock-service")
    p_quarantine = sub.add_parser("quarantine")
    p_quarantine.add_argument("case_id")
    sub.add_parser("quarantine-queue")
    p_q_review = sub.add_parser("quarantine-review")
    p_q_review.add_argument("case_id")
    p_q_review.add_argument("quarantine_seq", type=int)
    p_q_review.add_argument("--reviewer", required=True)
    p_q_review.add_argument("--note", default="")
    p_profile = sub.add_parser("profile")
    p_profile.add_argument("customer_id")
    p_profile.add_argument("--as-of", default=None)
    p_profile.add_argument("--actor", default="kyc-service")
    p_profile_show = sub.add_parser("profile-show")
    p_profile_show.add_argument("customer_id")
    p_case_profile = sub.add_parser("case-profile")
    p_case_profile.add_argument("case_id")
    p_counterparties = sub.add_parser("counterparties")
    p_counterparties.add_argument("customer_id")
    p_counterparty = sub.add_parser("counterparty")
    p_counterparty.add_argument("customer_id")
    p_counterparty.add_argument("name")
    sub.add_parser("shared-counterparties")
    args = parser.parse_args(argv)

    services = build_services()
    try:
        if args.command == "intake":
            case = services.intake.open_case(args.alert_id)
            print(json.dumps(case.model_dump(mode="json"), indent=2))
        elif args.command == "list":
            cases = services.store.list_cases(args.status)
            print(json.dumps([c.model_dump(mode="json") for c in cases], indent=2))
        elif args.command == "show":
            case = services.store.get_case(args.case_id)
            if case is None:
                print(f"case not found: {args.case_id}", file=sys.stderr)
                return 1
            out = {
                "case": case.model_dump(mode="json"),
                "evidence": [
                    i.model_dump(mode="json")
                    for i in services.store.list_evidence(args.case_id)
                ],
                "audit": [
                    e.model_dump(mode="json")
                    for e in services.store.list_audit(args.case_id)
                ],
            }
            print(json.dumps(out, indent=2))
        elif args.command == "verify":
            intact = services.evidence.verify_chain(args.case_id)
            print(json.dumps({"case_id": args.case_id, "chain_intact": intact}))
        elif args.command == "ingest-lists":
            snapshots = services.screening.ingest_from_source(services.screening_feed)
            print(
                json.dumps(
                    [s.model_dump(mode="json") for s in snapshots], indent=2
                )
            )
        elif args.command == "snapshots":
            print(
                json.dumps(
                    [
                        s.model_dump(mode="json")
                        for s in services.store.list_snapshots()
                    ],
                    indent=2,
                )
            )
        elif args.command == "screen":
            pins = {}
            if args.sanctions:
                pins["sanctions"] = args.sanctions
            if args.pep:
                pins["pep"] = args.pep
            if args.adverse_media:
                pins["adverse_media"] = args.adverse_media
            run = services.screening.screen_case(
                args.case_id, pins, actor=args.actor
            )
            hits = [
                h
                for h in services.store.list_hits(args.case_id)
                if h.run_id == run.run_id
            ]
            print(
                json.dumps(
                    {
                        "run": run.model_dump(mode="json"),
                        "hits": [h.model_dump(mode="json") for h in hits],
                    },
                    indent=2,
                )
            )
        elif args.command == "register-packs":
            packs = services.typologies.register_from_source(services.rule_pack_feed)
            print(json.dumps([p.model_dump(mode="json") for p in packs], indent=2))
        elif args.command == "packs":
            print(
                json.dumps(
                    [
                        p.model_dump(mode="json")
                        for p in services.store.list_rule_packs()
                    ],
                    indent=2,
                )
            )
        elif args.command == "ingest-transactions":
            batch = services.typologies.ingest_from_source(
                args.case_id, services.transactions
            )
            print(json.dumps(batch.model_dump(mode="json"), indent=2))
        elif args.command == "run-typologies":
            run = services.typologies.run_typologies(
                args.case_id, args.pack, args.version, actor=args.actor
            )
            findings = services.typologies.list_findings(
                args.case_id, run_id=run.run_id
            )
            print(
                json.dumps(
                    {
                        "run": run.model_dump(mode="json"),
                        "findings": [
                            f.model_dump(mode="json") for f in findings
                        ],
                    },
                    indent=2,
                )
            )
        elif args.command == "findings":
            findings = services.typologies.list_findings(args.case_id)
            print(
                json.dumps(
                    [f.model_dump(mode="json") for f in findings], indent=2
                )
            )
        elif args.command == "investigate":
            record = services.investigations.run_investigation(
                args.case_id, actor=args.actor, profile=args.profile
            )
            print(json.dumps(record.model_dump(mode="json"), indent=2))
        elif args.command == "investigation":
            if services.store.get_case(args.case_id) is None:
                print(f"case not found: {args.case_id}", file=sys.stderr)
                return 1
            current = services.investigations.current_record(args.case_id)
            print(
                json.dumps(
                    {
                        "case_id": args.case_id,
                        "current": (
                            current.model_dump(mode="json")
                            if current is not None
                            else None
                        ),
                        "history": [
                            r.model_dump(mode="json")
                            for r in services.investigations.record_history(
                                args.case_id
                            )
                        ],
                    },
                    indent=2,
                )
            )
        elif args.command == "disposition":
            from .models import DispositionOutcome

            record = services.dispositions.record_disposition(
                args.case_id,
                analyst_id=args.analyst,
                analyst_role=args.role,
                outcome=DispositionOutcome(args.outcome),
                rationale_codes=args.code,
                record_id=args.record_id,
                record_version=args.record_version,
                note=args.note,
                review_period_days=args.review_days,
                missing_evidence=args.missing,
            )
            print(
                json.dumps(
                    {
                        "disposition": services.dispositions.view(record),
                        "case_status": services.store.get_case(
                            args.case_id
                        ).status.value,
                    },
                    indent=2,
                )
            )
        elif args.command == "confirm":
            from .models import ConfirmationOutcome

            confirmation = services.dispositions.confirm_disposition(
                args.case_id,
                confirmer_id=args.confirmer,
                confirmer_role=args.role,
                outcome=ConfirmationOutcome(args.outcome),
                note=args.note,
            )
            print(
                json.dumps(
                    {
                        "confirmation": confirmation.model_dump(mode="json"),
                        "case_status": services.store.get_case(
                            args.case_id
                        ).status.value,
                    },
                    indent=2,
                )
            )
        elif args.command == "dispositions":
            if services.store.get_case(args.case_id) is None:
                print(f"case not found: {args.case_id}", file=sys.stderr)
                return 1
            print(
                json.dumps(
                    {
                        "case_id": args.case_id,
                        "dispositions": [
                            services.dispositions.view(r)
                            for r in services.dispositions.history(args.case_id)
                        ],
                        "confirmations": [
                            c.model_dump(mode="json")
                            for c in services.dispositions.confirmations(
                                args.case_id
                            )
                        ],
                    },
                    indent=2,
                )
            )
        elif args.command == "queue":
            if args.kind == "confirmations":
                entries = services.dispositions.confirmation_queue()
            else:
                entries = services.dispositions.escalation_queue()
            print(json.dumps(entries, indent=2))
        elif args.command == "draft-sar":
            narrative, verification = services.sar.draft_narrative(
                args.case_id, actor=args.actor, profile=args.profile
            )
            print(
                json.dumps(
                    {
                        "narrative": services.sar.view(narrative),
                        "verification": verification.model_dump(mode="json"),
                    },
                    indent=2,
                )
            )
        elif args.command == "sar":
            if services.store.get_case(args.case_id) is None:
                print(f"case not found: {args.case_id}", file=sys.stderr)
                return 1
            current = services.sar.current_narrative(args.case_id)
            print(
                json.dumps(
                    {
                        "case_id": args.case_id,
                        "current": (
                            services.sar.view(current)
                            if current is not None
                            else None
                        ),
                        "history": [
                            services.sar.view(n)
                            for n in services.sar.narrative_history(
                                args.case_id
                            )
                        ],
                    },
                    indent=2,
                )
            )
        elif args.command == "verify-sar":
            verification = services.sar.verify_narrative(args.case_id)
            print(json.dumps(verification.model_dump(mode="json"), indent=2))
        elif args.command == "approve-sar":
            from .models import ApprovalOutcome

            approval = services.approvals.decide_narrative(
                args.case_id,
                approver_id=args.approver,
                approver_role=args.role,
                outcome=ApprovalOutcome(args.outcome),
                reason_codes=args.code,
                note=args.note,
            )
            print(
                json.dumps(
                    {
                        "approval": services.approvals.view(approval),
                        "case_status": services.store.get_case(
                            args.case_id
                        ).status.value,
                    },
                    indent=2,
                )
            )
        elif args.command == "case-file":
            if services.store.get_case(args.case_id) is None:
                print(f"case not found: {args.case_id}", file=sys.stderr)
                return 1
            print(
                json.dumps(
                    services.sealing.case_file_view(args.case_id),
                    indent=2,
                )
            )
        elif args.command == "seal":
            seal = services.sealing.seal_case(
                args.case_id,
                officer_id=args.officer,
                officer_role=args.role,
                purpose=args.purpose,
            )
            print(
                json.dumps(
                    {"seal": services.sealing.view(seal)}, indent=2
                )
            )
        elif args.command == "unseal":
            unseal = services.sealing.unseal_case(
                args.case_id,
                officer_id=args.officer,
                officer_role=args.role,
                reason_code=args.code,
                note=args.note,
            )
            print(json.dumps(unseal.model_dump(mode="json"), indent=2))
        elif args.command == "hold":
            event = services.sealing.place_hold(
                args.case_id,
                officer_id=args.officer,
                officer_role=args.role,
                reason_code=args.code,
                note=args.note,
            )
            print(json.dumps(event.model_dump(mode="json"), indent=2))
        elif args.command == "release-hold":
            event = services.sealing.release_hold(
                args.case_id,
                officer_id=args.officer,
                officer_role=args.role,
                reason_code=args.code,
                note=args.note,
            )
            print(json.dumps(event.model_dump(mode="json"), indent=2))
        elif args.command == "export":
            package = services.sealing.export_case_file(args.case_id)
            rendered = json.dumps(package, indent=2)
            if args.out:
                from pathlib import Path

                Path(args.out).write_text(rendered + "\n", encoding="utf-8")
                print(
                    json.dumps(
                        {
                            "exported": args.out,
                            "case_id": args.case_id,
                            "seal_id": package["seal"]["seal_id"],
                            "items": len(package["items"]),
                        }
                    )
                )
            else:
                print(rendered)
        elif args.command == "verify-export":
            from pathlib import Path

            from .sealing import verify_export_package

            package = json.loads(
                Path(args.file).read_text(encoding="utf-8")
            )
            result = verify_export_package(package)
            print(json.dumps(result.model_dump(mode="json"), indent=2))
            return 0 if result.ok else 1
        elif args.command == "clock":
            from datetime import date

            as_of = (
                date.fromisoformat(args.as_of)
                if args.as_of
                else date.today()
            )
            view = services.clocks.case_clocks(args.case_id, as_of=as_of)
            print(json.dumps(view.model_dump(mode="json"), indent=2))
        elif args.command == "clock-board":
            from datetime import date

            as_of = (
                date.fromisoformat(args.as_of)
                if args.as_of
                else date.today()
            )
            services.clocks.refresh_all_escalations(as_of=as_of)
            board = services.clocks.clock_board(as_of=as_of)
            print(
                json.dumps(
                    [v.model_dump(mode="json") for v in board], indent=2
                )
            )
        elif args.command == "clock-escalations":
            from datetime import date

            as_of = (
                date.fromisoformat(args.as_of)
                if args.as_of
                else date.today()
            )
            services.clocks.refresh_all_escalations(as_of=as_of)
            queue = services.clocks.escalation_queue(as_of=as_of)
            print(
                json.dumps(
                    [e.model_dump(mode="json") for e in queue], indent=2
                )
            )
        elif args.command == "open-review":
            review = services.reviews.open_review(
                args.case_id, actor=args.actor
            )
            print(
                json.dumps(
                    services.reviews.review_view(review), indent=2
                )
            )
        elif args.command == "review":
            from datetime import date

            clocks = services.clocks.case_clocks(
                args.case_id, as_of=date.today()
            )
            print(
                json.dumps(
                    {
                        "case_id": args.case_id,
                        "current": services.reviews.current_review(
                            args.case_id
                        ),
                        "history": services.reviews.reviews_for_case(
                            args.case_id
                        ),
                        "continuing_cycles": [
                            c.model_dump(mode="json")
                            for c in clocks.continuing_history
                        ],
                    },
                    indent=2,
                )
            )
        elif args.command == "reviews":
            print(
                json.dumps(
                    services.reviews.history_for_customer(args.customer),
                    indent=2,
                )
            )
        elif args.command == "disposition-review":
            from .models import ReviewOutcome

            disposition = services.reviews.record_review_disposition(
                args.case_id,
                args.review_id,
                analyst_id=args.analyst,
                analyst_role=args.role,
                outcome=ReviewOutcome(args.outcome),
                rationale_codes=args.code,
                note=args.note,
            )
            print(
                json.dumps(
                    disposition.model_dump(mode="json"), indent=2
                )
            )
        elif args.command == "open-due-reviews":
            from datetime import date

            as_of = (
                date.fromisoformat(args.as_of)
                if args.as_of
                else date.today()
            )
            opened = services.reviews.open_due_reviews(
                as_of=as_of, actor=args.actor
            )
            print(
                json.dumps(
                    [
                        services.reviews.review_view(r) for r in opened
                    ],
                    indent=2,
                )
            )
        elif args.command == "quarantine":
            records = services.quarantine.records_for(args.case_id)
            print(
                json.dumps(
                    [services.quarantine.view(r) for r in records],
                    indent=2,
                )
            )
        elif args.command == "quarantine-queue":
            print(
                json.dumps(
                    [
                        e.model_dump(mode="json")
                        for e in services.quarantine.queue()
                    ],
                    indent=2,
                )
            )
        elif args.command == "quarantine-review":
            review = services.quarantine.mark_reviewed(
                args.case_id,
                args.quarantine_seq,
                reviewer=args.reviewer,
                note=args.note,
            )
            print(json.dumps(review.model_dump(mode="json"), indent=2))
        elif args.command == "profile":
            from datetime import date

            as_of = (
                date.fromisoformat(args.as_of)
                if args.as_of
                else date.today()
            )
            view = services.profiles.assemble_profile(
                args.customer_id, as_of=as_of, actor=args.actor
            )
            print(json.dumps(view.model_dump(mode="json"), indent=2))
        elif args.command == "profile-show":
            view = services.profiles.latest_view(args.customer_id)
            print(json.dumps(view.model_dump(mode="json"), indent=2))
        elif args.command == "case-profile":
            view = services.profiles.profile_for_case(args.case_id)
            print(json.dumps(view.model_dump(mode="json"), indent=2))
        elif args.command == "counterparties":
            views = services.profiles.counterparties_for_customer(
                args.customer_id
            )
            print(
                json.dumps(
                    [v.model_dump(mode="json") for v in views], indent=2
                )
            )
        elif args.command == "counterparty":
            view = services.profiles.counterparty_detail(
                args.customer_id, args.name
            )
            print(json.dumps(view.model_dump(mode="json"), indent=2))
        elif args.command == "shared-counterparties":
            shared = services.profiles.shared_counterparties()
            print(
                json.dumps(
                    [s.model_dump(mode="json") for s in shared], indent=2
                )
            )
    except AmlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
