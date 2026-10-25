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
    except AmlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
