"""Command-line entry point: intake, case inspection, screening.

Usage:
    aml-agent intake <alert_id>     open a case from a feed alert
    aml-agent list [--status S]     list cases
    aml-agent show <case_id>        show one case + evidence + audit
    aml-agent verify <case_id>      verify the evidence hash chain
    aml-agent ingest-lists          ingest snapshots from the list feed
    aml-agent snapshots             list ingested snapshots
    aml-agent screen <case_id> --sanctions V [--pep V] [--adverse-media V]
                                    screen a case against a pinned set
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
    except AmlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
