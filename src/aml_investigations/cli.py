"""Command-line entry point: intake and case inspection.

Usage:
    aml-agent intake <alert_id>     open a case from a feed alert
    aml-agent list [--status S]     list cases
    aml-agent show <case_id>        show one case + evidence + audit
    aml-agent verify <case_id>      verify the evidence hash chain
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
    except AmlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
