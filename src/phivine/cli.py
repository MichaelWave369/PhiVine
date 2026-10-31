"""PhiVine inspection, held proposals, revalidation and sandbox fixture CLI.

No command executes a Windows application.
"""

import argparse
import json
import sys

from .inspector import InspectionError, inspect_file
from .planner import plan_launch
from .revalidate import read_plan_json, revalidate_plan
from .sandbox import qualify_fixture_sandbox


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phivine",
        description="Inspect, plan, revalidate and qualify a fixed fixture without executing Windows apps.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="Read-only offline Windows binary evidence")
    inspect.add_argument("path", help="Local .exe or .msi candidate")
    plan = sub.add_parser("plan", help="Read-only, non-executable Wine launch proposal")
    plan.add_argument("path", help="Local .exe or .msi candidate")
    plan.add_argument(
        "--request-network", action="store_true",
        help="Request a future network permission review; never grants access",
    )
    verify = sub.add_parser(
        "verify-plan",
        help="Reopen the proposed file without following symlinks and check its exact digest; no launch",
    )
    verify.add_argument("proposal_json", help="Local JSON produced by phivine plan")
    sub.add_parser(
        "sandbox-check",
        help="Run only a fixed, harmless Linux bubblewrap fixture; no Wine or Windows app",
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            report = inspect_file(args.path)
        elif args.command == "plan":
            report = plan_launch(args.path, request_network=args.request_network)
        elif args.command == "verify-plan":
            report = revalidate_plan(read_plan_json(args.proposal_json))
        else:
            report = qualify_fixture_sandbox()
    except (InspectionError, OSError, ValueError) as exc:
        print(json.dumps({"schema": "phivine.error.v0.1", "error": str(exc)}), file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2, sort_keys=True))
    if args.command == "sandbox-check" and not report["fixture_boundary_passed"]:
        return 3
    if args.command == "verify-plan" and not report["artifact_match_observed"]:
        return 3
    return 0
