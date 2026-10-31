"""PhiVine's read-only inspection and launch-planning CLI.

Neither command launches an executable or grants an effect permission.
"""

import argparse
import json
import sys

from .inspector import InspectionError, inspect_file
from .planner import plan_launch


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phivine",
        description="Inspect Windows binaries and propose held launch plans, without execution.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="Read-only offline file evidence")
    inspect.add_argument("path", help="Local .exe or .msi candidate")
    plan = sub.add_parser("plan", help="Read-only, non-executable Wine launch proposal")
    plan.add_argument("path", help="Local .exe or .msi candidate")
    plan.add_argument(
        "--request-network",
        action="store_true",
        help="Record a network permission request for human review; never grants network access",
    )
    args = parser.parse_args(argv)

    try:
        report = (
            inspect_file(args.path)
            if args.command == "inspect"
            else plan_launch(args.path, request_network=args.request_network)
        )
    except (InspectionError, OSError, ValueError) as exc:
        print(json.dumps({"schema": "phivine.error.v0.1", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0
