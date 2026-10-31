"""PhiVine read-only planning and fixed-fixture sandbox qualification CLI.

No user-provided executable is launched by any command.
"""

import argparse
import json
import sys

from .inspector import InspectionError, inspect_file
from .planner import plan_launch
from .sandbox import qualify_fixture_sandbox


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phivine",
        description="Inspect local binaries, plan held launches and qualify a fixed Linux fixture.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="Read-only offline file evidence")
    inspect.add_argument("path", help="Local .exe or .msi candidate")
    plan = sub.add_parser("plan", help="Read-only non-executable Wine launch proposal")
    plan.add_argument("path", help="Local .exe or .msi candidate")
    plan.add_argument(
        "--request-network",
        action="store_true",
        help="Record a network permission review request; never grants network access",
    )
    sub.add_parser(
        "sandbox-check",
        help="Run only a fixed, harmless Linux bubblewrap isolation fixture; no Wine or Windows app",
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            report = inspect_file(args.path)
        elif args.command == "plan":
            report = plan_launch(args.path, request_network=args.request_network)
        else:
            report = qualify_fixture_sandbox()
    except (InspectionError, OSError, ValueError) as exc:
        print(json.dumps({"schema": "phivine.error.v0.1", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    # A HELD sandbox result is an unsuccessful qualification and must be
    # machine-detectable; unlike ordinary advisory inspection, it exits 3.
    if args.command == "sandbox-check" and not report["fixture_boundary_passed"]:
        return 3
    return 0
