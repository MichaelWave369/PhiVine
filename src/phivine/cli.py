"""PhiVine inspect, plan, verify, stage and observe runner identities.

No CLI command launches Wine or any user-provided Windows executable.
"""

import argparse
import json
import sys

from .inspector import InspectionError, inspect_file
from .planner import plan_launch
from .revalidate import read_plan_json, revalidate_plan
from .runner import observe_runner
from .sandbox import qualify_fixture_sandbox
from .staging import stage_plan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phivine",
        description="Offline Windows binary evidence and separately requested snapshot staging.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="Read-only Windows binary evidence")
    inspect.add_argument("path", help="Local .exe or .msi candidate")
    plan = sub.add_parser("plan", help="Non-executable Wine launch proposal")
    plan.add_argument("path", help="Local .exe or .msi candidate")
    plan.add_argument("--request-network", action="store_true",
                      help="Record future network review request; never grants access")
    verify = sub.add_parser("verify-plan", help="Read-only exact-file revalidation")
    verify.add_argument("proposal_json", help="Local JSON from phivine plan")
    stage = sub.add_parser("stage-plan",
                           help="Explicitly copy a planned .exe into an existing private store; no execution")
    stage.add_argument("proposal_json", help="Local JSON from phivine plan")
    stage.add_argument("--store", required=True,
                       help="Existing absolute private 0700 directory, owned by the invoking user")
    runner = sub.add_parser("observe-runner",
                            help="Read an exact ELF runner path and hash bytes; never invokes it")
    runner.add_argument("path", help="Exact absolute local Wine ELF path; no PATH search")
    sub.add_parser("sandbox-check",
                   help="Run only fixed harmless Bubblewrap fixture, not Windows applications")
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            report = inspect_file(args.path)
        elif args.command == "plan":
            report = plan_launch(args.path, request_network=args.request_network)
        elif args.command == "verify-plan":
            report = revalidate_plan(read_plan_json(args.proposal_json))
        elif args.command == "stage-plan":
            report = stage_plan(read_plan_json(args.proposal_json), args.store)
        elif args.command == "observe-runner":
            report = observe_runner(args.path)
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
    if args.command == "stage-plan" and not report["content_snapshot_created_or_reused"]:
        return 3
    if args.command == "observe-runner" and not report["binary_identity_observed"]:
        return 3
    return 0
