"""PhiVine evidence CLI: no user-provided executable is ever launched."""

import argparse
import json
import sys

from .inspector import InspectionError, inspect_file
from .import_triage import review_pe_imports
from .pe_imports import inspect_pe_imports
from .phios_handoff import build_phios_handoff
from .planner import plan_launch
from .revalidate import read_plan_json, revalidate_plan
from .runner import observe_runner
from .runner_resolve import resolve_runner
from .sandbox import qualify_fixture_sandbox
from .staging import stage_plan
from .stage_verify import verify_stage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phivine",
        description="Offline Windows compatibility evidence, never execution authority.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="Read-only Windows binary evidence")
    inspect.add_argument("path", help="Local .exe or .msi candidate")
    imports = sub.add_parser("inspect-imports", help="Bounded read-only direct PE import DLL names (HELD)")
    imports.add_argument("path", help="Local .exe; no code or DLL execution")
    triage = sub.add_parser("triage-imports", help="Review direct DLL names without granting compatibility")
    triage.add_argument("path", help="Local .exe input for read-only inspection")
    plan = sub.add_parser("plan", help="Non-executable Wine launch proposal")
    plan.add_argument("path", help="Local .exe or .msi candidate")
    plan.add_argument("--request-network", action="store_true",
                      help="Record future network review request; never grants access")
    verify = sub.add_parser("verify-plan", help="Read-only exact-file revalidation")
    verify.add_argument("proposal_json", help="Local JSON from phivine plan")
    stage = sub.add_parser("stage-plan",
                           help="Explicitly copy a planned .exe to an existing private store; no execution")
    stage.add_argument("proposal_json", help="Local JSON from phivine plan")
    stage.add_argument("--store", required=True,
                       help="Existing absolute private directory owned by the invoking user")
    check = sub.add_parser("verify-stage",
                           help="Read-only verification of staged bytes against a held proposal")
    check.add_argument("proposal_json", help="Local JSON from phivine plan")
    check.add_argument("--store", required=True, help="Existing absolute private stage directory")
    runner = sub.add_parser("observe-runner",
                            help="Read an exact ELF runner path and fingerprint bytes; never invokes it")
    runner.add_argument("path", help="Exact absolute local Wine ELF path; no PATH search")
    resolve = sub.add_parser("resolve-runner",
                             help="Observe bounded Wine symlink chains and wrappers; no execution")
    resolve.add_argument("path", help="Absolute local runner path; symlink targets are observations only")
    handoff = sub.add_parser(
        "phios-handoff",
        help="Build a path-redacted, permanently HELD advisory record for future PhiOS integration",
    )
    handoff.add_argument("proposal_json", help="Local held proposal JSON")
    handoff.add_argument("--store", help="Optional existing private stage directory for live verification")
    handoff.add_argument("--runner", help="Optional absolute Wine runner path for live observation")
    sub.add_parser("sandbox-check",
                   help="Run only a fixed harmless Bubblewrap fixture, not Windows applications")
    args = parser.parse_args(argv)

    try:
        if args.command == "inspect":
            report = inspect_file(args.path)
        elif args.command == "inspect-imports":
            report = inspect_pe_imports(args.path)
        elif args.command == "plan":
            report = plan_launch(args.path, request_network=args.request_network)
        elif args.command == "verify-plan":
            report = revalidate_plan(read_plan_json(args.proposal_json))
        elif args.command == "stage-plan":
            report = stage_plan(read_plan_json(args.proposal_json), args.store)
        elif args.command == "verify-stage":
            report = verify_stage(read_plan_json(args.proposal_json), args.store)
        elif args.command == "observe-runner":
            report = observe_runner(args.path)
        elif args.command == "resolve-runner":
            report = resolve_runner(args.path)
        elif args.command == "phios-handoff":
            report = build_phios_handoff(
                read_plan_json(args.proposal_json),
                stage_store=args.store,
                runner_path=args.runner,
            )
        else:
            report = qualify_fixture_sandbox()
    except (InspectionError, OSError, ValueError) as exc:
        print(json.dumps({"schema": "phivine.error.v0.1", "error": str(exc)}), file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2, sort_keys=True))
    # Names on disk are observations, never a compatibility or launch grant.
    if args.command == "inspect-imports":
        return 3
    if args.command == "sandbox-check" and not report["fixture_boundary_passed"]:
        return 3
    if args.command == "verify-plan" and not report["artifact_match_observed"]:
        return 3
    if args.command == "stage-plan" and not report["content_snapshot_created_or_reused"]:
        return 3
    if args.command == "verify-stage" and not report["staged_bytes_match_observed"]:
        return 3
    if args.command == "observe-runner" and not report["binary_identity_observed"]:
        return 3
    if args.command == "resolve-runner" and not report["resolved_elf_observed"]:
        return 3
    # A handoff can NEVER be interpreted as success/authorization by exit code.
    if args.command == "phios-handoff":
        return 3
    return 0
