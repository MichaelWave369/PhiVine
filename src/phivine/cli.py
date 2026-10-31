"""PhiVine's intentionally non-executing Rung 1 CLI."""

import argparse
import json
import sys

from .inspector import InspectionError, inspect_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phivine",
        description="Inspect a local Windows binary without executing it.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="Read-only offline evidence report")
    inspect.add_argument("path", help="Local .exe or .msi candidate")
    args = parser.parse_args(argv)

    try:
        report = inspect_file(args.path)
    except (InspectionError, OSError) as exc:
        print(json.dumps({"schema": "phivine.error.v0.1", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0
