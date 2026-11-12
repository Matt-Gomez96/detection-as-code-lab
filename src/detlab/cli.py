"""Command line: ``uv run detlab <command>``.

  convert [--check]      Generate splunk/*.spl from rules/ (--check: only verify).
  show LOG [--limit N]   Print the events of a log as flat fields (to design rules).
  run RULE LOG           Run a Sigma rule against a log and print the matches.
  sql RULE               Print the SQL the local engine runs for a rule.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from detlab import convert, engine
from detlab.events import load_events


def _print_events(events: list[dict], limit: int | None = None) -> None:
    for event in events[:limit]:
        print(json.dumps(event, indent=2, ensure_ascii=False, default=str))


def cmd_convert(args: argparse.Namespace) -> int:
    root = Path.cwd()
    result = convert.convert_all(root, check=args.check)
    if args.check:
        problems = [*result.outdated, *result.stale]
        for path in result.outdated:
            print(f"out of date: {path.relative_to(root).as_posix()}")
        for path in result.stale:
            print(f"no matching rule: {path.relative_to(root).as_posix()}")
        if problems:
            print("Run `uv run detlab convert` and commit the result.")
            return 1
        print("Splunk queries are up to date.")
        return 0
    for path in result.written:
        print(f"wrote {path.relative_to(root).as_posix()}")
    for path in result.stale:
        print(f"removed {path.relative_to(root).as_posix()}")
    if not result.written and not result.stale:
        print("Nothing to do: Splunk queries are up to date.")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    events = load_events(args.log)
    print(f"# {len(events)} events in {args.log}", file=sys.stderr)
    _print_events(events, args.limit)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    events = load_events(args.log)
    matches = engine.match(args.rule, events)
    print(f"# {len(matches)} of {len(events)} events matched", file=sys.stderr)
    _print_events(matches, args.limit)
    return 0


def cmd_sql(args: argparse.Namespace) -> int:
    for query in engine.to_sql(args.rule):
        print(query)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detlab", description="Detection-as-Code lab tooling")
    commands = parser.add_subparsers(dest="command", required=True)

    p = commands.add_parser("convert", help="generate splunk/*.spl from rules/")
    p.add_argument("--check", action="store_true", help="only verify, do not write")
    p.set_defaults(func=cmd_convert)

    p = commands.add_parser("show", help="print the events of a log as flat fields")
    p.add_argument("log", type=Path)
    p.add_argument("--limit", type=int, default=5, help="events to print (default 5)")
    p.set_defaults(func=cmd_show)

    p = commands.add_parser("run", help="run a Sigma rule against a log")
    p.add_argument("rule", type=Path)
    p.add_argument("log", type=Path)
    p.add_argument("--limit", type=int, default=10, help="matches to print (default 10)")
    p.set_defaults(func=cmd_run)

    p = commands.add_parser("sql", help="print the SQL used by the local engine")
    p.add_argument("rule", type=Path)
    p.set_defaults(func=cmd_sql)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
