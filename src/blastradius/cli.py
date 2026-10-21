"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .feed import FeedError, bundled_feed_names, load_feed_file, resolve_feeds
from .models import SEVERITIES, severity_rank
from .report import to_json, to_text
from .scan import scan

EXIT_OK, EXIT_FOUND, EXIT_USAGE = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blastradius",
        description="Find out whether a compromised package reached this machine, when, "
        "and what to rotate. Offline; reads advisory IOC feeds.",
    )
    parser.add_argument("--version", action="version", version=f"blastradius {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="sweep this machine against one or more advisory feeds")
    sc.add_argument(
        "--feed",
        action="append",
        default=[],
        metavar="NAME|FILE",
        help="bundled feed name or path to a feed JSON (repeatable; default: all bundled)",
    )
    sc.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="DIR",
        help="directory to sweep (repeatable; default: your home directory)",
    )
    sc.add_argument(
        "--logs",
        action="append",
        default=[],
        metavar="FILE",
        help="extra text file (proxy/DNS/CI log) to search for IOC domains",
    )
    sc.add_argument(
        "--no-host-checks",
        action="store_true",
        help="skip host artifact paths and shell-history domain search",
    )
    sc.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    sc.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="medium",
        help="exit 1 if any finding has at least this severity (default: medium)",
    )
    sc.add_argument("--no-color", action="store_true")
    sc.add_argument("-q", "--quiet", action="store_true", help="no progress output on stderr")

    sub.add_parser("feeds", help="list bundled advisory feeds")

    val = sub.add_parser("validate", help="validate a feed file")
    val.add_argument("file", type=Path)
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        feeds, _ = resolve_feeds(args.feed)
    except FeedError as exc:
        print(f"blastradius: {exc}", file=sys.stderr)
        return EXIT_USAGE
    roots = args.root or [os.path.expanduser("~")]
    missing = [r for r in roots if not os.path.isdir(os.path.expanduser(r))]
    if missing:
        print(f"blastradius: not a directory: {', '.join(missing)}", file=sys.stderr)
        return EXIT_USAGE

    show_progress = not args.quiet and sys.stderr.isatty()

    def progress(n: int) -> None:
        print(f"\r  scanned {n} directories...", end="", file=sys.stderr, flush=True)

    result = scan(
        feeds,
        roots,
        host_checks=not args.no_host_checks,
        log_files=args.logs,
        progress=progress if show_progress else None,
    )
    if show_progress:
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)

    if args.format == "json":
        print(to_json(result))
    else:
        color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        print(
            to_text(result, color=color and args.format == "text", markdown=args.format == "markdown"), end=""
        )

    threshold = severity_rank(args.fail_on)
    return EXIT_FOUND if any(severity_rank(f.severity) >= threshold for f in result.findings) else EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "feeds":
        for name in bundled_feed_names():
            print(name)
        return EXIT_OK
    if args.command == "validate":
        try:
            feed = load_feed_file(args.file)
        except FeedError as exc:
            print(f"invalid: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(
            f"ok: {feed.id} ({len(feed.packages)} packages, {len(feed.files)} files, "
            f"{len(feed.domains)} domains)"
        )
        return EXIT_OK
    try:
        return _cmd_scan(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
