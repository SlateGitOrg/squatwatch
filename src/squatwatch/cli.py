"""Command-line interface.

Exit codes (stable, for CI):

====  ==========================================================================
0     no finding at or above ``--fail-on``
1     at least one finding at or above ``--fail-on``
2     usage error (bad arguments)
3     input error: config/registry fixture invalid, path missing, or a manifest
      could not be parsed (ignored with ``--ignore-errors``); findings win over this
4     internal error (a bug — please report it)
====  ==========================================================================
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from squatwatch import __version__
from squatwatch.checker import CheckerSettings, NameChecker
from squatwatch.config import Config, load_config
from squatwatch.confusion import InternalPolicy
from squatwatch.errors import SquatwatchError
from squatwatch.evaluation import build_dataset, render_markdown, score_items
from squatwatch.hooks.review import review_path
from squatwatch.models import Ecosystem, ScanResult, Severity
from squatwatch.popular import PopularIndex, snapshot_metadata
from squatwatch.registry import FixtureRegistry, HttpRegistryClient, RegistryClient
from squatwatch.report import render_json, render_sarif, render_text
from squatwatch.scanner import Scanner

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INPUT = 3
EXIT_INTERNAL = 4

log = logging.getLogger("squatwatch")


def _severity(text: str) -> Severity:
    try:
        return Severity.parse(text)
    except SquatwatchError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _score(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from exc
    if not 0 <= value <= 1:
        raise argparse.ArgumentTypeError("must be between 0 and 1")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="squatwatch",
        description="Detect typosquats, dependency confusion and risky build hooks "
        "in npm and PyPI manifests, lockfiles and package archives.",
    )
    parser.add_argument("--version", action="version", version=f"squatwatch {__version__}")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="more logging (-vv debug)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def output_opts(p: argparse.ArgumentParser, default_fail: str) -> None:
        p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
        p.add_argument("-o", "--output", type=Path, help="write the report to a file")
        p.add_argument(
            "--fail-on",
            type=_severity,
            default=None,
            help=f"lowest severity that makes the exit code 1 (default: config or {default_fail})",
        )
        p.add_argument("--ignore-errors", action="store_true", help="do not exit 3 on input errors")

    scan = sub.add_parser("scan", help="scan manifests, lockfiles, directories and archives")
    scan.add_argument("paths", nargs="+", type=Path)
    scan.add_argument(
        "-c", "--config", type=Path, help="squatwatch.toml (default: look in the first directory)"
    )
    scan.add_argument("--min-score", type=_score, help="typosquat reporting threshold")
    scan.add_argument(
        "--internal",
        action="append",
        default=[],
        metavar="NAME",
        help="internal package name (repeatable)",
    )
    scan.add_argument(
        "--internal-scope", action="append", default=[], metavar="@SCOPE", help="internal npm scope"
    )
    reg = scan.add_mutually_exclusive_group()
    reg.add_argument(
        "--registry", type=Path, metavar="FIXTURE.json", help="offline registry answers"
    )
    reg.add_argument(
        "--online",
        action="store_true",
        help="query pypi.org / registry.npmjs.org for internal names",
    )
    scan.add_argument("--no-hooks", action="store_true", help="skip build/install hook review")
    output_opts(scan, "high")

    check = sub.add_parser("check", help="check package names typed on the command line")
    check.add_argument("names", nargs="+")
    check.add_argument("-e", "--ecosystem", choices=[e.value for e in Ecosystem], required=True)
    check.add_argument("--min-score", type=_score, default=CheckerSettings().min_score)
    output_opts(check, "low")

    review = sub.add_parser("review", help="review build/install hooks of archives or source trees")
    review.add_argument("paths", nargs="+", type=Path)
    output_opts(review, "high")

    ev = sub.add_parser("eval", help="run the labelled evaluation (dev sweep + held-out test)")
    ev.add_argument("--data-dir", type=Path, default=Path("data/eval"))
    ev.add_argument("-o", "--output", type=Path)

    sub.add_parser("snapshot", help="show the bundled popular-package snapshot metadata")
    return parser


def _emit(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        log.info("wrote %s", output)


def _render(result: ScanResult, fmt: str, fail_on: Severity, verbose: bool) -> str:
    if fmt == "json":
        return render_json(result, fail_on=fail_on)
    if fmt == "sarif":
        return render_sarif(result)
    return render_text(result, fail_on=fail_on, verbose=verbose)


def _exit_code(result: ScanResult, fail_on: Severity, ignore_errors: bool) -> int:
    if any(f.severity >= fail_on for f in result.findings):
        return EXIT_FINDINGS
    if result.errors and not ignore_errors:
        return EXIT_INPUT
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    first_dir = next((p for p in args.paths if p.is_dir()), None)
    config = load_config(args.config, search_dir=first_dir)
    if args.min_score is not None:
        config.min_score = args.min_score
    if args.no_hooks:
        config.hooks = False
    if args.internal or args.internal_scope:
        policy = config.internal
        config.internal = InternalPolicy(
            names=policy.names | frozenset(args.internal),
            patterns=policy.patterns,
            npm_scopes=policy.npm_scopes + tuple(args.internal_scope),
        )
    registry: RegistryClient | None = None
    if args.online:
        registry = HttpRegistryClient()
    elif args.registry is not None:
        registry = FixtureRegistry.from_file(args.registry)
    elif config.registry_fixture is not None:
        registry = FixtureRegistry.from_file(config.registry_fixture)
    fail_on = args.fail_on or config.fail_on
    result = Scanner(config, registry=registry).scan(args.paths)
    _emit(_render(result, args.format, fail_on, args.verbose > 0), args.output)
    return _exit_code(result, fail_on, args.ignore_errors)


def _cmd_check(args: argparse.Namespace) -> int:
    eco = Ecosystem(args.ecosystem)
    config = Config(min_score=args.min_score)
    scanner = Scanner(config)
    result = ScanResult()
    for name in args.names:
        result.findings.extend(scanner.check_name(eco, name))
    fail_on = args.fail_on or Severity.LOW
    _emit(_render(result, args.format, fail_on, args.verbose > 0), args.output)
    return _exit_code(result, fail_on, args.ignore_errors)


def _cmd_review(args: argparse.Namespace) -> int:
    result = ScanResult()
    for path in args.paths:
        result.extend(review_path(path, third_party=True))
    scanner = Scanner(Config())
    result.findings.extend(scanner.check_dependencies(result.dependencies))
    fail_on = args.fail_on or Severity.HIGH
    _emit(_render(result, args.format, fail_on, args.verbose > 0), args.output)
    return _exit_code(result, fail_on, args.ignore_errors)


def _cmd_eval(args: argparse.Namespace) -> int:
    indexes = {eco: PopularIndex.bundled(eco) for eco in Ecosystem}
    settings = CheckerSettings(min_score=0.0)
    checkers = {eco: NameChecker(indexes[eco], settings) for eco in Ecosystem}
    items = build_dataset(args.data_dir, indexes)
    scored = score_items(items, checkers)
    report = render_markdown(
        scored,
        shipped_threshold=CheckerSettings().min_score,
        in_snapshot=lambda item: bool(item.target) and item.target in indexes[item.ecosystem],
    )
    _emit(report, args.output)
    return EXIT_OK


def _cmd_snapshot(_: argparse.Namespace) -> int:
    for eco in Ecosystem:
        meta = snapshot_metadata(eco)
        index = PopularIndex.bundled(eco)
        sys.stdout.write(f"{eco.value}: {len(index)} names\n")
        for key in ("source", "source-sha256", "licence", "ranks"):
            sys.stdout.write(f"  {key}: {meta.get(key, '?')}\n")
    return EXIT_OK


_COMMANDS = {
    "scan": _cmd_scan,
    "check": _cmd_check,
    "review": _cmd_review,
    "eval": _cmd_eval,
    "snapshot": _cmd_snapshot,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    level = logging.WARNING - 10 * min(args.verbose, 2)
    logging.basicConfig(level=level, format="squatwatch: %(levelname)s: %(message)s")
    try:
        return _COMMANDS[args.command](args)
    except SquatwatchError as exc:
        sys.stderr.write(f"squatwatch: error: {exc}\n")
        return EXIT_INPUT
    except Exception:
        log.exception("internal error")
        return EXIT_INTERNAL


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
