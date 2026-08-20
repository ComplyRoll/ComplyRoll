"""Minimal ComplyRoll command-line scaffold."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from . import __version__


PHASES = (
    ("0", "Harden stigroll ingestion and provenance"),
    ("1", "Build VDR cases, policy clocks, and VER exports"),
    ("2", "Add automation, coverage, and change integration"),
    ("3", "Add KSI validation and SDR evidence"),
    ("4", "Integrate trust-center and ongoing certification workflows"),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="complyroll",
        description="Local-first evidence compiler for FedRAMP 20x VDR.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("version", help="show the ComplyRoll version")
    subparsers.add_parser("plan", help="show the high-level implementation phases")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "version":
        print(f"ComplyRoll {__version__}")
        return 0

    if args.command == "plan":
        for phase, outcome in PHASES:
            print(f"Phase {phase}: {outcome}")
        return 0

    raise AssertionError(f"unhandled command: {args.command}")
