"""invariant run invariant.yaml [--evidence proof/]"""
from __future__ import annotations

import argparse

from .runner import run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="invariant")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run every invariant in a config file")
    run_p.add_argument("config", help="path to invariant.yaml")
    run_p.add_argument("--evidence", metavar="DIR",
                        help="write a proof bundle (per-check evidence + manifest) to DIR")

    args = parser.parse_args(argv)
    if args.command == "run":
        return run(args.config, args.evidence)
    return 2  # argparse's `required=True` makes this unreachable; kept honest anyway.


if __name__ == "__main__":
    raise SystemExit(main())
