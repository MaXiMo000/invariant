"""filesystem check: assert a path exists (or doesn't), and optionally its
type and permission bits -- infrastructure/environment verification with
no cloud SDK, for the common case of "did the deploy actually put this
file where it's supposed to be, with the permissions it needs."

Args:
    path: the path to check
    must_exist: bool, default True. False asserts the path does NOT exist.
    type: "file" | "dir" (optional, only checked if must_exist is True)
    mode: expected permission bits as an octal int (e.g. 0o644) or string
        ("0644" / "644") (optional, only checked if must_exist is True)
"""
from __future__ import annotations

import pathlib
import stat

from ..model import FAIL, PASS, UNVERIFIED


def _parse_mode(mode) -> int:
    if isinstance(mode, int):
        return mode
    return int(str(mode), 8)


def run(args: dict) -> tuple[str, str, dict]:
    path = pathlib.Path(args["path"])
    must_exist = args.get("must_exist", True)
    expect_type = args.get("type")
    expect_mode = args.get("mode")

    try:
        exists = path.exists()
        actual_stat = path.stat() if exists else None
    except OSError as exc:
        return UNVERIFIED, f"could not stat {path}: {exc}", {"path": str(path)}

    evidence = {"path": str(path), "exists": exists}

    if not must_exist:
        if exists:
            return FAIL, f"{path} exists, expected it not to", evidence
        return PASS, f"{path} does not exist, as expected", evidence

    if not exists:
        return FAIL, f"{path} does not exist", evidence

    actual_type = "dir" if path.is_dir() else "file" if path.is_file() else "other"
    actual_mode = stat.S_IMODE(actual_stat.st_mode)
    evidence["type"] = actual_type
    evidence["mode"] = oct(actual_mode)

    problems = []
    if expect_type is not None and actual_type != expect_type:
        problems.append(f"type {actual_type!r}, expected {expect_type!r}")
    if expect_mode is not None:
        expected_mode = _parse_mode(expect_mode)
        if actual_mode != expected_mode:
            problems.append(f"mode {oct(actual_mode)}, expected {oct(expected_mode)}")

    if problems:
        return FAIL, "; ".join(problems), evidence
    return PASS, f"{path} exists" + (f" ({actual_type}, {oct(actual_mode)})" if expect_type or expect_mode else ""), evidence
