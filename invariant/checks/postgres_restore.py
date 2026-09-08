"""postgres_restore check: shells out to firedrill.

Does not reimplement any of firedrill's restore-and-verify logic -- runs
`firedrill run <dump> --json <tmpfile>` and reads its report as evidence.
firedrill's own report distinguishes "verified and broken" from "could not
verify" (its exit code alone does not); this adapter surfaces that
distinction rather than collapsing it to pass/fail.

Args:
    dump: path to a pg_dump archive
    fail_on: severity threshold passed through to firedrill (optional)
    timeout: seconds to wait for firedrill before giving up (default 900,
        generous because a real restore is the point) -- without this, a
        stuck Docker pull or a restore that never returns blocks the whole
        invariant run forever instead of reporting unverified, which is
        exactly the silent-hang this tool exists to refuse
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

from ..model import FAIL, PASS, UNVERIFIED

_DEFAULT_TIMEOUT = 900


def run(args: dict) -> tuple[str, str, dict]:
    dump = args["dump"]

    if shutil.which("firedrill") is None:
        return UNVERIFIED, "firedrill is not installed (pip install firedrill)", {}

    fd, report_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    cmd = ["firedrill", "run", dump, "--json", report_path, "--quiet"]
    if "fail_on" in args:
        cmd += ["--fail-on", args["fail_on"]]

    timeout = args.get("timeout", _DEFAULT_TIMEOUT)
    try:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return UNVERIFIED, f"firedrill did not finish within {timeout}s", {"command": cmd}
        try:
            report = json.loads(open(report_path, encoding="utf-8").read())
        except (FileNotFoundError, json.JSONDecodeError):
            report = {}
    finally:
        if os.path.exists(report_path):
            os.remove(report_path)

    evidence = {
        "command": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "report": report,
    }

    if proc.returncode == 2:
        return UNVERIFIED, "firedrill could not start (config or docker error)", evidence
    if not report.get("verified", proc.returncode == 0):
        return UNVERIFIED, "firedrill could not verify the restore", evidence
    if proc.returncode == 0:
        return PASS, "firedrill restored the archive and it checked out", evidence
    return FAIL, "firedrill restored the archive and found problems", evidence
