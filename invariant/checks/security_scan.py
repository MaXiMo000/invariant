"""security_scan check: shells out to carabiner.

Runs `carabiner scan --json` against a repo and reads its finding list as
evidence. Does not reimplement any of carabiner's engines or baseline logic.

Args:
    repo: path to the repository to scan (default ".")
    all: run every engine, not just the fast pre-commit path (default False)
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..model import FAIL, PASS, UNVERIFIED


def run(args: dict) -> tuple[str, str, dict]:
    repo = args.get("repo", ".")

    if shutil.which("carabiner") is None:
        return UNVERIFIED, "carabiner is not installed (pip install carabiner-sec)", {}

    cmd = ["carabiner", "scan", "--root", repo, "--json"]
    if args.get("all"):
        cmd.append("--all")

    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        report = {}

    evidence = {
        "command": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "report": report,
    }

    if proc.returncode == 2:
        return UNVERIFIED, "carabiner could not run (config error)", evidence
    new = report.get("new", [])
    if proc.returncode == 0:
        return PASS, f"{len(new)} new finding(s), all below the fail threshold", evidence
    return FAIL, f"{len(new)} new finding(s) at or above the fail threshold", evidence
