"""security_scan check: shells out to carabiner.

Runs `carabiner scan --json` against a repo and reads its finding list as
evidence. Does not reimplement any of carabiner's engines or baseline logic.

Args:
    repo: path to the repository to scan (default ".")
    all: run every engine, not just the fast pre-commit path (default False)
    info: also count informational findings in the result, not just count
        them silently -- carabiner hides these from `new` by default, which
        means a repo with only informational findings reads as a clean PASS
        unless this is set (default False)
    fail_on: severity threshold passed through to carabiner's --fail-on,
        overriding its per-engine defaults -- needed alongside `info` to
        actually fail the build on an informational finding, since carabiner
        counting one in `new` and gating the exit code on it are separate
        (default: carabiner's own per-engine thresholds)
    timeout: seconds to wait for carabiner before giving up (default 300) --
        without this, a carabiner hang (a scanner stuck on a huge lockfile,
        a stalled network call) blocks the whole invariant run forever
        instead of reporting unverified, which is exactly the silent-hang
        this tool exists to refuse
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..model import FAIL, PASS, UNVERIFIED

_DEFAULT_TIMEOUT = 300


def run(args: dict) -> tuple[str, str, dict]:
    repo = args.get("repo", ".")

    if shutil.which("carabiner") is None:
        return UNVERIFIED, "carabiner is not installed (pip install carabiner-sec)", {}

    cmd = ["carabiner", "scan", "--root", repo, "--json"]
    if args.get("all"):
        cmd.append("--all")
    if args.get("info"):
        cmd.append("--info")
    if args.get("fail_on"):
        cmd += ["--fail-on", args["fail_on"]]

    timeout = args.get("timeout", _DEFAULT_TIMEOUT)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return UNVERIFIED, f"carabiner did not finish within {timeout}s", {"command": cmd}

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
