"""Load invariant.yaml, run every invariant, print a report, write a proof
bundle if asked, return the process exit code.
"""
from __future__ import annotations

import pathlib
import time

import yaml

from .checks import REGISTRY
from .evidence import write as write_evidence
from .model import CheckResult, FAIL, PASS, UNVERIFIED

_MARK = {PASS: "PASS", FAIL: "FAIL", UNVERIFIED: "????"}


def load_config(path: str) -> list[dict]:
    data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")) or {}
    return data.get("invariants", [])


def run_all(invariants: list[dict]) -> list[CheckResult]:
    results = []
    for inv in invariants:
        name = inv["name"]
        check_type = inv["check"]
        args = inv.get("args", {})
        fn = REGISTRY.get(check_type)
        if fn is None:
            known = ", ".join(sorted(REGISTRY))
            results.append(CheckResult(
                name, UNVERIFIED, f"unknown check type {check_type!r} (known: {known})"))
            continue
        started = time.monotonic()
        try:
            status, detail, evidence = fn(args)
        except Exception as exc:  # noqa: BLE001 - a broken check is unverified, not a crash
            status, detail, evidence = UNVERIFIED, f"check raised {exc!r}", {}
        results.append(CheckResult(name, status, detail, time.monotonic() - started, evidence))
    return results


def render(results: list[CheckResult]) -> str:
    lines = [f"  [{_MARK[r.status]:<4}] {r.name:<30} {r.seconds:6.2f}s  {r.detail}"
             for r in results]
    passed = sum(r.status == PASS for r in results)
    failed = sum(r.status == FAIL for r in results)
    unverified = sum(r.status == UNVERIFIED for r in results)
    lines += ["", f"  {passed} passed, {failed} failed, {unverified} unverified"]
    return "\n".join(lines)


def exit_code(results: list[CheckResult]) -> int:
    # Unverified fails the build, same as firedrill and carabiner: an
    # invariant nobody could check is not one you get to call satisfied.
    return 0 if all(r.status == PASS for r in results) else 1


def run(config_path: str, evidence_dir: str | None) -> int:
    invariants = load_config(config_path)
    results = run_all(invariants)
    print(render(results))
    if evidence_dir:
        write_evidence(results, pathlib.Path(evidence_dir))
        print(f"\n  evidence written to {evidence_dir}/")
    return exit_code(results)
