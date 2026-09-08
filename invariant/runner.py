"""Load invariant.yaml, run every invariant, print a report, write a proof
bundle if asked, return the process exit code.
"""
from __future__ import annotations

import os
import pathlib
import re
import time

import yaml

from .checks import REGISTRY
from .evidence import write as write_evidence
from .model import CheckResult, FAIL, PASS, UNVERIFIED

_MARK = {PASS: "PASS", FAIL: "FAIL", UNVERIFIED: "????"}

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class EnvRefError(ValueError):
    """A ${VAR} reference in an invariant's args names an environment
    variable that isn't set."""


def _expand_env_refs(value):
    """Recursively replaces ${VAR} in string args with os.environ[VAR] --
    so a dsn like `${PROD_DSN}` (whole string) or
    `postgresql://user:${PROD_PASSWORD}@host/db` (partial) never needs its
    credential written into invariant.yaml itself, which typically lives
    in the repo it's checking.
    """
    if isinstance(value, str):
        def _sub(m: re.Match) -> str:
            var = m.group(1)
            if var not in os.environ:
                raise EnvRefError(f"${{{var}}} is referenced but {var} is not set")
            return os.environ[var]
        return _ENV_REF.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _expand_env_refs(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env_refs(v) for v in value]
    return value


def load_config(path: str) -> list[dict]:
    data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")) or {}
    return data.get("invariants", [])


def run_all(invariants: list[dict], only: list[str] | None = None) -> list[CheckResult]:
    """only, if given, restricts the run to invariants with a matching name
    -- everything else in the config is skipped entirely (not reported as
    unverified; it simply wasn't asked for this run)."""
    results = []
    for inv in invariants:
        name = inv["name"]
        if only is not None and name not in only:
            continue
        check_type = inv["check"]
        fn = REGISTRY.get(check_type)
        if fn is None:
            known = ", ".join(sorted(REGISTRY))
            results.append(CheckResult(
                name, UNVERIFIED, f"unknown check type {check_type!r} (known: {known})"))
            continue

        started = time.monotonic()
        try:
            args = _expand_env_refs(inv.get("args", {}))
        except EnvRefError as exc:
            results.append(CheckResult(name, UNVERIFIED, str(exc), time.monotonic() - started))
            continue

        try:
            status, detail, evidence = fn(args)
        except KeyError as exc:
            # The single most common config mistake -- a required arg
            # missing or misspelled -- used to read as `check raised
            # KeyError('dsn')`, identical in shape to a check that's
            # genuinely flaky. Naming it explicitly as a config problem is
            # a clearer starting point for debugging, not a new validation
            # layer: nothing is checked before dispatch that wasn't
            # already going to fail the exact same way.
            status, detail, evidence = (
                UNVERIFIED,
                f"missing required arg {exc} for check type {check_type!r}",
                {},
            )
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


def run(config_path: str, evidence_dir: str | None,
        only: list[str] | None = None, as_json: bool = False) -> int:
    invariants = load_config(config_path)
    results = run_all(invariants, only=only)
    if as_json:
        import json
        print(json.dumps([r.as_dict() for r in results], indent=2, default=str))
    else:
        print(render(results))
    if evidence_dir:
        write_evidence(results, pathlib.Path(evidence_dir))
        if not as_json:
            print(f"\n  evidence written to {evidence_dir}/")
    return exit_code(results)
