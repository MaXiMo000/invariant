"""receipt check: read a receipt evidence file (written by
github.com/MaXiMo000/receipt) and assert its status.

The concrete "receipt = evidence, invariant = policy" boundary: receipt
produces a record of what a command actually touched; this check is where
that evidence gets turned into a pass/fail judgment as part of a larger
set of invariants, without invariant reimplementing any of receipt's
snapshot/diff logic.

Args:
    path: path to a receipt-*.json file (the one receipt run --out wrote,
        not the whole receipts/ directory)
    expect_status: the status the receipt must have (default: "pass")
"""
from __future__ import annotations

import json

from ..model import FAIL, PASS, UNVERIFIED


def run(args: dict) -> tuple[str, str, dict]:
    path = args["path"]
    expect_status = args.get("expect_status", "pass")

    try:
        record = json.loads(open(path, encoding="utf-8").read())
    except (OSError, json.JSONDecodeError) as exc:
        return UNVERIFIED, f"could not read receipt at {path}: {exc}", {"path": path}

    inner = record.get("receipt", {})
    actual_status = inner.get("status")
    evidence = {
        "path": path,
        "receipt_task": inner.get("task"),
        "receipt_status": actual_status,
        "receipt_detail": inner.get("detail"),
    }

    if actual_status is None:
        return UNVERIFIED, f"{path} doesn't look like a receipt (no status field)", evidence
    if actual_status != expect_status:
        return FAIL, f"receipt status is {actual_status!r}, expected {expect_status!r}: {inner.get('detail')}", evidence
    return PASS, f"receipt status is {actual_status!r}: {inner.get('detail')}", evidence
