"""sql check: run a query, assert the single scalar it returns.

stdlib sqlite3 only. Postgres invariants belong to the `postgres_restore`
check (which already needs a running Postgres) rather than teaching this one
a second driver for one number.

Args:
    dsn: path to a sqlite3 database file
    query: a query returning exactly one row of one column
    must_equal: the value that column must equal to pass
"""
from __future__ import annotations

import sqlite3

from ..model import FAIL, PASS


def run(args: dict) -> tuple[str, str, dict]:
    dsn = args["dsn"]
    query = args["query"]
    expected = args["must_equal"]

    conn = sqlite3.connect(dsn)
    try:
        row = conn.execute(query).fetchone()
    finally:
        conn.close()
    actual = row[0] if row else None

    evidence = {"dsn": dsn, "query": query, "actual": actual, "expected": expected}
    if actual == expected:
        return PASS, f"{query!r} = {actual!r}", evidence
    return FAIL, f"{query!r} = {actual!r}, expected {expected!r}", evidence
