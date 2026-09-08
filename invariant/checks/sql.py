"""sql check: run a query, assert the single scalar it returns.

sqlite3 (stdlib) needs nothing extra. A `dsn` starting with postgres:// or
postgresql:// uses psycopg if it's installed -- not a hard dependency, same
reasoning as firedrill/carabiner: most invariants never touch Postgres, so
the checks that don't shouldn't pay for a driver they don't use.

Args:
    dsn: a sqlite3 file path, or a postgres(ql):// connection string
    query: a query returning exactly one row of one column
    must_equal: the value that column must equal to pass
"""
from __future__ import annotations

import sqlite3

from ..model import FAIL, PASS, UNVERIFIED

_PG_SCHEMES = ("postgres://", "postgresql://")


def run(args: dict) -> tuple[str, str, dict]:
    dsn = args["dsn"]
    query = args["query"]
    expected = args["must_equal"]

    if dsn.startswith(_PG_SCHEMES):
        actual, err = _query_postgres(dsn, query)
    else:
        actual, err = _query_sqlite(dsn, query)

    if err:
        return UNVERIFIED, err, {"dsn": dsn, "query": query}

    evidence = {"dsn": dsn, "query": query, "actual": actual, "expected": expected}
    if actual == expected:
        return PASS, f"{query!r} = {actual!r}", evidence
    return FAIL, f"{query!r} = {actual!r}, expected {expected!r}", evidence


def _query_sqlite(dsn: str, query: str):
    conn = sqlite3.connect(dsn)
    try:
        row = conn.execute(query).fetchone()
    finally:
        conn.close()
    return (row[0] if row else None), None


def _query_postgres(dsn: str, query: str):
    try:
        import psycopg
    except ImportError:
        return None, "psycopg is not installed (pip install psycopg[binary]) for a postgres dsn"
    try:
        with psycopg.connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(query)
            row = cur.fetchone()
        return (row[0] if row else None), None
    except Exception as exc:  # noqa: BLE001 - a bad connection/query is unverified, not a crash
        return None, f"could not query postgres: {exc}"
