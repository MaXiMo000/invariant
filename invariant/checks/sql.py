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
from urllib.parse import urlsplit, urlunsplit

from ..model import FAIL, PASS, UNVERIFIED

_PG_SCHEMES = ("postgres://", "postgresql://")


def _redact_dsn(dsn: str) -> str:
    """Strip a password out of a DSN before it goes into evidence.

    A postgres(ql):// DSN can carry `user:pass@host` -- evidence is meant to
    be written to disk and handed to someone else to inspect, so a live
    credential must never be one of the things it hands over. sqlite DSNs
    are a bare file path with no credential to leak, and pass through
    unchanged.
    """
    if not dsn.startswith(_PG_SCHEMES):
        return dsn
    parts = urlsplit(dsn)
    if parts.password is None:
        return dsn
    netloc = f"{parts.username}:[REDACTED]@{parts.hostname}" if parts.username else "[REDACTED]@" + (parts.hostname or "")
    if parts.port:
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def run(args: dict) -> tuple[str, str, dict]:
    dsn = args["dsn"]
    query = args["query"]
    expected = args["must_equal"]
    safe_dsn = _redact_dsn(dsn)

    if dsn.startswith(_PG_SCHEMES):
        actual, err = _query_postgres(dsn, query)
    else:
        actual, err = _query_sqlite(dsn, query)

    if err:
        return UNVERIFIED, err, {"dsn": safe_dsn, "query": query}

    evidence = {"dsn": safe_dsn, "query": query, "actual": actual, "expected": expected}
    if actual == expected:
        return PASS, f"{query!r} = {actual!r}", evidence
    return FAIL, f"{query!r} = {actual!r}, expected {expected!r}", evidence


def _query_sqlite(dsn: str, query: str):
    conn = sqlite3.connect(dsn)
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.Error as exc:
        # A bad query (typo'd table/column name, syntax error) used to
        # propagate straight out of here uncaught -- the postgres path
        # below already catches its own driver's exceptions the same way.
        # invariant's own runner happens to catch this one level up, so it
        # never took the whole tool down, but a check module calling
        # _query_sqlite() directly (migration_diff does) got a real crash
        # instead of the (status, detail, evidence) tuple its own contract
        # promises -- found by testing this exact case, not assumed fine
        # because the runner's own catch-all papered over it.
        return None, str(exc)
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
