"""gdpr_erasure check: after a "right to be forgotten" request, verify no
row remains for the erased subject in *any* of the declared stores their
data could have lived in.

A single `sql` check (see sql.py) already answers "is this one query's
count zero" -- what this adds is aggregating that same question across
every table a subject's data could be in, into one pass/fail per subject,
instead of N separate invariant entries a human has to mentally combine to
know whether an erasure actually finished. A real erasure is rarely one
table: users, orders, activity logs, uploaded files, and whatever else
carries a foreign key back to the subject.

Args:
    dsn: a sqlite3 file path, or a postgres(ql):// connection string (same as the `sql` check)
    subject_id: the identifier of the erased subject -- always passed as a
        query parameter, never interpolated into SQL
    stores: a list of {table, column} pairs, one per place the subject's
        data could live -- table/column names ARE interpolated (SQL can't
        parameterize an identifier), so each is checked against a strict
        identifier pattern first and rejected otherwise
"""
from __future__ import annotations

import re
import sqlite3

from ..model import FAIL, PASS, UNVERIFIED
from .sql import _PG_SCHEMES, _redact_dsn

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def run(args: dict) -> tuple[str, str, dict]:
    dsn = args["dsn"]
    subject_id = args["subject_id"]
    stores = args["stores"]
    safe_dsn = _redact_dsn(dsn)

    if not stores:
        return UNVERIFIED, "no stores declared to check -- nothing to verify", {"dsn": safe_dsn}

    checked = []
    residual = []
    for store in stores:
        table, column = store["table"], store["column"]
        if not (_SAFE_IDENTIFIER.match(table) and _SAFE_IDENTIFIER.match(column)):
            return UNVERIFIED, (
                f"'{table}'/'{column}' is not a plain identifier -- refusing to "
                "build a query from it"
            ), {"dsn": safe_dsn, "stores_checked": checked}

        if dsn.startswith(_PG_SCHEMES):
            count, err = _count_postgres(dsn, table, column, subject_id)
        else:
            count, err = _count_sqlite(dsn, table, column, subject_id)

        if err:
            return UNVERIFIED, f"{table}: {err}", {"dsn": safe_dsn, "stores_checked": checked}

        checked.append({"table": table, "column": column, "remaining": count})
        if count:
            residual.append(f"{table}.{column}")

    evidence = {"dsn": safe_dsn, "subject_id": str(subject_id), "stores_checked": checked}
    if residual:
        return FAIL, f"subject {subject_id} still has data in: {', '.join(residual)}", evidence
    return PASS, (
        f"subject {subject_id} has no remaining rows in any of the "
        f"{len(stores)} declared store(s)"
    ), evidence


def _count_sqlite(dsn: str, table: str, column: str, subject_id):
    conn = sqlite3.connect(dsn)
    try:
        row = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {column} = ?", (subject_id,)  # noqa: S608 -- identifiers already validated
        ).fetchone()
    except sqlite3.Error as exc:
        return None, str(exc)
    finally:
        conn.close()
    return row[0], None


def _count_postgres(dsn: str, table: str, column: str, subject_id):
    try:
        import psycopg
    except ImportError:
        return None, "psycopg is not installed (pip install psycopg[binary]) for a postgres dsn"
    try:
        with psycopg.connect(dsn, connect_timeout=5) as conn, conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {column} = %s", (subject_id,))  # noqa: S608
            row = cur.fetchone()
        return row[0], None
    except Exception as exc:  # noqa: BLE001 - a bad connection/query is unverified, not a crash
        return None, f"could not query postgres: {exc}"
