"""migration_diff check: does a value survive a data migration.

Not "does a query equal a fixed constant" -- that's the `sql` check. This
compares the result of a query against the SOURCE store to the result of
a query against the DESTINATION store, live, both sides queried right
now -- so a migration's "the row count / total amount / whatever business
invariant survived unchanged" claim is checked against reality on both
ends, not against a number someone wrote down once during the migration
and never revisited. Source and destination can be different dsns
entirely (a legacy MySQL-shaped sqlite export vs. the new Postgres schema,
for instance), since each side is just {dsn, query} -- the same shape the
`sql` check already uses.

Args:
    source: {dsn, query} -- query must return exactly one row of one column
    destination: {dsn, query} -- same shape
    tolerance: optional numeric tolerance for the comparison (default 0,
        exact match) -- for a currency/unit conversion during migration
        where a small rounding difference is expected and fine
"""
from __future__ import annotations

from ..model import FAIL, PASS, UNVERIFIED
from .sql import _PG_SCHEMES, _query_postgres, _query_sqlite, _redact_dsn


def _run_side(spec: dict) -> tuple[object, str | None, str]:
    dsn = spec["dsn"]
    query = spec["query"]
    if dsn.startswith(_PG_SCHEMES):
        value, err = _query_postgres(dsn, query)
    else:
        value, err = _query_sqlite(dsn, query)
    return value, err, _redact_dsn(dsn)


def run(args: dict) -> tuple[str, str, dict]:
    source = args["source"]
    destination = args["destination"]
    tolerance = args.get("tolerance", 0)

    src_value, src_err, src_dsn = _run_side(source)
    if src_err:
        return UNVERIFIED, f"source: {src_err}", {"source_dsn": src_dsn}

    dst_value, dst_err, dst_dsn = _run_side(destination)
    if dst_err:
        return UNVERIFIED, f"destination: {dst_err}", {
            "source_dsn": src_dsn, "source_value": src_value, "destination_dsn": dst_dsn,
        }

    evidence = {
        "source_dsn": src_dsn, "source_query": source["query"], "source_value": src_value,
        "destination_dsn": dst_dsn, "destination_query": destination["query"],
        "destination_value": dst_value, "tolerance": tolerance,
    }

    if src_value is None or dst_value is None:
        # A query returning no row at all (an empty result set, not a
        # zero) -- there's nothing numeric to diff, but "both sides
        # returned nothing" is itself a real agreement, not a failure.
        if src_value == dst_value:
            return PASS, "both source and destination returned no row", evidence
        return FAIL, f"source={src_value!r}, destination={dst_value!r} -- one side returned no row", evidence

    try:
        diff = abs(src_value - dst_value)
        matches = diff <= tolerance
    except TypeError:
        # Non-numeric values (e.g. comparing text columns) -- tolerance
        # doesn't mean anything for those, fall back to exact equality.
        diff = None
        matches = src_value == dst_value

    if matches:
        detail = f"source={src_value!r} matches destination={dst_value!r}"
        if tolerance:
            detail += f" (within tolerance {tolerance})"
        return PASS, detail, evidence

    detail = f"source={src_value!r} but destination={dst_value!r}"
    if diff is not None:
        detail += f" (diff {diff}, tolerance {tolerance})"
    return FAIL, detail, evidence
