"""Build examples/demo.db: a clean db by default, or one broken invariant at
a time with --break, mirroring firedrill's tests/field_test.py --mutate.

    python examples/make_demo_db.py             # clean, both invariants pass
    python examples/make_demo_db.py --break negative_payment
    python examples/make_demo_db.py --break orphan_order
"""
from __future__ import annotations

import argparse
import pathlib
import sqlite3

DB_PATH = pathlib.Path(__file__).parent / "demo.db"

SCHEMA = """
CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT);
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER);
CREATE TABLE payments (id INTEGER PRIMARY KEY, order_id INTEGER, amount INTEGER);
"""


def build(break_case: str | None) -> None:
    DB_PATH.unlink(missing_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA)
        conn.execute("INSERT INTO customers VALUES (1, 'Ada'), (2, 'Grace')")
        conn.execute("INSERT INTO orders VALUES (1, 1), (2, 2)")
        conn.execute("INSERT INTO payments VALUES (1, 1, 4200), (2, 2, 1500)")
        if break_case == "negative_payment":
            conn.execute("INSERT INTO payments VALUES (3, 1, -500)")
        elif break_case == "orphan_order":
            conn.execute("INSERT INTO orders VALUES (3, 999)")
        conn.commit()
    finally:
        conn.close()
    print(f"wrote {DB_PATH}" + (f" (broken: {break_case})" if break_case else " (clean)"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--break", dest="break_case",
                        choices=["negative_payment", "orphan_order"])
    build(parser.parse_args().break_case)
