"""Run: python tests/test_invariant.py

Covers the property the whole tool exists for: a check that cannot run must
report "unverified", never fold silently into "pass" or "fail".
"""
from __future__ import annotations

import json
import pathlib
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from invariant import runner
from invariant.model import FAIL, PASS, UNVERIFIED


def _make_db(path: str, negative_payment: bool) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE payments (id INTEGER PRIMARY KEY, amount INTEGER)")
    conn.execute("INSERT INTO payments VALUES (1, 100)")
    if negative_payment:
        conn.execute("INSERT INTO payments VALUES (2, -50)")
    conn.commit()
    conn.close()


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(pathlib.Path(self.tmp.name) / "demo.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_passing_invariant(self):
        _make_db(self.db_path, negative_payment=False)
        invariants = [{
            "name": "no_negative_payments",
            "check": "sql",
            "args": {"dsn": self.db_path,
                     "query": "SELECT COUNT(*) FROM payments WHERE amount < 0",
                     "must_equal": 0},
        }]
        results = runner.run_all(invariants)
        self.assertEqual(results[0].status, PASS)
        self.assertEqual(runner.exit_code(results), 0)

    def test_failing_invariant(self):
        _make_db(self.db_path, negative_payment=True)
        invariants = [{
            "name": "no_negative_payments",
            "check": "sql",
            "args": {"dsn": self.db_path,
                     "query": "SELECT COUNT(*) FROM payments WHERE amount < 0",
                     "must_equal": 0},
        }]
        results = runner.run_all(invariants)
        self.assertEqual(results[0].status, FAIL)
        self.assertEqual(runner.exit_code(results), 1)

    def test_unknown_check_type_is_unverified_not_a_crash(self):
        invariants = [{"name": "mystery", "check": "does_not_exist", "args": {}}]
        results = runner.run_all(invariants)
        self.assertEqual(results[0].status, UNVERIFIED)
        self.assertEqual(runner.exit_code(results), 1)

    def test_broken_check_is_unverified_not_a_crash(self):
        # A missing arg must not take the whole run down with a KeyError --
        # that's one broken invariant, reported, not a stack trace.
        invariants = [{"name": "bad_args", "check": "sql", "args": {}}]
        results = runner.run_all(invariants)
        self.assertEqual(results[0].status, UNVERIFIED)

    def test_sql_check_routes_postgres_dsn_without_crashing(self):
        # No real Postgres in this suite -- what matters is that a pg dsn
        # goes down the postgres path (missing driver or bad connection) and
        # comes back unverified rather than raising, whether or not psycopg
        # happens to be installed in the environment running this test.
        invariants = [{
            "name": "pg_check",
            "check": "sql",
            "args": {"dsn": "postgresql://nouser@127.0.0.1:1/nodb",
                     "query": "SELECT 1", "must_equal": 0},
        }]
        results = runner.run_all(invariants)
        self.assertEqual(results[0].status, UNVERIFIED)

    def test_evidence_bundle_is_written(self):
        _make_db(self.db_path, negative_payment=False)
        invariants = [{
            "name": "no_negative_payments",
            "check": "sql",
            "args": {"dsn": self.db_path,
                     "query": "SELECT COUNT(*) FROM payments WHERE amount < 0",
                     "must_equal": 0},
        }]
        results = runner.run_all(invariants)
        out_dir = pathlib.Path(self.tmp.name) / "proof"
        from invariant.evidence import write
        write(results, out_dir)

        manifest = json.loads((out_dir / "manifest.json").read_text())
        self.assertEqual(len(manifest["checks"]), 1)
        self.assertEqual(manifest["checks"][0]["status"], PASS)
        self.assertTrue((out_dir / "no_negative_payments.json").exists())


if __name__ == "__main__":
    unittest.main()
