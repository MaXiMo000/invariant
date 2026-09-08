"""Run: python tests/test_invariant.py

Covers the property the whole tool exists for: a check that cannot run must
report "unverified", never fold silently into "pass" or "fail".
"""
from __future__ import annotations

import json
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from invariant import runner
from invariant.checks import postgres_restore, security_scan
from invariant.checks.sql import _redact_dsn
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

    def test_a_missing_required_arg_says_so_clearly_not_a_bare_keyerror_repr(self):
        # This is the actual finding from the audit: a config typo and a
        # genuinely flaky check used to produce an identical-looking
        # `check raised KeyError('dsn')` message. They're distinguishable now.
        invariants = [{"name": "bad_args", "check": "sql", "args": {}}]
        results = runner.run_all(invariants)
        self.assertIn("missing required arg 'dsn'", results[0].detail)
        self.assertIn("check type 'sql'", results[0].detail)
        self.assertNotIn("KeyError", results[0].detail)

    def test_env_var_reference_in_args_is_expanded(self):
        _make_db(self.db_path, negative_payment=False)
        with mock.patch.dict("os.environ", {"TEST_DB_PATH": self.db_path}):
            invariants = [{
                "name": "check",
                "check": "sql",
                "args": {"dsn": "${TEST_DB_PATH}",
                         "query": "SELECT COUNT(*) FROM payments WHERE amount < 0",
                         "must_equal": 0},
            }]
            results = runner.run_all(invariants)
        self.assertEqual(results[0].status, PASS)

    def test_partial_env_var_reference_inside_a_larger_string_is_expanded(self):
        with mock.patch.dict("os.environ", {"TEST_SECRET": "hunter2"}):
            invariants = [{
                "name": "check",
                "check": "sql",
                "args": {"dsn": "postgresql://user:${TEST_SECRET}@127.0.0.1:1/db",
                         "query": "SELECT 1", "must_equal": 0},
            }]
            results = runner.run_all(invariants)
        # Never listening on :1 -- what matters is the dsn was actually
        # expanded before the connection was attempted, not left as the
        # literal, unusable "${TEST_SECRET}" string.
        self.assertEqual(results[0].status, UNVERIFIED)
        self.assertNotIn("${TEST_SECRET}", str(results[0].evidence))

    def test_unset_env_var_reference_is_unverified_with_a_clear_reason(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            invariants = [{
                "name": "check",
                "check": "sql",
                "args": {"dsn": "${DEFINITELY_NOT_SET_XYZ}", "query": "SELECT 1", "must_equal": 0},
            }]
            results = runner.run_all(invariants)
        self.assertEqual(results[0].status, UNVERIFIED)
        self.assertIn("DEFINITELY_NOT_SET_XYZ", results[0].detail)
        self.assertIn("is not set", results[0].detail)

    def test_check_filter_runs_only_the_named_invariant(self):
        _make_db(self.db_path, negative_payment=False)
        invariants = [
            {"name": "a", "check": "sql", "args": {"dsn": self.db_path, "query": "SELECT 1", "must_equal": 1}},
            {"name": "b", "check": "sql", "args": {"dsn": self.db_path, "query": "SELECT 2", "must_equal": 1}},
        ]
        results = runner.run_all(invariants, only=["a"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].name, "a")

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

    def test_postgres_dsn_password_is_redacted_from_evidence(self):
        # Regression test for a real finding from the portfolio audit: a
        # postgres:// dsn embeds `user:pass@host`, and that password was
        # landing verbatim in the evidence dict (and thus on disk via
        # --evidence). No real Postgres needed here -- the redaction has to
        # happen before the connection is even attempted, on both the
        # unverified and the pass/fail paths.
        invariants = [{
            "name": "pg_check",
            "check": "sql",
            "args": {"dsn": "postgresql://appuser:s3cr3t-password@127.0.0.1:1/proddb",
                     "query": "SELECT 1", "must_equal": 0},
        }]
        results = runner.run_all(invariants)
        self.assertEqual(results[0].status, UNVERIFIED)  # nothing listening on :1
        self.assertNotIn("s3cr3t-password", json.dumps(results[0].evidence))
        self.assertIn("appuser", results[0].evidence["dsn"])  # username kept, it isn't secret

    def test_postgres_dsn_password_is_redacted_from_written_evidence_file(self):
        # End-to-end: the same finding, verified against the actual file
        # written to disk, the way it was originally confirmed live.
        invariants = [{
            "name": "pg_check",
            "check": "sql",
            "args": {"dsn": "postgresql://appuser:s3cr3t-password@127.0.0.1:1/proddb",
                     "query": "SELECT 1", "must_equal": 0},
        }]
        results = runner.run_all(invariants)
        out_dir = pathlib.Path(self.tmp.name) / "proof"
        from invariant.evidence import write
        write(results, out_dir)
        written = (out_dir / "pg_check.json").read_text()
        self.assertNotIn("s3cr3t-password", written)

    def test_sqlite_dsn_a_file_path_is_left_alone(self):
        # sqlite dsns are bare file paths -- nothing to redact, and the
        # redaction pass must not mangle a normal path.
        self.assertEqual(_redact_dsn("/tmp/demo.db"), "/tmp/demo.db")

    def test_postgres_dsn_with_no_password_is_left_alone(self):
        self.assertEqual(
            _redact_dsn("postgresql://appuser@127.0.0.1/proddb"),
            "postgresql://appuser@127.0.0.1/proddb",
        )

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

    def test_json_output_through_the_real_cli_is_a_valid_result_array(self):
        import contextlib
        import io

        from invariant.cli import main as cli_main

        _make_db(self.db_path, negative_payment=False)
        config_path = pathlib.Path(self.tmp.name) / "invariant.yaml"
        config_path.write_text(
            "invariants:\n"
            "  - name: check_one\n"
            "    check: sql\n"
            f"    args: {{dsn: {self.db_path}, query: 'SELECT 1', must_equal: 1}}\n"
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main(["run", str(config_path), "--json"])
        self.assertEqual(code, 0)
        parsed = json.loads(out.getvalue())
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["name"], "check_one")
        self.assertEqual(parsed[0]["status"], PASS)


class TestSecurityScan(unittest.TestCase):
    """No real carabiner here -- what matters is the command it would run.

    Without --info, carabiner hides informational findings from `new` by
    default, so a repo with only informational findings reads as a clean
    PASS. Without --fail-on, carabiner gates on its own per-engine
    thresholds regardless of what `new` contains. Both have to be passed
    through, or that gap stays open.
    """

    def _run_with_fake_carabiner(self, args, stdout='{"new": [], "accepted": 0}'):
        captured = {}

        def fake_run(cmd, **kw):
            captured["cmd"] = cmd
            return mock.Mock(returncode=0, stdout=stdout, stderr="")

        with mock.patch("shutil.which", return_value="/usr/bin/carabiner"), \
             mock.patch("subprocess.run", side_effect=fake_run):
            security_scan.run(args)
        return captured["cmd"]

    def test_info_and_fail_on_passed_through_when_set(self):
        cmd = self._run_with_fake_carabiner({"repo": ".", "info": True, "fail_on": "info"})
        self.assertIn("--info", cmd)
        self.assertEqual(cmd[cmd.index("--fail-on") + 1], "info")

    def test_info_and_fail_on_omitted_by_default(self):
        cmd = self._run_with_fake_carabiner({"repo": "."})
        self.assertNotIn("--info", cmd)
        self.assertNotIn("--fail-on", cmd)

    def test_hung_carabiner_is_unverified_not_a_hang(self):
        def fake_run(cmd, **kw):
            self.assertIn("timeout", kw)
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])

        with mock.patch("shutil.which", return_value="/usr/bin/carabiner"), \
             mock.patch("subprocess.run", side_effect=fake_run):
            status, detail, _ = security_scan.run({"repo": "."})
        self.assertEqual(status, UNVERIFIED)
        self.assertIn("300", detail)


class TestPostgresRestore(unittest.TestCase):
    def test_hung_firedrill_is_unverified_not_a_hang(self):
        def fake_run(cmd, **kw):
            self.assertIn("timeout", kw)
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])

        with mock.patch("shutil.which", return_value="/usr/bin/firedrill"), \
             mock.patch("subprocess.run", side_effect=fake_run):
            status, detail, _ = postgres_restore.run({"dump": "dump.custom"})
        self.assertEqual(status, UNVERIFIED)
        self.assertIn("900", detail)


if __name__ == "__main__":
    unittest.main()
