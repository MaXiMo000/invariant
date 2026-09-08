# invariant

[![ci](https://github.com/MaXiMo000/invariant/actions/workflows/ci.yml/badge.svg)](https://github.com/MaXiMo000/invariant/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/invariant-verify.svg)](https://pypi.org/project/invariant-verify/)

**<https://maximo000.github.io/invariant/>**

**Declare what must stay true. Get more than pass/fail back.**

Most CI tells you a build is green. It rarely tells you *why* it trusts that,
or leaves anything behind for someone else to check without re-running it
themselves. `invariant` runs a list of named checks against real systems and
writes a proof bundle next to the report — evidence, not just a verdict.

```yaml
invariants:
  - name: no_negative_payments
    check: sql
    args: {dsn: prod.db, query: "SELECT COUNT(*) FROM payments WHERE amount < 0", must_equal: 0}

  - name: latest_backup_restores
    check: postgres_restore
    args: {dump: backups/latest.dump}

  - name: repo_security_controls_fire
    check: security_scan
    args: {repo: .}
```

```
$ invariant run invariant.yaml --evidence proof/
  [PASS] no_negative_payments               0.00s  'SELECT COUNT(*)...' = 0
  [FAIL] latest_backup_restores             4.31s  firedrill restored the archive and found problems
  [????] repo_security_controls_fire        0.00s  carabiner is not installed (pip install carabiner-sec)

  1 passed, 1 failed, 1 unverified

  evidence written to proof/
```

## Three statuses, not two

A check that could not run — the tool isn't installed, Docker is down, a
credential is missing — is not the same fact as a check that ran and found a
problem. Folding both into "fail" throws away the difference; folding the
first into "pass" is worse, because now the report is lying. `invariant`
keeps `unverified` as its own status everywhere, and **it fails the build**,
same rule as [firedrill](https://github.com/MaXiMo000/firedrill) and
[carabiner](https://github.com/MaXiMo000/carabiner): an invariant nobody
could check is not one you get to call satisfied.

## Why another one

Because the interesting part isn't the runner — it's what backs each check
type. `invariant` doesn't reimplement backup verification or security
scanning; it wraps tools that already do those honestly:

- **`postgres_restore`** shells out to
  [firedrill](https://github.com/MaXiMo000/firedrill), which restores a
  Postgres dump into a disposable, version-matched container and proves it's
  usable — rather than trusting that a backup job exiting 0 means anything.
- **`security_scan`** shells out to
  [carabiner](https://github.com/MaXiMo000/carabiner), which runs multiple
  scanners against a repo, ratchets existing findings, and reports only
  what's new.
- **`sql`** is the trivial case, built in: one query, one expected scalar.
  stdlib `sqlite3` needs nothing extra; a `postgres://` dsn uses `psycopg` if
  `pip install invariant[postgres]` put it there, and reports `unverified`
  rather than crashing if it didn't. A dsn's password is stripped before it
  ever reaches the evidence bundle — the dsn you pass in is used to connect,
  never written to disk with its credential intact. Not every invariant
  needs a whole tool behind it. See `examples/recur_invariants.yaml` for two
  real ones run
  against [recur](https://github.com/MaXiMo000/recur)'s actual Postgres
  schema — "no subscription has a negative amount" and "every logged price
  change actually changed the price" — neither enforced by a schema
  constraint, which is the point.
- **`http`** GETs a URL and asserts on its status code and/or a body
  substring — stdlib `urllib`, nothing else. The response body is never
  written whole into evidence, only its length; only what the check
  actually asserted (did it contain X) is evidence-worthy.
- **`filesystem`** asserts a path exists (or explicitly doesn't), and
  optionally its type and permission bits — environment/deploy
  verification with no cloud SDK.
- **`receipt`** reads a receipt file written by
  [receipt](https://github.com/MaXiMo000/receipt) and asserts its status —
  the concrete "receipt = evidence, invariant = policy" boundary: receipt
  produces the record of what a command touched, this check turns it into
  a pass/fail as part of a larger set of invariants, with no reimplementing
  of receipt's own snapshot/diff logic.

Any string arg on any check can reference an environment variable —
`dsn: ${PROD_DSN}` (whole value) or `dsn: postgresql://user:${PROD_PASSWORD}@host/db`
(embedded) — so a credential never has to be written into `invariant.yaml`
itself, which typically lives in the repo being checked.

Four repos that individually prove "this backup works" or "this repo is
secure" become one config file that proves all of it, with one report and one
evidence directory, and a fifth check type is one new file in `checks/`, not
a rewrite.

## Install

```bash
pip install invariant-verify    # PyPI blocks the plain name "invariant" --
                                 # see pyproject.toml -- the command and the
                                 # `invariant` import are unaffected
                                 # + `pip install firedrill` / `carabiner-sec`
                                 # for the checks that need them
```

## Use

```bash
python examples/make_demo_db.py         # or --break negative_payment / orphan_order
invariant run examples/invariant.yaml --evidence proof/
```

`--evidence DIR` writes `manifest.json` (name, status, timing, sha256 per
check) plus one `<name>.json` per check holding its raw evidence — the exact
command run, stdout/stderr, exit code, and the wrapped tool's own report
where there is one. Enough for someone else to see what actually happened
without taking the exit code's word for it. Each check type is responsible
for keeping its own evidence honest but not sensitive — `sql`'s dsn
redaction (above) is the one place this has actually mattered so far; a new
check type that touches a credential should do the same before returning
its evidence dict, not after.

`--check NAME` (repeatable) runs only the named invariants — everything
else in the config is skipped, not reported as unverified. `--json` prints
the result array instead of the human report, for scripting against
invariant's own output directly.

## Add a check type

A check is a function `args: dict -> (status, detail, evidence)` where
`status` is `"pass"`, `"fail"`, or `"unverified"`. Add the module under
`invariant/checks/`, register it in `invariant/checks/__init__.py`. That's
the whole extension point — the runner, evidence writer, and CLI don't change.

## What's deliberately not built

No plugin SDK, no YAML schema validator, no dashboard, no signing of the
evidence bundle (a sha256 catches an edited file; a real signature is a
separate, later problem). No `migration_diff` or `reconcile` check types
yet — added the same way as the six above, when there's a real invariant
to run them against.

MIT licensed.
