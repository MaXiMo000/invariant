"""Build examples/demo.dump: a small, real Postgres dump for the
postgres_restore check to restore. Needs Docker.

Same technique as firedrill's own tests/make_corpus.py (a throwaway
container, `pg_dump` inside it, `docker cp` out) -- not reimplemented, just
scaled down to the one healthy fixture this example needs.

    python examples/make_demo_dump.py
"""
from __future__ import annotations

import pathlib
import subprocess
import time
import uuid

DUMP_PATH = pathlib.Path(__file__).parent / "demo.dump"
NAME = f"invariant-demo-{uuid.uuid4().hex[:8]}"


def sh(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}\n{result.stderr}")
    return result


def _wait_ready(attempts: int = 60, delay: float = 1.0) -> None:
    """pg_isready can report ready during the container's own internal
    restart -- the postgres image starts a temporary server for initdb's
    scripts, stops it, then starts the real one -- so a separate readiness
    check can pass in that gap right before the connection it was meant to
    guarantee fails. Probe with the actual operation instead."""
    last_err = ""
    for _ in range(attempts):
        probe = sh("docker", "exec", "-u", "postgres", NAME, "psql", "-U", "postgres",
                   "-c", "select 1", check=False)
        if probe.returncode == 0:
            return
        last_err = probe.stderr
        time.sleep(delay)
    raise RuntimeError(f"postgres:16 never accepted a connection: {last_err}")


def build() -> None:
    sh("docker", "run", "-d", "--name", NAME,
       "-e", "POSTGRES_PASSWORD=demo-only-not-a-secret", "postgres:16")
    try:
        _wait_ready()
        sh("docker", "exec", "-u", "postgres", NAME, "psql", "-U", "postgres",
           "-c", "create table customer(id serial primary key, email text not null)")
        sh("docker", "exec", "-u", "postgres", NAME, "psql", "-U", "postgres",
           "-c", "insert into customer(email) values ('a@example.test'),('b@example.test')")
        sh("docker", "exec", "-u", "postgres", NAME, "pg_dump", "-U", "postgres",
           "-Fc", "-f", "/tmp/out.dump", "postgres")
        sh("docker", "cp", f"{NAME}:/tmp/out.dump", str(DUMP_PATH))
    finally:
        sh("docker", "rm", "-f", "-v", NAME, check=False)
    print(f"wrote {DUMP_PATH}")


if __name__ == "__main__":
    build()
