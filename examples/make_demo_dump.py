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


def build() -> None:
    sh("docker", "run", "-d", "--name", NAME,
       "-e", "POSTGRES_PASSWORD=demo-only-not-a-secret", "postgres:16")
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            if sh("docker", "exec", "-u", "postgres", NAME,
                  "pg_isready", "-U", "postgres", "-q", check=False).returncode == 0:
                break
            time.sleep(0.3)
        else:
            raise RuntimeError("postgres:16 never became ready")

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
