"""Proof bundle: every check's evidence, written to disk so someone else can
inspect what happened without re-running anything or taking your word for it.

Not a signature scheme -- a directory plus a sha256 per file, which is enough
to notice if the evidence was edited after the fact. Signing it is a real
upgrade and a separate problem; this only needs to survive "did you actually
run this."
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import time

from .model import CheckResult


def write(results: list[CheckResult], out_dir: pathlib.Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for r in results:
        blob = json.dumps(r.evidence, indent=2, sort_keys=True, default=str)
        digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        (out_dir / f"{r.name}.json").write_text(blob, encoding="utf-8")
        manifest.append({
            "name": r.name,
            "status": r.status,
            "detail": r.detail,
            "seconds": round(r.seconds, 3),
            "sha256": digest,
        })
    (out_dir / "manifest.json").write_text(
        json.dumps({"generated_at": time.time(), "checks": manifest}, indent=2),
        encoding="utf-8",
    )
