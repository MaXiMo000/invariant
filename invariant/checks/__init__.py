"""Check registry. A check is `args: dict -> (status, detail, evidence)`.

Adding a new invariant type is adding one module here and one line below --
not touching the runner. That's the only extension point on purpose.
"""
from . import (
    filesystem, gdpr_erasure, http, migration_diff, postgres_restore, receipt,
    security_scan, sql,
)

REGISTRY = {
    "sql": sql.run,
    "postgres_restore": postgres_restore.run,
    "security_scan": security_scan.run,
    "http": http.run,
    "filesystem": filesystem.run,
    "receipt": receipt.run,
    "gdpr_erasure": gdpr_erasure.run,
    "migration_diff": migration_diff.run,
}
