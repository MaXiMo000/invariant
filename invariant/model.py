"""What a single check reports. Three statuses, not two.

"unverified" exists as its own status, not folded into "fail", because a
check that could not run (the tool isn't installed, Docker is down, a config
error) is not evidence the invariant is broken -- it's evidence you don't
know. Reporting it as a pass would be worse than either.
"""
from __future__ import annotations

import dataclasses

PASS = "pass"
FAIL = "fail"
UNVERIFIED = "unverified"


@dataclasses.dataclass
class CheckResult:
    name: str
    status: str
    detail: str = ""
    seconds: float = 0.0
    evidence: dict = dataclasses.field(default_factory=dict)

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)
